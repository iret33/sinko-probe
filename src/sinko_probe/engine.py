import asyncio
import math
import random
import ssl
import string
import time
from typing import Callable, List, Optional, Set
import dns.asyncquery
import dns.asyncresolver
import dns.exception
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import httpx

from .models import (
    AppProfile,
    DomainProbe,
    ExpectedAction,
    ProbeResult,
    SinkoPolicyConfig,
    TargetSummary,
    TransportProtocol,
    Verdict,
)

SINKHOLE_ZERO_IPS = {"0.0.0.0", "127.0.0.1", "::", "::1"}


def compute_percentile(sorted_vals: List[float], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = (len(sorted_vals) - 1) * (pct / 100.0)
    lower = math.floor(idx)
    upper = math.ceil(idx)
    if lower == upper:
        return round(sorted_vals[int(idx)], 2)
    weight = idx - lower
    return round(sorted_vals[lower] * (1.0 - weight) + sorted_vals[upper] * weight, 2)


class DNSSimulatorEngine:
    def __init__(
        self,
        target_name: str = "Sinko",
        nameserver: str = "127.0.0.1",
        port: Optional[int] = None,
        protocol: TransportProtocol = TransportProtocol.UDP,
        timeout: float = 3.5,
        concurrency: int = 50,
        custom_sinkhole_ips: Optional[Set[str]] = None,
        cache_bust: bool = False,
        realistic_jitter: bool = True,
        policy: Optional[SinkoPolicyConfig] = None,
    ):
        self.target_name = target_name
        self.nameserver = nameserver
        self.protocol = protocol
        self.port = port or self._default_port(protocol)
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrency)
        self.sinkhole_ips = custom_sinkhole_ips or set()
        self.cache_bust = cache_bust
        self.realistic_jitter = realistic_jitter
        self.policy = policy

    @staticmethod
    def _default_port(protocol: TransportProtocol) -> int:
        if protocol == TransportProtocol.DOT:
            return 853
        if protocol == TransportProtocol.DOH:
            return 443
        return 53

    def _effective_expectation(self, probe: DomainProbe) -> ExpectedAction:
        if not self.policy:
            return probe.expected
        if probe.domain in self.policy.custom_blocklist:
            return ExpectedAction.BLOCK
        if probe.domain in self.policy.custom_allowlist:
            return ExpectedAction.ALLOW
        if probe.category in self.policy.category_rules:
            return self.policy.category_rules[probe.category]
        return probe.expected

    def _prepare_qname(self, domain: str) -> str:
        if not self.cache_bust:
            return domain
        nonce = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
        return f"sinkoprobe-{nonce}.{domain}"

    async def _raw_query(self, qname: str, rdtype: str) -> dns.message.Message:
        query_msg = dns.message.make_query(qname, rdtype)
        if self.protocol == TransportProtocol.UDP:
            return await dns.asyncquery.udp(
                query_msg, self.nameserver, port=self.port, timeout=self.timeout
            )
        if self.protocol == TransportProtocol.TCP:
            return await dns.asyncquery.tcp(
                query_msg, self.nameserver, port=self.port, timeout=self.timeout
            )
        if self.protocol == TransportProtocol.DOT:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return await dns.asyncquery.tls(
                query_msg, self.nameserver, port=self.port, timeout=self.timeout, ssl_context=ctx
            )
        if self.protocol == TransportProtocol.DOH:
            doh_url = (
                self.nameserver
                if self.nameserver.startswith("https://")
                else f"https://{self.nameserver}/dns-query"
            )
            async with httpx.AsyncClient(http2=True, verify=True, timeout=self.timeout) as client:
                return await dns.asyncquery.https(
                    query_msg, doh_url, session=client, timeout=self.timeout
                )
        raise ValueError(f"Unsupported protocol: {self.protocol}")

    async def probe_single(
        self,
        app_profile: AppProfile,
        probe: DomainProbe,
        on_complete: Optional[Callable[[ProbeResult], None]] = None,
    ) -> ProbeResult:
        if self.realistic_jitter:
            min_ms, max_ms = app_profile.burst_interval_ms
            await asyncio.sleep(random.uniform(min_ms / 1000.0, max_ms / 1000.0))

        qname = self._prepare_qname(probe.domain)
        expected = self._effective_expectation(probe)
        resolved_ips: List[str] = []
        cname_chain: List[str] = []
        error_msg: Optional[str] = None

        async with self.semaphore:
            start_time = time.perf_counter()
            try:
                response = await self._raw_query(qname, probe.record_type)
                latency_ms = (time.perf_counter() - start_time) * 1000.0
                rcode = response.rcode()

                if rcode == dns.rcode.NXDOMAIN:
                    verdict = Verdict.BLOCKED_NXDOMAIN
                elif rcode == dns.rcode.REFUSED:
                    verdict = Verdict.BLOCKED_REFUSED
                elif rcode != dns.rcode.NOERROR:
                    verdict = Verdict.ERROR_TIMEOUT
                    error_msg = f"DNS RCODE: {dns.rcode.to_text(rcode)}"
                else:
                    for rrset in response.answer:
                        if rrset.rdtype == dns.rdatatype.CNAME:
                            for rdata in rrset:
                                cname_chain.append(rdata.target.to_text().rstrip("."))
                        elif rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                            for rdata in rrset:
                                resolved_ips.append(rdata.to_text())

                    combined_targets = [c.lower() for c in cname_chain] + resolved_ips
                    markers = [m.lower() for m in probe.expected_cname_markers]

                    if not resolved_ips and not cname_chain:
                        verdict = Verdict.BLOCKED_ZERO_IP
                    elif any(ip in SINKHOLE_ZERO_IPS for ip in resolved_ips):
                        verdict = Verdict.BLOCKED_ZERO_IP
                    elif any(ip in self.sinkhole_ips for ip in resolved_ips):
                        verdict = Verdict.BLOCKED_SINKHOLE_IP
                    elif markers and any(
                        any(marker in target for marker in markers) for target in combined_targets
                    ):
                        verdict = Verdict.SAFESEARCH_ENFORCED
                    else:
                        verdict = Verdict.ALLOWED_RESOLVED

            except dns.exception.Timeout:
                latency_ms = (time.perf_counter() - start_time) * 1000.0
                verdict = Verdict.ERROR_TIMEOUT
                error_msg = "DNS query timed out"
            except Exception as exc:
                latency_ms = (time.perf_counter() - start_time) * 1000.0
                verdict = Verdict.ERROR_TIMEOUT
                error_msg = str(exc)

        is_blocked = verdict in {
            Verdict.BLOCKED_ZERO_IP,
            Verdict.BLOCKED_NXDOMAIN,
            Verdict.BLOCKED_REFUSED,
            Verdict.BLOCKED_SINKHOLE_IP,
        }

        if expected == ExpectedAction.BLOCK:
            passed = is_blocked
        elif expected == ExpectedAction.SAFESEARCH:
            passed = verdict == Verdict.SAFESEARCH_ENFORCED
        else:
            passed = verdict in {Verdict.ALLOWED_RESOLVED, Verdict.SAFESEARCH_ENFORCED}

        result = ProbeResult(
            target_name=self.target_name,
            app_id=app_profile.id,
            app_name=app_profile.name,
            app_name_ar=app_profile.name_ar,
            domain=probe.domain,
            record_type=probe.record_type,
            category=probe.category,
            expected=expected,
            verdict=verdict,
            resolved_ips=resolved_ips,
            cname_chain=cname_chain,
            latency_ms=round(latency_ms, 2),
            passed_expectation=passed,
            error_message=error_msg,
        )
        if on_complete:
            on_complete(result)
        return result

    async def run_simulation(
        self,
        profiles: List[AppProfile],
        iterations: int = 1,
        on_complete: Optional[Callable[[ProbeResult], None]] = None,
    ) -> List[ProbeResult]:
        tasks = [
            self.probe_single(profile, probe, on_complete=on_complete)
            for _ in range(iterations)
            for profile in profiles
            for probe in profile.probes
        ]
        return await asyncio.gather(*tasks)

    def summarize(self, results: List[ProbeResult]) -> TargetSummary:
        total = len(results)
        passed = sum(1 for r in results if r.passed_expectation)

        expected_blocks = [r for r in results if r.expected == ExpectedAction.BLOCK]
        actual_blocks = [r for r in expected_blocks if r.passed_expectation]

        expected_allows = [r for r in results if r.expected == ExpectedAction.ALLOW]
        false_positives = [r for r in expected_allows if not r.passed_expectation]

        expected_ss = [r for r in results if r.expected == ExpectedAction.SAFESEARCH]
        enforced_ss = [r for r in expected_ss if r.passed_expectation]

        latencies = sorted(r.latency_ms for r in results)

        return TargetSummary(
            target_name=self.target_name,
            server_endpoint=f"{self.nameserver}:{self.port}",
            protocol=self.protocol,
            total_probes=total,
            passed_probes=passed,
            compliance_score=round((passed / total) * 100, 1) if total else 0.0,
            block_rate=round((len(actual_blocks) / len(expected_blocks)) * 100, 1)
            if expected_blocks
            else 100.0,
            false_positive_rate=round((len(false_positives) / len(expected_allows)) * 100, 1)
            if expected_allows
            else 0.0,
            safesearch_rate=round((len(enforced_ss) / len(expected_ss)) * 100, 1)
            if expected_ss
            else 100.0,
            p50_ms=compute_percentile(latencies, 50),
            p95_ms=compute_percentile(latencies, 95),
            p99_ms=compute_percentile(latencies, 99),
        )
