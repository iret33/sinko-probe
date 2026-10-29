"""Async DNS probe engine: transports, burst scheduling and verdicts."""

import asyncio
import contextlib
import random
import socket
import ssl
import string
import time
from collections.abc import AsyncIterator, Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

import dns.asyncquery
import dns.exception
import dns.message
import httpx

from .analysis import compute_percentile, summarize_results
from .classify import Classification, MarkerSet, classify_response, outcome_for, parse_sinkholes
from .endpoints import parse_endpoint
from .models import (
    AppProfile,
    Category,
    DomainProbe,
    ExpectedAction,
    ProbeResult,
    SinkoPolicyConfig,
    TargetSummary,
    TransportProtocol,
    Verdict,
)

__all__ = [
    "DNSSimulatorEngine",
    "PlanError",
    "PlannedProbe",
    "ResolverUnavailableError",
    "build_plan",
    "compute_percentile",
]

CACHE_BUST_PREFIX = "sinkoprobe-"
EDNS_PAYLOAD = 1232  # DNS Flag Day 2020 buffer size; EDNS is also needed to receive EDE codes
PADDING_BLOCK = 128  # RFC 8467 block-length padding for encrypted transports
POLICY_PROFILE_ID = "policy_custom_rules"
DOH_MEDIA_TYPE = "application/dns-message"

ResultCallback = Callable[[ProbeResult], None]


class PlanError(ValueError):
    """The probes and the policy contradict each other."""


class ResolverUnavailableError(OSError):
    """The resolver's hostname could not be resolved; every query reports it as a transport
    error, so an unreachable box is reported (and alerted on) like one that stopped answering."""


class DoHResponseError(dns.exception.DNSException):
    """A DoH server answered with something other than a DNS message."""


@dataclass(frozen=True)
class PlannedProbe:
    profile: AppProfile
    probe: DomainProbe
    expected: ExpectedAction
    markers: MarkerSet


def plan_probe(
    profile: AppProfile, probe: DomainProbe, policy: SinkoPolicyConfig | None
) -> PlannedProbe:
    expected = (
        policy.expectation_for(probe.domain, probe.category, probe.expected)
        if policy
        else probe.expected
    )
    markers = MarkerSet.parse(probe.expected_cname_markers)
    if expected == ExpectedAction.SAFESEARCH and not markers:
        raise PlanError(
            f"the policy expects SafeSearch for {probe.domain} ({profile.id}), but that probe "
            "has no expected_cname_markers to verify it with"
        )
    return PlannedProbe(profile, probe, expected, markers)


def build_plan(
    profiles: Sequence[AppProfile], policy: SinkoPolicyConfig | None = None
) -> list[PlannedProbe]:
    """Resolve every probe's expectation, adding probes for the policy's own custom domains."""
    plan = [plan_probe(profile, probe, policy) for profile in profiles for probe in profile.probes]
    if policy is None:
        return plan

    probed = {(p.probe.domain, p.probe.record_type) for p in plan}
    extra = [
        DomainProbe(domain=domain, category=Category.CUSTOM, expected=action)
        for domains, action in (
            (policy.custom_blocklist, ExpectedAction.BLOCK),
            (policy.custom_allowlist, ExpectedAction.ALLOW),
        )
        for domain in domains
        if (domain, "A") not in probed
    ]
    if extra:
        profile = AppProfile(
            id=POLICY_PROFILE_ID,
            name="Policy Custom Rules",
            name_ar="قواعد السياسة المخصصة",
            description=f"Custom block/allow list entries from '{policy.policy_name}'.",
            probes=extra,
        )
        plan.extend(plan_probe(profile, probe, policy) for probe in extra)
    return plan


class DNSSimulatorEngine:
    def __init__(
        self,
        target_name: str = "Sinko",
        nameserver: str = "127.0.0.1",
        port: int | None = None,
        protocol: TransportProtocol = TransportProtocol.UDP,
        timeout: float = 3.5,
        concurrency: int = 50,
        custom_sinkhole_ips: Iterable[str] | None = None,
        cache_bust: bool = False,
        realistic_jitter: bool = True,
        policy: SinkoPolicyConfig | None = None,
        *,
        insecure: bool = False,
        ca_file: str | Path | None = None,
        tls_server_name: str | None = None,
        seed: int | None = None,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if concurrency < 1:
            raise ValueError("concurrency must be at least 1")
        self.target_name = target_name
        self.endpoint = parse_endpoint(nameserver, protocol, port)
        self.timeout = timeout
        self.concurrency = concurrency
        self.sinkholes = parse_sinkholes(custom_sinkhole_ips or ())
        self.cache_bust = cache_bust
        self.realistic_jitter = realistic_jitter
        self.policy = policy
        self.insecure = insecure
        self.ca_file = str(ca_file) if ca_file else None
        self.tls_server_name = tls_server_name
        self._rng = random.Random(seed)
        self._in_session = False
        self._address: str | None = None
        self._address_error: str | None = None
        self._dot_context: ssl.SSLContext | None = None
        self._doh_client: httpx.AsyncClient | None = None

    @property
    def protocol(self) -> TransportProtocol:
        return self.endpoint.protocol

    @property
    def port(self) -> int:
        return self.endpoint.port

    @property
    def nameserver(self) -> str:
        return self.endpoint.host

    # -- planning & scheduling ---------------------------------------------------------------

    def build_plan(self, profiles: Sequence[AppProfile]) -> list[PlannedProbe]:
        return build_plan(profiles, self.policy)

    async def run_simulation(
        self,
        profiles: Sequence[AppProfile],
        iterations: int = 1,
        on_complete: ResultCallback | None = None,
    ) -> list[ProbeResult]:
        return await self.run_plan(self.build_plan(profiles), iterations, on_complete)

    async def run_plan(
        self,
        plan: Sequence[PlannedProbe],
        iterations: int = 1,
        on_complete: ResultCallback | None = None,
    ) -> list[ProbeResult]:
        """Send ``iterations`` waves of the plan, one wave after another."""
        if iterations < 1:
            raise ValueError("iterations must be at least 1")
        semaphore = asyncio.Semaphore(self.concurrency)
        results: list[ProbeResult] = []
        async with self.session():
            for wave in range(1, iterations + 1):
                tasks = [
                    self._execute(planned, wave, semaphore, delay, on_complete)
                    for planned, delay in self._schedule(plan)
                ]
                results.extend(await asyncio.gather(*tasks))
        return results

    def _schedule(self, plan: Sequence[PlannedProbe]) -> list[tuple[PlannedProbe, float]]:
        """Start offsets that replay each app's lookups as a burst with random gaps between
        queries, while different apps run side by side."""
        if not self.realistic_jitter:
            return [(planned, 0.0) for planned in plan]
        offsets: dict[str, float] = {}
        schedule = []
        for planned in plan:
            low, high = planned.profile.burst_interval_ms
            offset = offsets.get(planned.profile.id, 0.0) + self._rng.uniform(low, high) / 1000.0
            offsets[planned.profile.id] = offset
            schedule.append((planned, offset))
        return schedule

    async def probe_single(
        self,
        app_profile: AppProfile,
        probe: DomainProbe,
        on_complete: ResultCallback | None = None,
        *,
        wave: int = 1,
    ) -> ProbeResult:
        planned = plan_probe(app_profile, probe, self.policy)
        async with self.session():
            return await self._execute(planned, wave, None, 0.0, on_complete)

    def summarize(self, results: Sequence[ProbeResult]) -> TargetSummary:
        return summarize_results(
            results,
            target_name=self.target_name,
            server_endpoint=self.endpoint.display(),
            protocol=self.protocol,
            policy_name=self.policy.policy_name if self.policy else None,
        )

    # -- one probe ---------------------------------------------------------------------------

    async def _execute(
        self,
        planned: PlannedProbe,
        wave: int,
        semaphore: asyncio.Semaphore | None,
        delay: float,
        on_complete: ResultCallback | None,
    ) -> ProbeResult:
        if delay > 0:
            await asyncio.sleep(delay)
        qname = self._qname_for(planned)
        query = self._make_query(qname, planned.probe.record_type)

        async with semaphore or contextlib.nullcontext():
            started = time.perf_counter()
            try:
                response = await self._send(query)
            except (dns.exception.Timeout, httpx.TimeoutException, TimeoutError):
                classification = Classification(
                    Verdict.ERROR_TIMEOUT, detail=f"no answer within {self.timeout:g}s"
                )
            except (OSError, EOFError, httpx.HTTPError, dns.exception.DNSException) as exc:
                classification = Classification(Verdict.ERROR_TRANSPORT, detail=_describe(exc))
            else:
                classification = None
            latency_ms = (time.perf_counter() - started) * 1000.0

        if classification is None:
            classification = classify_response(
                response, query.question[0].name, markers=planned.markers, sinkholes=self.sinkholes
            )

        profile, probe = planned.profile, planned.probe
        result = ProbeResult(
            target_name=self.target_name,
            wave=wave,
            app_id=profile.id,
            app_name=profile.name,
            app_name_ar=profile.name_ar or profile.name,
            domain=probe.domain,
            qname=qname,
            record_type=probe.record_type,
            category=probe.category,
            expected=planned.expected,
            verdict=classification.verdict,
            outcome=outcome_for(planned.expected, classification.verdict),
            resolved_ips=list(classification.resolved_ips),
            cname_chain=list(classification.cname_chain),
            ede_codes=list(classification.ede_codes),
            latency_ms=round(latency_ms, 2),
            error_message=classification.detail,
        )
        if on_complete:
            on_complete(result)
        return result

    def _qname_for(self, planned: PlannedProbe) -> str:
        # Only must-block names get a random label: real allowed or SafeSearch names have no
        # wildcard records, so a random subdomain of them would just come back NXDOMAIN.
        if self.cache_bust and planned.expected == ExpectedAction.BLOCK:
            nonce = "".join(self._rng.choices(string.ascii_lowercase + string.digits, k=8))
            return f"{CACHE_BUST_PREFIX}{nonce}.{planned.probe.domain}"
        return planned.probe.domain

    def _make_query(self, qname: str, record_type: str) -> dns.message.Message:
        encrypted = self.protocol in (TransportProtocol.DOT, TransportProtocol.DOH)
        query = dns.message.make_query(
            qname,
            record_type,
            use_edns=0,
            payload=EDNS_PAYLOAD,
            pad=PADDING_BLOCK if encrypted else 0,
        )
        if self.protocol == TransportProtocol.DOH:
            query.id = 0  # RFC 8484 section 4.1
        return query

    # -- transports --------------------------------------------------------------------------

    @contextlib.asynccontextmanager
    async def session(self) -> AsyncIterator[None]:
        """Resolve the resolver's address and set up shared TLS/HTTP state for a run."""
        if self._in_session:
            yield
            return
        self._in_session = True
        try:
            try:
                self._address = await self._resolve_address()
            except ResolverUnavailableError as exc:
                self._address_error = str(exc)
            if self.protocol == TransportProtocol.DOT:
                self._dot_context = self._ssl_context(alpn=["dot"])
            elif self.protocol == TransportProtocol.DOH:
                # One HTTP/2 client per run, so queries share a connection like a real stub
                # resolver instead of paying a TLS handshake each.
                self._doh_client = httpx.AsyncClient(
                    http2=True, verify=self._ssl_context(), timeout=self.timeout
                )
            yield
        finally:
            if self._doh_client is not None:
                await self._doh_client.aclose()
            self._in_session = False
            self._address = None
            self._address_error = None
            self._dot_context = None
            self._doh_client = None

    async def _resolve_address(self) -> str:
        if self.protocol == TransportProtocol.DOH or self.endpoint.is_ip:
            return self.endpoint.host
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(self.endpoint.host, self.port, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise ResolverUnavailableError(
                f"cannot resolve resolver hostname {self.endpoint.host!r}: {exc}"
            ) from exc
        return str(infos[0][4][0])

    def _ssl_context(self, alpn: list[str] | None = None) -> ssl.SSLContext:
        context = ssl.create_default_context(cafile=self.ca_file)
        if self.insecure:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        if alpn:
            context.set_alpn_protocols(alpn)
        return context

    async def _send(self, query: dns.message.Message) -> dns.message.Message:
        if self._address_error is not None:
            raise ResolverUnavailableError(self._address_error)
        address = self._address
        if address is None:
            raise RuntimeError("queries must be sent inside DNSSimulatorEngine.session()")
        if self.protocol == TransportProtocol.UDP:
            # Retries over TCP when the answer is truncated, like any real stub resolver.
            response, _ = await dns.asyncquery.udp_with_fallback(
                query, address, timeout=self.timeout, port=self.port
            )
            return response
        if self.protocol == TransportProtocol.TCP:
            return await dns.asyncquery.tcp(query, address, timeout=self.timeout, port=self.port)
        if self.protocol == TransportProtocol.DOT:
            return await dns.asyncquery.tls(
                query,
                address,
                timeout=self.timeout,
                port=self.port,
                ssl_context=self._dot_context,
                server_hostname=self.tls_server_name or self.endpoint.host,
            )
        return await self._doh_query(query)

    async def _doh_query(self, query: dns.message.Message) -> dns.message.Message:
        client = self._doh_client
        if client is None:
            raise RuntimeError("DoH queries must be sent inside DNSSimulatorEngine.session()")
        url = self.endpoint.url
        response = await client.post(
            url,
            content=query.to_wire(),
            headers={"accept": DOH_MEDIA_TYPE, "content-type": DOH_MEDIA_TYPE},
        )
        if not response.is_success:
            raise DoHResponseError(f"HTTP {response.status_code} from {url}")
        media_type = response.headers.get("content-type", "").partition(";")[0].strip().lower()
        if media_type != DOH_MEDIA_TYPE:
            raise DoHResponseError(f"unexpected Content-Type {media_type or 'none'!r} from {url}")
        answer = dns.message.from_wire(response.content)
        if not query.is_response(answer):
            raise DoHResponseError(f"answer from {url} does not match the query")
        return answer


def _describe(exc: BaseException) -> str:
    text = str(exc).strip()
    return f"{type(exc).__name__}: {text}" if text else type(exc).__name__
