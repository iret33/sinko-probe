"""Turn a DNS response into a verdict, independently of how it was transported."""

import ipaddress
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

import dns.edns
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype

from .models import ExpectedAction, Outcome, Verdict

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# RFC 8914 Extended DNS Errors that mean "this answer was filtered on purpose".
FILTERING_EDE_CODES = frozenset({15, 16, 17})  # Blocked, Censored, Filtered
PROHIBITED_EDE_CODE = 18  # REFUSED because the client is not allowed to query (an ACL)


@dataclass(frozen=True)
class MarkerSet:
    """SafeSearch evidence: CNAME targets (matched with their subdomains) and exact VIPs."""

    names: frozenset[str] = frozenset()
    addresses: frozenset[IPAddress] = frozenset()

    @classmethod
    def parse(cls, markers: Iterable[str]) -> "MarkerSet":
        names: set[str] = set()
        addresses: set[IPAddress] = set()
        for marker in markers:
            try:
                addresses.add(ipaddress.ip_address(marker))
            except ValueError:
                names.add(marker.lower().rstrip("."))
        return cls(frozenset(names), frozenset(addresses))

    def __bool__(self) -> bool:
        return bool(self.names or self.addresses)

    def matches(self, cnames: Iterable[str], addresses: Iterable[IPAddress]) -> bool:
        if any(address in self.addresses for address in addresses):
            return True
        return any(
            cname == name or cname.endswith("." + name) for cname in cnames for name in self.names
        )


@dataclass(frozen=True)
class Classification:
    verdict: Verdict
    resolved_ips: tuple[str, ...] = ()
    cname_chain: tuple[str, ...] = ()
    ede_codes: tuple[int, ...] = ()
    detail: str | None = None


def parse_sinkholes(values: Iterable[str]) -> tuple[IPNetwork, ...]:
    """Parse block-page addresses given as single IPs or CIDR ranges."""
    networks = []
    for value in values:
        try:
            networks.append(ipaddress.ip_network(value.strip(), strict=False))
        except ValueError as exc:
            raise ValueError(f"invalid sinkhole IP or CIDR {value!r}") from exc
    return tuple(networks)


def classify_response(
    response: dns.message.Message,
    qname: dns.name.Name,
    *,
    markers: MarkerSet | None = None,
    sinkholes: Sequence[IPNetwork] = (),
) -> Classification:
    markers = markers or MarkerSet()
    rcode = response.rcode()
    ede_options = [opt for opt in response.options if isinstance(opt, dns.edns.EDEOption)]
    ede_codes = tuple(int(option.code) for option in ede_options)
    ede_text = "; ".join(
        f"EDE {int(option.code)}" + (f": {option.text}" if option.text else "")
        for option in ede_options
    )
    filtered = any(code in FILTERING_EDE_CODES for code in ede_codes)

    if rcode == dns.rcode.NXDOMAIN:
        zone = None if filtered else _upstream_soa_zone(response, qname)
        if zone is not None:
            # A real negative answer carries the SOA of an enclosing zone (RFC 2308). Without a
            # filtering EDE this is indistinguishable from "the name simply does not exist".
            return Classification(
                Verdict.UPSTREAM_NXDOMAIN,
                ede_codes=ede_codes,
                detail=f"NXDOMAIN with the SOA of {zone}: the name does not exist upstream",
            )
        return Classification(
            Verdict.BLOCKED_NXDOMAIN, ede_codes=ede_codes, detail=ede_text or None
        )

    if rcode == dns.rcode.REFUSED:
        if PROHIBITED_EDE_CODE in ede_codes and not filtered:
            return Classification(
                Verdict.ERROR_RCODE,
                ede_codes=ede_codes,
                detail="REFUSED: this client is not allowed to query the resolver"
                + (f" ({ede_text})" if ede_text else ""),
            )
        return Classification(Verdict.BLOCKED_REFUSED, ede_codes=ede_codes, detail=ede_text or None)

    if rcode != dns.rcode.NOERROR:
        detail = f"DNS RCODE {dns.rcode.to_text(rcode)}" + (f" ({ede_text})" if ede_text else "")
        return Classification(Verdict.ERROR_RCODE, ede_codes=ede_codes, detail=detail)

    cnames: list[str] = []
    addresses: list[IPAddress] = []
    for rrset in response.answer:
        if rrset.rdtype == dns.rdatatype.CNAME:
            cnames.extend(rdata.target.to_text(omit_final_dot=True).lower() for rdata in rrset)
        elif rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
            addresses.extend(ipaddress.ip_address(rdata.address) for rdata in rrset)

    if not cnames and not addresses:
        verdict = Verdict.BLOCKED_NODATA
    elif any(address.is_unspecified or address.is_loopback for address in addresses):
        verdict = Verdict.BLOCKED_ZERO_IP
    elif any(address in network for address in addresses for network in sinkholes):
        verdict = Verdict.BLOCKED_SINKHOLE_IP
    elif markers and markers.matches(cnames, addresses):
        verdict = Verdict.SAFESEARCH_ENFORCED
    elif filtered:
        # The resolver says it filtered the name, so whatever it returned is a block page.
        verdict = Verdict.BLOCKED_SINKHOLE_IP
    else:
        verdict = Verdict.ALLOWED_RESOLVED
    return Classification(
        verdict,
        resolved_ips=tuple(str(address) for address in addresses),
        cname_chain=tuple(cnames),
        ede_codes=ede_codes,
        detail=ede_text or None,
    )


def outcome_for(expected: ExpectedAction, verdict: Verdict) -> Outcome:
    if verdict.is_error:
        return Outcome.ERROR
    if verdict == Verdict.UPSTREAM_NXDOMAIN:
        return Outcome.INCONCLUSIVE
    if expected == ExpectedAction.BLOCK:
        passed = verdict.is_blocked
    elif expected == ExpectedAction.SAFESEARCH:
        passed = verdict == Verdict.SAFESEARCH_ENFORCED
    else:
        passed = verdict in (Verdict.ALLOWED_RESOLVED, Verdict.SAFESEARCH_ENFORCED)
    return Outcome.PASS if passed else Outcome.FAIL


def _upstream_soa_zone(response: dns.message.Message, qname: dns.name.Name) -> str | None:
    """Return the enclosing zone if the NXDOMAIN carries an SOA from a parent of ``qname``.

    Blockers that synthesize NXDOMAIN usually send no SOA, or one owned by the query name itself.
    """
    for rrset in response.authority:
        if rrset.rdtype == dns.rdatatype.SOA:
            owner = rrset.name
            if owner != qname and qname.is_subdomain(owner):
                return owner.to_text()
    return None
