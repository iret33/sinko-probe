"""Data models shared by the engine, the reporters and the CLI."""

from enum import Enum

import dns.exception
import dns.name
from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator, model_validator

SUPPORTED_RECORD_TYPES = frozenset({"A", "AAAA"})


def normalize_domain(value: str) -> str:
    """Lower-case a domain, drop a trailing dot or leading ``*.`` and check that it is valid."""
    domain = value.strip().lower().rstrip(".").removeprefix("*.")
    if not domain:
        raise ValueError("domain must not be empty")
    try:
        dns.name.from_text(domain)
    except dns.exception.DNSException as exc:
        raise ValueError(f"invalid domain {value!r}: {exc}") from exc
    return domain


class TransportProtocol(str, Enum):
    UDP = "udp"
    TCP = "tcp"
    DOT = "dot"
    DOH = "doh"


class ExpectedAction(str, Enum):
    BLOCK = "block"  # Must be sinkholed (0.0.0.0, NODATA, NXDOMAIN, REFUSED or a block-page IP)
    ALLOW = "allow"  # Must resolve normally (false-positive check)
    SAFESEARCH = "safesearch"  # Must resolve to a known SafeSearch / Restricted Mode CNAME or VIP


class Category(str, Enum):
    ADS = "ads"
    TELEMETRY = "telemetry"
    SOCIAL = "social"
    GAMING = "gaming"
    STREAMING = "streaming"
    SAFE_SEARCH = "safe_search"
    PARENTAL_RESTRICTED = "parental_restricted"
    AI_CHATBOTS = "ai_chatbots"
    CORE_SERVICE = "core_service"
    CUSTOM = "custom"  # Domains that only appear in a policy's custom block/allow lists


class DomainProbe(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain: str
    record_type: str = "A"
    category: Category
    expected: ExpectedAction = ExpectedAction.BLOCK
    expected_cname_markers: list[str] = Field(
        default_factory=list,
        description=(
            "CNAME targets (a name or any subdomain of it) or exact IP addresses that prove "
            "SafeSearch enforcement"
        ),
    )

    @field_validator("domain")
    @classmethod
    def _normalize_domain(cls, value: str) -> str:
        return normalize_domain(value)

    @field_validator("record_type")
    @classmethod
    def _check_record_type(cls, value: str) -> str:
        record_type = value.strip().upper()
        if record_type not in SUPPORTED_RECORD_TYPES:
            supported = ", ".join(sorted(SUPPORTED_RECORD_TYPES))
            raise ValueError(f"record_type must be one of {supported}, got {value!r}")
        return record_type

    @field_validator("expected_cname_markers")
    @classmethod
    def _normalize_markers(cls, values: list[str]) -> list[str]:
        return [v.strip().lower().rstrip(".") for v in values if v.strip()]

    @model_validator(mode="after")
    def _safesearch_needs_markers(self) -> "DomainProbe":
        if self.expected == ExpectedAction.SAFESEARCH and not self.expected_cname_markers:
            raise ValueError(
                f"{self.domain}: a SafeSearch expectation needs expected_cname_markers"
            )
        return self


class AppProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, pattern=r"^\S+$")
    name: str
    name_ar: str | None = None
    description: str = ""
    burst_interval_ms: tuple[int, int] = (25, 250)
    probes: list[DomainProbe] = Field(min_length=1)

    @field_validator("burst_interval_ms")
    @classmethod
    def _check_interval(cls, value: tuple[int, int]) -> tuple[int, int]:
        low, high = value
        if low < 0 or high < low:
            raise ValueError("burst_interval_ms must be (min, max) with 0 <= min <= max")
        return value


class Verdict(str, Enum):
    BLOCKED_ZERO_IP = "BLOCKED (Zero/Loopback IP)"
    BLOCKED_NODATA = "BLOCKED (NODATA)"
    BLOCKED_NXDOMAIN = "BLOCKED (NXDOMAIN)"
    BLOCKED_REFUSED = "BLOCKED (REFUSED)"
    BLOCKED_SINKHOLE_IP = "BLOCKED (Sinkhole VIP)"
    SAFESEARCH_ENFORCED = "ENFORCED (SafeSearch CNAME/VIP)"
    ALLOWED_RESOLVED = "ALLOWED (Resolved)"
    UPSTREAM_NXDOMAIN = "INCONCLUSIVE (Upstream NXDOMAIN)"
    ERROR_TIMEOUT = "ERROR (Timeout)"
    ERROR_RCODE = "ERROR (SERVFAIL/RCODE)"
    ERROR_TRANSPORT = "ERROR (Transport)"

    @property
    def is_blocked(self) -> bool:
        return self.name.startswith("BLOCKED_")

    @property
    def is_error(self) -> bool:
        return self.name.startswith("ERROR_")


class Outcome(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"  # No usable answer (timeout, SERVFAIL, connection or TLS failure)
    INCONCLUSIVE = "inconclusive"  # Answered, but the answer cannot prove the filter's behaviour


class ProbeResult(BaseModel):
    target_name: str
    wave: int = 1
    app_id: str
    app_name: str
    app_name_ar: str
    domain: str
    qname: str | None = None  # The name actually queried; differs from domain with --cache-bust
    record_type: str
    category: Category
    expected: ExpectedAction
    verdict: Verdict
    outcome: Outcome
    resolved_ips: list[str] = Field(default_factory=list)
    cname_chain: list[str] = Field(default_factory=list)
    ede_codes: list[int] = Field(default_factory=list)
    latency_ms: float
    error_message: str | None = None

    @model_validator(mode="after")
    def _default_qname(self) -> "ProbeResult":
        if self.qname is None:
            self.qname = self.domain
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def passed_expectation(self) -> bool:
        return self.outcome == Outcome.PASS


class SinkoPolicyConfig(BaseModel):
    """Declarative policy matching a Sinko parental-control mode (e.g., Homework Mode)."""

    model_config = ConfigDict(extra="forbid")

    policy_name: str = "Default Sinko Family Policy"
    category_rules: dict[Category, ExpectedAction] = Field(default_factory=dict)
    custom_blocklist: list[str] = Field(default_factory=list)
    custom_allowlist: list[str] = Field(default_factory=list)

    @field_validator("custom_blocklist", "custom_allowlist")
    @classmethod
    def _normalize_lists(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(normalize_domain(v) for v in values))

    @model_validator(mode="after")
    def _reject_conflicts(self) -> "SinkoPolicyConfig":
        clash = sorted(set(self.custom_blocklist) & set(self.custom_allowlist))
        if clash:
            raise ValueError(
                "listed in both custom_blocklist and custom_allowlist: " + ", ".join(clash)
            )
        return self

    def expectation_for(
        self, domain: str, category: Category, default: ExpectedAction
    ) -> ExpectedAction:
        """Resolve what the policy expects for ``domain``.

        A custom list entry matches the domain itself and all of its subdomains, and the most
        specific entry wins (block ``roblox.com`` but allow ``create.roblox.com``). Without a
        matching entry the category rule applies, then the probe's own default.
        """
        best: tuple[int, ExpectedAction] | None = None
        for entries, action in (
            (self.custom_blocklist, ExpectedAction.BLOCK),
            (self.custom_allowlist, ExpectedAction.ALLOW),
        ):
            for entry in entries:
                if domain == entry or domain.endswith("." + entry):
                    depth = entry.count(".")
                    if best is None or depth > best[0]:
                        best = (depth, action)
        if best is not None:
            return best[1]
        return self.category_rules.get(category, default)


class TargetSummary(BaseModel):
    target_name: str
    server_endpoint: str
    protocol: TransportProtocol
    policy_name: str | None = None
    iterations: int = 1
    total_probes: int
    passed_probes: int
    failed_probes: int = 0
    error_probes: int = 0
    inconclusive_probes: int = 0
    # Rates are percentages; None means nothing of that kind could be measured.
    compliance_score: float | None
    block_rate: float | None
    false_positive_rate: float | None
    safesearch_rate: float | None
    error_rate: float = 0.0
    p50_ms: float | None
    p95_ms: float | None
    p99_ms: float | None
