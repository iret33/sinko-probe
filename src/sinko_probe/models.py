from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class TransportProtocol(str, Enum):
    UDP = "udp"
    TCP = "tcp"
    DOT = "dot"
    DOH = "doh"


class ExpectedAction(str, Enum):
    BLOCK = "block"               # Must be sinkholed (0.0.0.0, NXDOMAIN, REFUSED, or Sinkhole IP)
    ALLOW = "allow"               # Must resolve normally (false-positive check)
    SAFESEARCH = "safesearch"     # Must resolve to known SafeSearch / Restricted Mode CNAME or VIP


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


class DomainProbe(BaseModel):
    domain: str
    record_type: str = "A"
    category: Category
    expected: ExpectedAction = ExpectedAction.BLOCK
    expected_cname_markers: List[str] = Field(
        default_factory=list,
        description="Substrings expected in CNAME or resolved target for SafeSearch enforcement",
    )


class AppProfile(BaseModel):
    id: str
    name: str
    name_ar: str
    description: str
    burst_interval_ms: tuple[int, int] = (25, 250)
    probes: List[DomainProbe]


class Verdict(str, Enum):
    BLOCKED_ZERO_IP = "BLOCKED (Zero/Loopback IP)"
    BLOCKED_NXDOMAIN = "BLOCKED (NXDOMAIN)"
    BLOCKED_REFUSED = "BLOCKED (REFUSED)"
    BLOCKED_SINKHOLE_IP = "BLOCKED (Sinkhole VIP)"
    SAFESEARCH_ENFORCED = "ENFORCED (SafeSearch CNAME/VIP)"
    ALLOWED_RESOLVED = "ALLOWED (Resolved)"
    ERROR_TIMEOUT = "ERROR (Timeout/ServFail)"


class ProbeResult(BaseModel):
    target_name: str
    app_id: str
    app_name: str
    app_name_ar: str
    domain: str
    record_type: str
    category: Category
    expected: ExpectedAction
    verdict: Verdict
    resolved_ips: List[str] = []
    cname_chain: List[str] = []
    latency_ms: float
    passed_expectation: bool
    error_message: Optional[str] = None


class SinkoPolicyConfig(BaseModel):
    """Declarative policy matching a Sinko parental-control mode (e.g., Homework Mode)."""
    policy_name: str = "Default Sinko Family Policy"
    category_rules: Dict[Category, ExpectedAction] = Field(default_factory=dict)
    custom_blocklist: List[str] = Field(default_factory=list)
    custom_allowlist: List[str] = Field(default_factory=list)


class TargetSummary(BaseModel):
    target_name: str
    server_endpoint: str
    protocol: TransportProtocol
    total_probes: int
    passed_probes: int
    compliance_score: float
    block_rate: float
    false_positive_rate: float
    safesearch_rate: float
    p50_ms: float
    p95_ms: float
    p99_ms: float
