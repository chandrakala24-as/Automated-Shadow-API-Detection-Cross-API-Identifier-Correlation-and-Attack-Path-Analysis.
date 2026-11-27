"""In-memory data structures shared by the engine stages."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

ANONYMOUS = "anonymous"
INVALID = "invalid-token"


@dataclass
class Identity:
    name: str
    role: str  # "user" or "admin"
    headers: dict[str, str]


@dataclass
class Input:
    """A value an endpoint consumes: a path parameter or an identifier query parameter."""
    location: str  # "path" or "query"
    name: str
    entity: str


@dataclass
class Endpoint:
    method: str
    template: str
    inputs: list[Input] = field(default_factory=list)
    sources: set[str] = field(default_factory=set)
    in_spec: bool = False
    spec_public: bool = False
    spec_deprecated: bool = False
    spec_admin: bool = False
    live: bool = False
    statuses: set[int] = field(default_factory=set)
    samples: dict[str, set[str]] = field(default_factory=dict)
    classification: str = "candidate"
    skip_reason: str = ""
    sensitive: dict[str, list[str]] = field(default_factory=dict)

    @property
    def label(self) -> str:
        return f"{self.method} {self.template}"


@dataclass(frozen=True)
class IdRef:
    """An identifier found inside a response body."""
    entity: str
    value: str
    field_name: str
    json_path: str
    primary: bool

    @property
    def key(self) -> tuple[str, str]:
        return (self.entity, self.value)


@dataclass
class Observation:
    """One real request made by the scanner and what came back."""
    endpoint: str  # Endpoint.label
    identity: str
    values: dict[str, str]
    url_path: str
    status: int
    body: Any
    ids: list[IdRef] = field(default_factory=list)
    sensitive: dict[str, list[str]] = field(default_factory=dict)
    matches_not_found: bool = False

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300 and not self.matches_not_found

    @property
    def has_data(self) -> bool:
        return self.ok and isinstance(self.body, (dict, list)) and bool(self.body)


@dataclass
class Finding:
    type: str
    endpoint: str
    title: str
    description: str
    remediation: str
    owasp: str
    confidence: str  # "confirmed" or "review"
    attacker: str
    evidence: list[dict]
    data_categories: list[str] = field(default_factory=list)
    score: int = 0
    severity: str = "low"
    score_breakdown: dict = field(default_factory=dict)


@dataclass
class Link:
    producer: str
    consumer: str
    entity: str
    producer_field: str
    consumer_param: str
    confidence: float
    evidence: list[str]
    sample_value: str


@dataclass
class AttackPath:
    title: str
    attacker: str
    victim: str
    steps: list[dict]
    data_categories: list[str]
    score: int
    severity: str
    narrative: str


@dataclass
class ScanResult:
    endpoints: list[Endpoint]
    findings: list[Finding]
    links: list[Link]
    paths: list[AttackPath]
    warnings: list[str]
    stats: dict
