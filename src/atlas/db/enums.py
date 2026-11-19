"""Enumerations shared by the schema, services and API schemas.

All enums subclass ``str`` so they serialise cleanly and store as portable
``VARCHAR`` values (``native_enum=False``), keeping SQLite and PostgreSQL
behaviour identical.
"""

from __future__ import annotations

from enum import Enum

__all__ = [
    "AssetChangeType",
    "AssetKind",
    "ConfidenceLevel",
    "DnsRecordType",
    "EvidenceKind",
    "ExposureLevel",
    "FindingCategory",
    "FindingSeverity",
    "FindingStatus",
    "JobStatus",
    "JobType",
    "RelationshipType",
    "ScopeKind",
    "ScopeMode",
    "ServiceState",
    "TargetKind",
    "TechnologyCategory",
]


class _StrEnum(str, Enum):
    def __str__(self) -> str:  # pragma: no cover - convenience only
        return str(self.value)


class AssetKind(_StrEnum):
    DOMAIN = "domain"
    IP_ADDRESS = "ip"
    ASN = "asn"
    CERTIFICATE = "certificate"
    SERVICE = "service"


class ScopeKind(_StrEnum):
    DOMAIN = "domain"
    IP = "ip"
    CIDR = "cidr"
    ASN = "asn"
    URL = "url"


class ScopeMode(_StrEnum):
    INCLUDE = "include"
    EXCLUDE = "exclude"


class TargetKind(_StrEnum):
    DOMAIN = "domain"
    IP = "ip"
    CIDR = "cidr"
    URL = "url"


class JobType(_StrEnum):
    DISCOVER = "discover"
    DNS = "dns"
    CERTIFICATES = "certificates"
    HTTP = "http"
    SERVICES = "services"
    URLSCAN = "urlscan"
    FULL = "full"
    SNAPSHOT = "snapshot"


class JobStatus(_StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class DnsRecordType(_StrEnum):
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    NS = "NS"
    TXT = "TXT"
    SOA = "SOA"
    CAA = "CAA"
    SRV = "SRV"
    PTR = "PTR"
    DS = "DS"
    DNSKEY = "DNSKEY"


class ServiceState(_StrEnum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNKNOWN = "unknown"


class TechnologyCategory(_StrEnum):
    SERVER = "server"
    FRAMEWORK = "framework"
    CMS = "cms"
    LANGUAGE = "language"
    LIBRARY = "library"
    CDN = "cdn"
    WAF = "waf"
    ANALYTICS = "analytics"
    OTHER = "other"


class RelationshipType(_StrEnum):
    SUBDOMAIN_OF = "subdomain_of"
    RESOLVES_TO = "resolves_to"
    ANNOUNCED_BY = "announced_by"
    HOSTS_SERVICE = "hosts_service"
    PRESENTS_CERTIFICATE = "presents_certificate"
    SHARES_CERTIFICATE = "shares_certificate"
    SHARES_ADDRESS = "shares_address"
    SHARES_NAMESERVER = "shares_nameserver"
    CNAME_TO = "cname_to"
    REDIRECTS_TO = "redirects_to"
    SERVES_TECHNOLOGY = "serves_technology"


class FindingSeverity(_StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingCategory(_StrEnum):
    HTTP_HEADERS = "http.headers"
    HTTP_COOKIES = "http.cookies"
    TLS = "tls"
    CERTIFICATE = "certificate"
    DNS = "dns"
    EXPOSURE = "exposure"
    SOFTWARE_VERSION = "software.version"
    CONFIGURATION = "configuration"


class FindingStatus(_StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


class ExposureLevel(_StrEnum):
    PUBLIC = "public"
    RESTRICTED = "restricted"
    INTERNAL = "internal"
    UNKNOWN = "unknown"


class ConfidenceLevel(_StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class EvidenceKind(_StrEnum):
    HTTP_RESPONSE = "http_response"
    HTTP_HEADERS = "http_headers"
    TLS_HANDSHAKE = "tls_handshake"
    CERTIFICATE = "certificate"
    DNS_ANSWER = "dns_answer"
    SERVICE_BANNER = "service_banner"
    SCREENSHOT = "screenshot"
    TOOL_OUTPUT = "tool_output"
    NOTE = "note"


class AssetChangeType(_StrEnum):
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
