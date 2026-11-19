"""Domain services.

Services own business rules and transaction boundaries. They never construct SQL
directly beyond simple ORM queries, and they never touch argparse/typer or HTTP.
"""

from atlas.services.assets import asset_detail, get_asset, list_assets
from atlas.services.audit import record_event
from atlas.services.discovery import DiscoveryOutcome, discover, record_scan_results
from atlas.services.dns import (
    DnsChange,
    DnsOutcome,
    dangling_cnames,
    dns_history,
    dns_records,
    nameserver_summary,
    persist_dns_result,
)
from atlas.services.observations import (
    ensure_domain,
    ensure_ip_address,
    merge_observation_window,
    retire_dns_records,
    upsert_asset,
    upsert_dns_record,
)
from atlas.services.projects import (
    create_project,
    delete_project,
    get_project,
    list_projects,
    project_stats,
    slugify,
)
from atlas.services.relationships import upsert_relationship
from atlas.services.scopes import (
    add_rule,
    build_scope_set,
    check_value,
    list_rules,
    remove_rules,
)
from atlas.services.targets import ResolvedTarget, resolve_target, upsert_target

__all__ = [
    "DiscoveryOutcome",
    "DnsChange",
    "DnsOutcome",
    "ResolvedTarget",
    "add_rule",
    "asset_detail",
    "build_scope_set",
    "check_value",
    "create_project",
    "dangling_cnames",
    "delete_project",
    "discover",
    "dns_history",
    "dns_records",
    "ensure_domain",
    "ensure_ip_address",
    "get_asset",
    "get_project",
    "list_assets",
    "list_projects",
    "list_rules",
    "merge_observation_window",
    "nameserver_summary",
    "persist_dns_result",
    "project_stats",
    "record_event",
    "record_scan_results",
    "remove_rules",
    "resolve_target",
    "retire_dns_records",
    "slugify",
    "upsert_asset",
    "upsert_dns_record",
    "upsert_relationship",
    "upsert_target",
]
