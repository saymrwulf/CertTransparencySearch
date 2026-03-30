#!/usr/bin/env python3

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import ct_dns_utils
import ct_scan


@dataclass
class CaaObservation:
    name: str
    effective_rr_owner: str | None
    source_kind: str
    source_label: str | None
    aliases_seen: list[str]
    caa_rows: list[tuple[int, str, str]]


@dataclass
class CaaNameRow:
    name: str
    zone: str
    source_kind: str
    effective_rr_owner: str | None
    source_label: str | None
    aliases_seen: list[str]
    issue_values: list[str]
    issuewild_values: list[str]
    iodef_values: list[str]
    allowed_ca_families: list[str]
    current_covering_families: list[str]
    current_covering_subject_cns: list[str]
    current_covering_cert_count: int
    current_multi_family_overlap: bool
    current_policy_mismatch: bool
    mismatch_families: list[str]


@dataclass
class CaaAnalysis:
    generated_at_utc: str
    configured_domains: list[str]
    total_names: int
    rows: list[CaaNameRow]
    source_kind_counts: Counter[str]
    zone_counts: Counter[str]
    multi_family_overlap_names: list[str]
    policy_mismatch_names: list[str]


def normalize_dns_name(value: str) -> str:
    value = value.strip()
    if value.upper().startswith("DNS:"):
        return ct_dns_utils.normalize_name(value[4:])
    return ct_dns_utils.normalize_name(value)


def issuer_family(names: set[str]) -> str:
    lowered = " ".join(sorted(names)).lower()
    if "amazon" in lowered:
        return "Amazon"
    if "google trust services" in lowered or "cn=we1" in lowered:
        return "Google Trust Services"
    if "sectigo" in lowered or "comodo" in lowered:
        return "Sectigo/COMODO"
    if any(token in lowered for token in ["digicert", "quovadis", "thawte", "geotrust", "rapidssl", "symantec", "verisign"]):
        return "DigiCert/QuoVadis"
    return "Other"


def classify_zone(name: str, configured_domains: list[str]) -> str:
    for domain in sorted(configured_domains, key=len, reverse=True):
        lowered_domain = domain.lower()
        if name == lowered_domain or name.endswith(f".{lowered_domain}"):
            return lowered_domain
    return "other"


def cache_path(cache_dir: Path, name: str) -> Path:
    return cache_dir / ct_dns_utils.cache_key(f"caa-{name}")


def serialize_observation(observation: CaaObservation) -> dict[str, Any]:
    return {
        "name": observation.name,
        "effective_rr_owner": observation.effective_rr_owner,
        "source_kind": observation.source_kind,
        "source_label": observation.source_label,
        "aliases_seen": observation.aliases_seen,
        "caa_rows": [list(row) for row in observation.caa_rows],
    }


def deserialize_observation(payload: dict[str, Any]) -> CaaObservation:
    return CaaObservation(
        name=payload["name"],
        effective_rr_owner=payload.get("effective_rr_owner"),
        source_kind=payload["source_kind"],
        source_label=payload.get("source_label"),
        aliases_seen=list(payload.get("aliases_seen", [])),
        caa_rows=[(int(flag), str(tag), str(value)) for flag, tag, value in payload.get("caa_rows", [])],
    )


def parse_caa_response(lines: list[str]) -> tuple[list[tuple[int, str, str]], list[str]]:
    rows: list[tuple[int, str, str]] = []
    aliases: list[str] = []
    for line in lines:
        parts = line.split(maxsplit=2)
        if len(parts) == 3 and parts[0].isdigit():
            flag, tag, value = parts
            rows.append((int(flag), tag.lower(), value.strip().strip('"').lower()))
        elif line.endswith("."):
            aliases.append(ct_dns_utils.normalize_name(line))
    return rows, aliases


def query_caa_lines(name: str) -> list[str]:
    output = ct_dns_utils.run_dig(name, "CAA", short=True)
    return [line.strip() for line in output.splitlines() if line.strip()]


def relevant_caa_live(name: str) -> CaaObservation:
    labels = name.rstrip(".").lower().split(".")
    for index in range(len(labels)):
        candidate = ".".join(labels[index:])
        rows, aliases = parse_caa_response(query_caa_lines(candidate))
        if rows:
            if index == 0:
                source_kind = "alias_target" if aliases else "exact"
            else:
                source_kind = "parent_alias_target" if aliases else "parent"
            return CaaObservation(
                name=name,
                effective_rr_owner=candidate,
                source_kind=source_kind,
                source_label=aliases[-1] if aliases else candidate,
                aliases_seen=aliases,
                caa_rows=rows,
            )
    return CaaObservation(
        name=name,
        effective_rr_owner=None,
        source_kind="none",
        source_label=None,
        aliases_seen=[],
        caa_rows=[],
    )


def scan_name_cached(name: str, cache_dir: Path, ttl_seconds: int) -> CaaObservation:
    key = cache_path(cache_dir, name).name
    cached = ct_dns_utils.load_json_cache(cache_dir, key, ttl_seconds)
    if cached is not None:
        cached.pop("cached_at", None)
        return deserialize_observation(cached)
    observation = relevant_caa_live(name)
    ct_dns_utils.store_json_cache(cache_dir, key, serialize_observation(observation))
    return observation


def allowed_ca_families(caa_rows: list[tuple[int, str, str]]) -> list[str]:
    families: set[str] = set()
    for _flag, tag, value in caa_rows:
        if tag != "issue":
            continue
        normalized = value[:-1] if value.endswith(".") else value
        if any(token in normalized for token in ["amazon.com", "amazontrust.com", "awstrust.com", "amazonaws.com", "aws.amazon.com"]):
            families.add("Amazon")
        if any(token in normalized for token in ["sectigo.com", "comodoca.com", "comodo.com"]):
            families.add("Sectigo/COMODO")
        if any(token in normalized for token in ["digicert.com", "digicert.ne.jp", "thawte.com", "geotrust.com", "rapidssl.com", "symantec.com", "quovadisglobal.com", "digitalcertvalidation.com"]):
            families.add("DigiCert/QuoVadis")
        if "pki.goog" in normalized:
            families.add("Google Trust Services")
        if "letsencrypt.org" in normalized:
            families.add("Let's Encrypt")
        if any(token in normalized for token in ["telia.com", "telia.fi", "telia.se"]):
            families.add("Telia")
    return sorted(families)


def issue_values(caa_rows: list[tuple[int, str, str]], tag: str) -> list[str]:
    return sorted({value for _flag, row_tag, value in caa_rows if row_tag == tag})


def build_analysis(
    hits: list[ct_scan.CertificateHit],
    configured_domains: list[str],
    cache_dir: Path,
    ttl_seconds: int,
) -> CaaAnalysis:
    names = sorted(
        {
            normalize_dns_name(entry)
            for hit in hits
            for entry in hit.san_entries
            if normalize_dns_name(entry)
        }
    )
    coverage: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for hit in hits:
        family = issuer_family(hit.issuer_names)
        subject_cn = normalize_dns_name(hit.subject_cn)
        for entry in hit.san_entries:
            coverage[normalize_dns_name(entry)].append((subject_cn, family))

    rows: list[CaaNameRow] = []
    for name in names:
        observation = scan_name_cached(name, cache_dir, ttl_seconds)
        allowed_families = allowed_ca_families(observation.caa_rows)
        current_families = sorted({family for _subject, family in coverage[name]})
        mismatch_families = sorted(family for family in current_families if allowed_families and family not in allowed_families)
        rows.append(
            CaaNameRow(
                name=name,
                zone=classify_zone(name, configured_domains),
                source_kind=observation.source_kind,
                effective_rr_owner=observation.effective_rr_owner,
                source_label=observation.source_label,
                aliases_seen=observation.aliases_seen,
                issue_values=issue_values(observation.caa_rows, "issue"),
                issuewild_values=issue_values(observation.caa_rows, "issuewild"),
                iodef_values=issue_values(observation.caa_rows, "iodef"),
                allowed_ca_families=allowed_families,
                current_covering_families=current_families,
                current_covering_subject_cns=sorted({subject for subject, _family in coverage[name]}),
                current_covering_cert_count=len(coverage[name]),
                current_multi_family_overlap=len(current_families) > 1,
                current_policy_mismatch=bool(mismatch_families),
                mismatch_families=mismatch_families,
            )
        )

    return CaaAnalysis(
        generated_at_utc=ct_scan.utc_iso(datetime.now(UTC)),
        configured_domains=sorted(configured_domains),
        total_names=len(rows),
        rows=rows,
        source_kind_counts=Counter(row.source_kind for row in rows),
        zone_counts=Counter(row.zone for row in rows),
        multi_family_overlap_names=sorted(row.name for row in rows if row.current_multi_family_overlap),
        policy_mismatch_names=sorted(row.name for row in rows if row.current_policy_mismatch),
    )


def rows_for_zone(analysis: CaaAnalysis, zone: str) -> list[CaaNameRow]:
    return [row for row in analysis.rows if row.zone == zone]


def policy_counter(rows: list[CaaNameRow]) -> Counter[tuple[str, ...]]:
    counter: Counter[tuple[str, ...]] = Counter()
    for row in rows:
        key = tuple(row.allowed_ca_families) if row.allowed_ca_families else ("UNRESTRICTED",)
        counter[key] += 1
    return counter


def serialize_analysis(analysis: CaaAnalysis) -> dict[str, Any]:
    return {
        "generated_at_utc": analysis.generated_at_utc,
        "configured_domains": analysis.configured_domains,
        "total_names": analysis.total_names,
        "rows": [asdict(row) for row in analysis.rows],
        "source_kind_counts": dict(analysis.source_kind_counts),
        "zone_counts": dict(analysis.zone_counts),
        "multi_family_overlap_names": analysis.multi_family_overlap_names,
        "policy_mismatch_names": analysis.policy_mismatch_names,
    }
