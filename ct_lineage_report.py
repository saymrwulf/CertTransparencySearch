#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.x509.oid import NameOID
from psycopg.rows import dict_row

import ct_scan


HISTORICAL_QUERY_SQL = """
WITH ci AS (
    SELECT
        min(sub.certificate_id) AS id,
        min(sub.issuer_ca_id) AS issuer_ca_id,
        x509_commonName(sub.certificate) AS common_name,
        x509_subjectName(sub.certificate) AS subject_dn,
        x509_notBefore(sub.certificate) AS not_before,
        x509_notAfter(sub.certificate) AS not_after,
        encode(x509_serialNumber(sub.certificate), 'hex') AS serial_number,
        sub.certificate AS certificate
    FROM (
        SELECT cai.*
        FROM certificate_and_identities cai
        WHERE plainto_tsquery('certwatch', %(domain)s) @@ identities(cai.certificate)
          AND cai.name_value ILIKE %(name_pattern)s ESCAPE '\\'
        LIMIT %(max_candidates)s
    ) sub
    GROUP BY sub.certificate
)
SELECT
    ci.id,
    ci.issuer_ca_id,
    ca.name AS issuer_name,
    ci.common_name,
    ci.subject_dn,
    ci.not_before,
    ci.not_after,
    cl.first_seen,
    ci.serial_number,
    coalesce(cl.revoked, 0) AS revoked_count,
    rev.revocation_date,
    rev.reason_code,
    rev.last_seen_check_date,
    crl_state.active_crl_count,
    crl_state.last_checked AS crl_last_checked,
    ci.certificate
FROM ci
JOIN ca ON ca.id = ci.issuer_ca_id
JOIN certificate_lifecycle cl ON cl.certificate_id = ci.id
LEFT JOIN LATERAL (
    SELECT
        cr.revocation_date,
        cr.reason_code,
        cr.last_seen_check_date
    FROM crl_revoked cr
    WHERE cr.ca_id = ci.issuer_ca_id
      AND cr.serial_number = decode(ci.serial_number, 'hex')
    ORDER BY cr.last_seen_check_date DESC NULLS LAST
    LIMIT 1
) rev ON TRUE
LEFT JOIN LATERAL (
    SELECT
        count(*) FILTER (
            WHERE crl.error_message IS NULL
              AND crl.next_update > now() AT TIME ZONE 'UTC'
        ) AS active_crl_count,
        max(crl.last_checked) AS last_checked
    FROM crl
    WHERE crl.ca_id = ci.issuer_ca_id
) crl_state ON TRUE
WHERE cl.certificate_type = 'Certificate'
ORDER BY ci.not_before ASC, cl.first_seen ASC NULLS LAST, ci.id ASC;
"""


ENV_TOKENS = {
    "api",
    "auth",
    "developer",
    "webbanking",
    "sandbox",
    "dev",
    "test",
    "qa",
    "uat",
    "preprod",
    "prod",
    "stage",
    "stg",
    "release",
    "replica",
    "support",
    "hotfix",
    "monitoring",
    "mail",
    "statement",
    "update",
    "secure",
}


@dataclass
class HistoricalCertificate:
    fingerprint_sha256: str
    subject_cn: str
    subject_dn: str
    issuer_name: str
    issuer_family: str
    validity_not_before: datetime
    validity_not_after: datetime
    effective_not_after: datetime
    san_entries: list[str]
    first_seen: datetime | None
    current: bool
    revocation_status: str
    revocation_date: datetime | None
    matched_domains: set[str] = field(default_factory=set)
    crtsh_certificate_ids: set[int] = field(default_factory=set)
    serial_numbers: set[str] = field(default_factory=set)


@dataclass
class CnCollisionRow:
    subject_cn: str
    certificate_count: int
    current_certificate_count: int
    distinct_value_count: int
    issuer_families: str
    details: str


@dataclass
class SanChangeRow:
    subject_cn: str
    certificate_count: int
    current_certificate_count: int
    distinct_san_profiles: int
    stable_entries: int
    variable_entries: int
    delta_pattern: str
    representative_delta: str


@dataclass
class StartDayRow:
    start_day: str
    certificate_count: int
    top_subjects: str
    top_issuers: str


@dataclass
class StepWeekRow:
    week_start: str
    certificate_count: int
    prior_eight_week_avg: str
    top_subjects: str
    top_issuers: str


@dataclass
class OverlapRow:
    subject_cn: str
    asset_variant_count: int
    current_certificate_count: int
    lineage: str
    max_concurrent: int
    max_overlap_days: int
    overlap_class: str
    details: str


@dataclass
class RedFlagRow:
    subject_cn: str
    score: int
    certificate_count: int
    current_certificate_count: int
    flags: str
    notes: str


@dataclass
class HistoricalAssessment:
    domains: list[str]
    certificates: list[HistoricalCertificate]
    cn_groups: dict[str, list[HistoricalCertificate]]
    dn_rows: list[CnCollisionRow]
    dn_current_rows: list[CnCollisionRow]
    dn_past_rows: list[CnCollisionRow]
    issuer_rows: list[CnCollisionRow]
    vendor_rows: list[CnCollisionRow]
    vendor_current_rows: list[CnCollisionRow]
    vendor_past_rows: list[CnCollisionRow]
    san_rows: list[SanChangeRow]
    san_current_rows: list[SanChangeRow]
    san_past_rows: list[SanChangeRow]
    san_pattern_counts: Counter[str]
    overlap_current_rows: list[OverlapRow]
    overlap_past_rows: list[OverlapRow]
    normal_reissuance_assets: int
    repeated_asset_count: int
    current_red_flag_rows: list[RedFlagRow]
    past_red_flag_rows: list[RedFlagRow]
    day_rows: list[StartDayRow]
    week_rows: list[StepWeekRow]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyse historical certificate lineage, CN reuse, issuer drift, SAN drift, and issuance bursts."
    )
    parser.add_argument("--domains-file", type=Path, default=Path("domains.local.txt"))
    parser.add_argument("--cache-dir", type=Path, default=Path(".cache/ct-history-v2"))
    parser.add_argument("--cache-ttl-seconds", type=int, default=0)
    parser.add_argument("--max-candidates-per-domain", type=int, default=10000)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument(
        "--markdown-output",
        type=Path,
        default=Path("output/corpus/certificate-lineage-report.md"),
    )
    parser.add_argument(
        "--latex-output",
        type=Path,
        default=Path("output/corpus/certificate-lineage-report.tex"),
    )
    parser.add_argument(
        "--pdf-output",
        type=Path,
        default=Path("output/corpus/certificate-lineage-report.pdf"),
    )
    parser.add_argument("--skip-pdf", action="store_true")
    parser.add_argument("--pdf-engine", default="xelatex")
    parser.add_argument("--quiet", action="store_true")
    return parser.parse_args()


def short_issuer(issuer_name: str) -> str:
    lowered = issuer_name.lower()
    if "amazon" in lowered:
        return "Amazon"
    if "sectigo" in lowered or "comodo" in lowered:
        return "Sectigo/COMODO"
    if "digicert" in lowered:
        return "DigiCert"
    if "symantec" in lowered:
        return "Symantec"
    if "verisign" in lowered:
        return "VeriSign"
    if "cloudflare" in lowered:
        return "Cloudflare"
    if "google trust services" in lowered or "cn=we1" in lowered:
        return "Google Trust Services"
    return issuer_name


def pct(count: int, total: int) -> str:
    if total <= 0:
        return "0.0%"
    return f"{(count / total) * 100:.1f}%"


def md_table(headers: list[str], rows: list[list[str]]) -> list[str]:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return lines


def extract_common_name(cert: x509.Certificate) -> str | None:
    attributes = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attributes:
        return None
    return attributes[0].value


def query_historical_domain(domain: str, max_candidates: int, attempts: int, quiet: bool) -> list[ct_scan.DatabaseRecord]:
    raw_match_count = ct_scan.query_raw_match_count(domain=domain, attempts=attempts, verbose=not quiet)
    if raw_match_count > max_candidates:
        raise ValueError(
            f"domain={domain} raw identity matches={raw_match_count} exceed max_candidates={max_candidates}; "
            f"increase --max-candidates-per-domain to at least {raw_match_count} for a complete result set"
        )
    params = {
        "domain": domain,
        "name_pattern": f"%{ct_scan.escape_like(domain)}%",
        "max_candidates": max_candidates,
    }
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            with ct_scan.connect() as conn, conn.cursor(row_factory=dict_row) as cur:
                cur.execute(HISTORICAL_QUERY_SQL, params)
                rows = cur.fetchall()
            return [ct_scan.row_to_record(domain, row) for row in rows]
        except Exception as exc:
            last_error = exc
            if attempt == attempts:
                break
            if not quiet:
                print(
                    f"[warn] historical domain={domain} attempt={attempt}/{attempts} failed: {exc}",
                    file=__import__("sys").stderr,
                )
            __import__("time").sleep(min(2 ** attempt, 10))
    assert last_error is not None
    raise last_error


def load_records(args: argparse.Namespace) -> tuple[list[str], list[ct_scan.DatabaseRecord]]:
    domains = ct_scan.load_domains(args.domains_file)
    all_records: list[ct_scan.DatabaseRecord] = []
    for domain in domains:
        cached = ct_scan.load_cached_records(
            cache_dir=args.cache_dir,
            domain=domain,
            ttl_seconds=args.cache_ttl_seconds,
            max_candidates=args.max_candidates_per_domain,
        )
        if cached is not None:
            if not args.quiet:
                print(f"[cache] historical domain={domain} records={len(cached)}", file=__import__("sys").stderr)
            all_records.extend(cached)
            continue
        if not args.quiet:
            print(f"[query] historical domain={domain}", file=__import__("sys").stderr)
        queried = query_historical_domain(
            domain=domain,
            max_candidates=args.max_candidates_per_domain,
            attempts=args.retries,
            quiet=args.quiet,
        )
        ct_scan.store_cached_records(args.cache_dir, domain, args.max_candidates_per_domain, queried)
        all_records.extend(queried)
    return domains, all_records


def build_certificates(records: list[ct_scan.DatabaseRecord]) -> list[HistoricalCertificate]:
    now = datetime.now(UTC).replace(tzinfo=None)
    by_fingerprint: dict[str, HistoricalCertificate] = {}
    for record in records:
        cert = x509.load_der_x509_certificate(record.certificate_der)
        is_leaf, _reason = ct_scan.is_leaf_certificate(cert)
        if not is_leaf:
            continue
        fingerprint_sha256 = hashlib.sha256(record.certificate_der).hexdigest()
        hit = by_fingerprint.get(fingerprint_sha256)
        if hit is None:
            subject_cn = record.common_name or extract_common_name(cert) or "-"
            revocation_status, revocation_date, _revocation_reason, _crtsh_crl_timestamp, _revocation_note = ct_scan.revocation_fields(record)
            effective_not_after = record.not_after
            if revocation_status == "revoked" and revocation_date is not None and revocation_date < effective_not_after:
                effective_not_after = revocation_date
            hit = HistoricalCertificate(
                fingerprint_sha256=fingerprint_sha256,
                subject_cn=subject_cn,
                subject_dn=cert.subject.rfc4514_string(),
                issuer_name=record.issuer_name,
                issuer_family=short_issuer(record.issuer_name),
                validity_not_before=record.not_before,
                validity_not_after=record.not_after,
                effective_not_after=effective_not_after,
                san_entries=ct_scan.extract_san_entries(cert),
                first_seen=record.first_seen,
                current=record.not_before <= now <= record.not_after,
                revocation_status=revocation_status,
                revocation_date=revocation_date,
                matched_domains={record.domain},
                crtsh_certificate_ids={record.certificate_id},
                serial_numbers={record.serial_number},
            )
            by_fingerprint[fingerprint_sha256] = hit
            continue
        hit.matched_domains.add(record.domain)
        hit.crtsh_certificate_ids.add(record.certificate_id)
        hit.serial_numbers.add(record.serial_number)
        if hit.first_seen is None or (record.first_seen is not None and record.first_seen < hit.first_seen):
            hit.first_seen = record.first_seen
    return sorted(
        by_fingerprint.values(),
        key=lambda item: (
            item.subject_cn.casefold(),
            item.validity_not_before,
            item.fingerprint_sha256,
        ),
    )


def group_by_subject_cn(certificates: list[HistoricalCertificate]) -> dict[str, list[HistoricalCertificate]]:
    groups: dict[str, list[HistoricalCertificate]] = defaultdict(list)
    for certificate in certificates:
        groups[certificate.subject_cn.lower()].append(certificate)
    return groups


def summarize_name_list(values: set[str], limit: int = 3) -> str:
    ordered = sorted(values, key=str.casefold)
    if len(ordered) <= limit:
        return ", ".join(ordered)
    return ", ".join(ordered[:limit]) + f", ... (+{len(ordered) - limit} more)"


def family_counter(values: list[HistoricalCertificate]) -> Counter[str]:
    return Counter(item.issuer_family for item in values)


def dn_change_rows(cn_groups: dict[str, list[HistoricalCertificate]]) -> list[CnCollisionRow]:
    rows: list[CnCollisionRow] = []
    for certificates in cn_groups.values():
        dns = {item.subject_dn for item in certificates}
        if len(dns) <= 1:
            continue
        subject_cn = min({item.subject_cn for item in certificates}, key=str.casefold)
        rows.append(
            CnCollisionRow(
                subject_cn=subject_cn,
                certificate_count=len(certificates),
                current_certificate_count=sum(1 for item in certificates if item.current),
                distinct_value_count=len(dns),
                issuer_families=", ".join(
                    f"{name} ({count})" for name, count in family_counter(certificates).most_common()
                ),
                details=summarize_name_list(dns, limit=2),
            )
        )
    return sorted(
        rows,
        key=lambda item: (-item.distinct_value_count, -item.certificate_count, item.subject_cn.casefold()),
    )


def issuer_change_rows(
    cn_groups: dict[str, list[HistoricalCertificate]],
) -> tuple[list[CnCollisionRow], list[CnCollisionRow]]:
    exact_rows: list[CnCollisionRow] = []
    vendor_rows: list[CnCollisionRow] = []
    for certificates in cn_groups.values():
        issuer_names = {item.issuer_name for item in certificates}
        issuer_families = {item.issuer_family for item in certificates}
        subject_cn = min({item.subject_cn for item in certificates}, key=str.casefold)
        if len(issuer_names) > 1:
            exact_rows.append(
                CnCollisionRow(
                    subject_cn=subject_cn,
                    certificate_count=len(certificates),
                    current_certificate_count=sum(1 for item in certificates if item.current),
                    distinct_value_count=len(issuer_names),
                    issuer_families=", ".join(
                        f"{name} ({count})" for name, count in family_counter(certificates).most_common()
                    ),
                    details=summarize_name_list(issuer_names, limit=3),
                )
            )
        if len(issuer_families) > 1:
            vendor_rows.append(
                CnCollisionRow(
                    subject_cn=subject_cn,
                    certificate_count=len(certificates),
                    current_certificate_count=sum(1 for item in certificates if item.current),
                    distinct_value_count=len(issuer_families),
                    issuer_families=", ".join(
                        f"{name} ({count})" for name, count in family_counter(certificates).most_common()
                    ),
                    details=summarize_name_list(issuer_families, limit=4),
                )
            )
    ordering = lambda item: (-item.distinct_value_count, -item.certificate_count, item.subject_cn.casefold())
    return (sorted(exact_rows, key=ordering), sorted(vendor_rows, key=ordering))


def classify_san_delta(delta_entries: set[str]) -> str:
    dns_names = [entry[4:] for entry in delta_entries if entry.startswith("DNS:")]
    if not dns_names:
        return "non-DNS SAN drift"
    if all(name.startswith("www.") or f"www.{name}" in dns_names for name in dns_names):
        return "www toggle"
    zones = {ct_scan.san_tail_split(name)[1] for name in dns_names}
    if len(zones) > 1:
        return "cross-zone bridge change"
    lowered = " ".join(dns_names).lower()
    if any(token in lowered for token in ENV_TOKENS) or any(char.isdigit() for char in lowered):
        return "environment or fleet change"
    if len(dns_names) <= 3:
        return "small alias change"
    return "broad SAN redesign"


def representative_delta(delta_entries: set[str]) -> str:
    values = sorted(delta_entries, key=str.casefold)
    if not values:
        return "-"
    if len(values) <= 4:
        return ", ".join(values)
    return ", ".join(values[:4]) + f", ... (+{len(values) - 4} more)"


def san_change_rows(cn_groups: dict[str, list[HistoricalCertificate]]) -> tuple[list[SanChangeRow], Counter[str]]:
    rows: list[SanChangeRow] = []
    pattern_counts: Counter[str] = Counter()
    for certificates in cn_groups.values():
        profiles = {tuple(item.san_entries) for item in certificates}
        if len(profiles) <= 1:
            continue
        subject_cn = min({item.subject_cn for item in certificates}, key=str.casefold)
        profile_sets = [set(profile) for profile in profiles]
        stable_entries = set.intersection(*profile_sets)
        all_entries = set.union(*profile_sets)
        delta_entries = all_entries - stable_entries
        pattern = classify_san_delta(delta_entries)
        pattern_counts[pattern] += 1
        rows.append(
            SanChangeRow(
                subject_cn=subject_cn,
                certificate_count=len(certificates),
                current_certificate_count=sum(1 for item in certificates if item.current),
                distinct_san_profiles=len(profiles),
                stable_entries=len(stable_entries),
                variable_entries=len(delta_entries),
                delta_pattern=pattern,
                representative_delta=representative_delta(delta_entries),
            )
        )
    rows.sort(
        key=lambda item: (
            -item.distinct_san_profiles,
            -item.variable_entries,
            -item.certificate_count,
            item.subject_cn.casefold(),
        )
    )
    return rows, pattern_counts


def overlap_days(left: HistoricalCertificate, right: HistoricalCertificate) -> int:
    start = max(left.validity_not_before, right.validity_not_before)
    end = min(left.effective_not_after, right.effective_not_after)
    if end <= start:
        return 0
    return max(1, (end - start).days)


def overlap_class(days: int) -> str:
    if days <= 0:
        return "no overlap"
    if days < 50:
        return "normal rollover"
    return "red flag (>=50 days)"


def build_asset_key(certificate: HistoricalCertificate) -> tuple[str, str, tuple[str, ...], str]:
    return (
        certificate.subject_cn.lower(),
        certificate.subject_dn,
        tuple(certificate.san_entries),
        certificate.issuer_family,
    )


def overlap_metrics(certificates: list[HistoricalCertificate]) -> tuple[int, int]:
    if len(certificates) < 2:
        return (0, max(1, len(certificates)))
    ordered = sorted(
        certificates,
        key=lambda item: (
            item.validity_not_before,
            item.effective_not_after,
            item.fingerprint_sha256,
        ),
    )
    max_overlap = 0
    max_concurrent = 1
    active: list[HistoricalCertificate] = []
    for certificate in ordered:
        active = [item for item in active if item.effective_not_after > certificate.validity_not_before]
        for other in active:
            max_overlap = max(max_overlap, overlap_days(other, certificate))
        active.append(certificate)
        max_concurrent = max(max_concurrent, len(active))
    return (max_overlap, max_concurrent)


def overlap_row_from_asset(
    asset_certificates: list[HistoricalCertificate],
    overlap_days_value: int,
    max_concurrent: int,
    details_prefix: str,
) -> OverlapRow:
    ordered = sorted(
        asset_certificates,
        key=lambda item: (
            item.validity_not_before,
            item.effective_not_after,
            item.fingerprint_sha256,
        ),
    )
    representative = ordered[0]
    return OverlapRow(
        subject_cn=representative.subject_cn,
        asset_variant_count=len(ordered),
        current_certificate_count=sum(1 for item in ordered if item.current),
        lineage=representative.issuer_family,
        max_concurrent=max_concurrent,
        max_overlap_days=overlap_days_value,
        overlap_class=overlap_class(overlap_days_value),
        details=(
            f"{details_prefix}; "
            f"DN={representative.subject_dn}; "
            f"SANs={len(representative.san_entries)}; "
            f"windows={', '.join(f'{item.validity_not_before.date().isoformat()}->{item.effective_not_after.date().isoformat()}' for item in ordered[:4])}"
            + ("" if len(ordered) <= 4 else f", ... (+{len(ordered) - 4} more)")
        ),
    )


def overlap_rows(cn_groups: dict[str, list[HistoricalCertificate]]) -> tuple[list[OverlapRow], list[OverlapRow], int, int]:
    normal_reissuance = 0
    repeated_asset_count = 0
    current_red_flags: list[OverlapRow] = []
    past_red_flags: list[OverlapRow] = []
    for certificates in cn_groups.values():
        by_asset: dict[tuple[str, str, tuple[str, ...], str], list[HistoricalCertificate]] = defaultdict(list)
        for certificate in certificates:
            by_asset[build_asset_key(certificate)].append(certificate)
        for asset_certificates in by_asset.values():
            if len(asset_certificates) < 2:
                continue
            repeated_asset_count += 1
            max_overlap, max_concurrent = overlap_metrics(asset_certificates)
            current_certificates = [item for item in asset_certificates if item.current]
            current_overlap, current_concurrent = overlap_metrics(current_certificates)
            if max_overlap < 50:
                normal_reissuance += 1
                continue
            if current_overlap >= 50:
                current_red_flags.append(
                    overlap_row_from_asset(
                        current_certificates,
                        current_overlap,
                        current_concurrent,
                        f"current overlap persists; historical max overlap={max_overlap} days",
                    )
                )
                continue
            past_red_flags.append(
                overlap_row_from_asset(
                    asset_certificates,
                    max_overlap,
                    max_concurrent,
                    "historical overlap reached red-flag territory, but no currently valid pair still does",
                )
            )
    ordering = lambda item: (-item.max_overlap_days, -item.max_concurrent, -item.asset_variant_count, item.subject_cn.casefold())
    return (
        sorted(current_red_flags, key=ordering),
        sorted(past_red_flags, key=ordering),
        normal_reissuance,
        repeated_asset_count,
    )


def build_red_flag_rows(
    cn_groups: dict[str, list[HistoricalCertificate]],
    dn_rows: list[CnCollisionRow],
    vendor_rows: list[CnCollisionRow],
    san_rows: list[SanChangeRow],
    overlap_rows_: list[OverlapRow],
) -> list[RedFlagRow]:
    dn_set = {row.subject_cn.lower() for row in dn_rows}
    vendor_set = {row.subject_cn.lower() for row in vendor_rows}
    san_set = {row.subject_cn.lower() for row in san_rows}
    overlap_set = {row.subject_cn.lower() for row in overlap_rows_}
    rows: list[RedFlagRow] = []
    for key, certificates in cn_groups.items():
        flags: list[str] = []
        if key in overlap_set:
            flags.append("overlap >=50 days")
        if key in dn_set:
            flags.append("Subject DN drift")
        if key in vendor_set:
            flags.append("CA lineage drift")
        if key in san_set:
            flags.append("SAN drift")
        if not flags:
            continue
        issuer_mix = Counter(item.issuer_family for item in certificates)
        notes = ", ".join(f"{name} ({count})" for name, count in issuer_mix.most_common())
        rows.append(
            RedFlagRow(
                subject_cn=min({item.subject_cn for item in certificates}, key=str.casefold),
                score=len(flags),
                certificate_count=len(certificates),
                current_certificate_count=sum(1 for item in certificates if item.current),
                flags=", ".join(flags),
                notes=notes,
            )
        )
    rows.sort(key=lambda item: (-item.score, -item.certificate_count, item.subject_cn.casefold()))
    return rows


def top_start_days(certificates: list[HistoricalCertificate], limit: int = 12) -> list[StartDayRow]:
    by_day: dict[date, list[HistoricalCertificate]] = defaultdict(list)
    for certificate in certificates:
        by_day[certificate.validity_not_before.date()].append(certificate)
    rows: list[StartDayRow] = []
    for start_day, day_items in sorted(by_day.items(), key=lambda item: (-len(item[1]), item[0])):
        subject_counts = Counter(item.subject_cn for item in day_items)
        issuer_counts = Counter(item.issuer_family for item in day_items)
        rows.append(
            StartDayRow(
                start_day=start_day.isoformat(),
                certificate_count=len(day_items),
                top_subjects=", ".join(f"{name} ({count})" for name, count in subject_counts.most_common(4)),
                top_issuers=", ".join(f"{name} ({count})" for name, count in issuer_counts.most_common()),
            )
        )
    return rows[:limit]


def spike_weeks(certificates: list[HistoricalCertificate], min_count: int = 8) -> list[StepWeekRow]:
    by_week: dict[date, list[HistoricalCertificate]] = defaultdict(list)
    for certificate in certificates:
        start_day = certificate.validity_not_before.date()
        week_start = start_day - timedelta(days=start_day.weekday())
        by_week[week_start].append(certificate)
    ordered_weeks = sorted(by_week)
    counts = [len(by_week[week]) for week in ordered_weeks]
    rows: list[StepWeekRow] = []
    for index, week in enumerate(ordered_weeks):
        current_count = counts[index]
        prior = counts[max(0, index - 8):index]
        if len(prior) < 4:
            continue
        prior_avg = sum(prior) / len(prior)
        if current_count < min_count:
            continue
        if current_count < prior_avg * 2 and current_count < prior_avg + 8:
            continue
        week_items = by_week[week]
        subject_counts = Counter(item.subject_cn for item in week_items)
        issuer_counts = Counter(item.issuer_family for item in week_items)
        rows.append(
            StepWeekRow(
                week_start=week.isoformat(),
                certificate_count=current_count,
                prior_eight_week_avg=f"{prior_avg:.1f}",
                top_subjects=", ".join(f"{name} ({count})" for name, count in subject_counts.most_common(4)),
                top_issuers=", ".join(f"{name} ({count})" for name, count in issuer_counts.most_common()),
            )
        )
    return rows


def partition_collision_rows(
    rows: list[CnCollisionRow],
    cn_groups: dict[str, list[HistoricalCertificate]],
    value_getter,
) -> tuple[list[CnCollisionRow], list[CnCollisionRow]]:
    current_rows: list[CnCollisionRow] = []
    past_rows: list[CnCollisionRow] = []
    for row in rows:
        certificates = cn_groups[row.subject_cn.lower()]
        current_values = {value_getter(item) for item in certificates if item.current}
        if len(current_values) > 1:
            current_rows.append(row)
        else:
            past_rows.append(row)
    return current_rows, past_rows


def partition_san_rows(
    rows: list[SanChangeRow],
    cn_groups: dict[str, list[HistoricalCertificate]],
) -> tuple[list[SanChangeRow], list[SanChangeRow]]:
    current_rows: list[SanChangeRow] = []
    past_rows: list[SanChangeRow] = []
    for row in rows:
        certificates = cn_groups[row.subject_cn.lower()]
        current_profiles = {tuple(item.san_entries) for item in certificates if item.current}
        if len(current_profiles) > 1:
            current_rows.append(row)
        else:
            past_rows.append(row)
    return current_rows, past_rows


def build_assessment(args: argparse.Namespace) -> HistoricalAssessment:
    domains, records = load_records(args)
    certificates = build_certificates(records)
    cn_groups = group_by_subject_cn(certificates)
    dn_rows = dn_change_rows(cn_groups)
    issuer_rows, vendor_rows = issuer_change_rows(cn_groups)
    san_rows, san_pattern_counts = san_change_rows(cn_groups)
    overlap_current_rows, overlap_past_rows, normal_reissuance_assets, repeated_asset_count = overlap_rows(cn_groups)
    dn_current_rows, dn_past_rows = partition_collision_rows(dn_rows, cn_groups, lambda item: item.subject_dn)
    vendor_current_rows, vendor_past_rows = partition_collision_rows(vendor_rows, cn_groups, lambda item: item.issuer_family)
    san_current_rows, san_past_rows = partition_san_rows(san_rows, cn_groups)
    current_red_flag_rows = build_red_flag_rows(
        cn_groups,
        dn_current_rows,
        vendor_current_rows,
        san_current_rows,
        overlap_current_rows,
    )
    past_red_flag_rows = build_red_flag_rows(
        cn_groups,
        dn_past_rows,
        vendor_past_rows,
        san_past_rows,
        overlap_past_rows,
    )
    day_rows = top_start_days(certificates)
    week_rows = spike_weeks(certificates)
    return HistoricalAssessment(
        domains=domains,
        certificates=certificates,
        cn_groups=cn_groups,
        dn_rows=dn_rows,
        dn_current_rows=dn_current_rows,
        dn_past_rows=dn_past_rows,
        issuer_rows=issuer_rows,
        vendor_rows=vendor_rows,
        vendor_current_rows=vendor_current_rows,
        vendor_past_rows=vendor_past_rows,
        san_rows=san_rows,
        san_current_rows=san_current_rows,
        san_past_rows=san_past_rows,
        san_pattern_counts=san_pattern_counts,
        overlap_current_rows=overlap_current_rows,
        overlap_past_rows=overlap_past_rows,
        normal_reissuance_assets=normal_reissuance_assets,
        repeated_asset_count=repeated_asset_count,
        current_red_flag_rows=current_red_flag_rows,
        past_red_flag_rows=past_red_flag_rows,
        day_rows=day_rows,
        week_rows=week_rows,
    )


def render_markdown(args: argparse.Namespace, assessment: HistoricalAssessment) -> None:
    args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
    certificates = assessment.certificates
    current_count = sum(1 for item in certificates if item.current)
    cn_groups = assessment.cn_groups
    repeated_cn_count = sum(1 for values in cn_groups.values() if len(values) > 1)
    same_cn_same_dn = sum(1 for values in cn_groups.values() if len(values) > 1 and len({item.subject_dn for item in values}) == 1)

    lines: list[str] = []
    lines.append("# Historical Certificate Lineage Analysis")
    lines.append("")
    lines.append(f"Generated: {ct_scan.utc_iso(datetime.now(UTC))}")
    lines.append(f"Configured search terms file: `{args.domains_file.name}`")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.extend(
        [
            f"- Historical unique leaf certificates in scope: **{len(certificates)}**.",
            f"- Currently valid subset inside that historical corpus: **{current_count}**.",
            f"- Distinct Subject CN values: **{len(cn_groups)}**.",
            f"- Subject CNs with more than one certificate over time: **{repeated_cn_count}**.",
            f"- Renewal asset lineages with only normal rollover overlap (`<50 days`): **{assessment.normal_reissuance_assets}**.",
            f"- Renewal asset lineages with a current overlap red flag (`>=50 days`): **{len(assessment.overlap_current_rows)}**.",
            f"- Renewal asset lineages with a past-only overlap red flag now fixed: **{len(assessment.overlap_past_rows)}**.",
            f"- Subject CN values with current red flags: **{len(assessment.current_red_flag_rows)}**.",
            f"- Subject CN values with past-only red flags now fixed: **{len(assessment.past_red_flag_rows)}**.",
        ]
    )
    lines.append("")
    lines.append("This report treats Subject CN as a hostname label, not as a unique asset key. The point is to follow certificate lineage through renewals, issuer changes, SAN changes, and issuance bursts across both current and expired certificates, while separating normal rollover from red-flag behavior.")
    lines.append("")
    lines.append("## Reading Notes")
    lines.append("")
    lines.extend(
        [
            "- **Subject CN** is the hostname placed in the certificate's Common Name field.",
            "- **Subject DN** is the full subject identity string, not just the hostname.",
            "- **SAN profile** means the complete set of SAN entries carried by a certificate.",
            "- **CA lineage** collapses exact issuer names into vendor-level families. In this report, legacy COMODO and Sectigo are treated as one lineage: `Sectigo/COMODO`.",
            "- A **renewal asset lineage** means the same Subject CN, same Subject DN, same SAN profile, and same CA lineage reissued over time.",
            "- Overlap threshold used here: anything `<50 days` is treated as normal rollover; anything `>=50 days` is treated as a red flag.",
            "- A **past-only** red flag means the issue is visible historically, but no currently valid certificate still carries that same red-flag condition.",
            "- A **current** red flag means at least one currently valid certificate still participates in that same red-flag condition.",
        ]
    )
    lines.append("")
    lines.append("## Chapter 1: Renewal Baseline Versus Overlap Red Flags")
    lines.append("")
    lines.append("**Management Summary**")
    lines.append("")
    lines.extend(
        [
            f"- {repeated_cn_count} of {len(cn_groups)} Subject CN values have more than one certificate across the historical corpus.",
            f"- {assessment.repeated_asset_count} renewal asset lineages contain more than one certificate.",
            f"- {assessment.normal_reissuance_assets} of those renewal asset lineages stay below the 50-day overlap threshold and fit the normal renewal model.",
            f"- {len(assessment.overlap_current_rows)} renewal asset lineages still have a current overlap red flag.",
            f"- {len(assessment.overlap_past_rows)} renewal asset lineages had an overlap red flag historically, but that issue is not current anymore.",
            f"- {same_cn_same_dn} repeated Subject CN values keep the same Subject DN while rotating serial number, validity span, or SAN profile.",
        ]
    )
    lines.append("")
    lines.append("This is the baseline that matters before any anomaly analysis. Most service names are not single certificates frozen in time. They are lineages of certificates issued, renewed, and sometimes restructured under the same public hostname. The key distinction is whether successor and predecessor overlap only briefly, which is normal, or coexist for fifty days or longer, which is the threshold treated here as a red flag.")
    lines.append("")
    if assessment.overlap_current_rows:
        lines.append("### Current Overlap Red Flags")
        lines.append("")
        lines.extend(
            md_table(
                ["Subject CN", "Lineage", "Asset Certs", "Current", "Max Concurrent", "Max Overlap Days", "Class", "Asset Details"],
                [
                    [
                        row.subject_cn,
                        row.lineage,
                        str(row.asset_variant_count),
                        str(row.current_certificate_count),
                        str(row.max_concurrent),
                        str(row.max_overlap_days),
                        row.overlap_class,
                        row.details,
                    ]
                    for row in assessment.overlap_current_rows[:20]
                ],
            )
        )
        lines.append("")
    if assessment.overlap_past_rows:
        lines.append("### Past Overlap Red Flags Now Fixed")
        lines.append("")
        lines.extend(
            md_table(
                ["Subject CN", "Lineage", "Asset Certs", "Current", "Max Concurrent", "Max Overlap Days", "Class", "Asset Details"],
                [
                    [
                        row.subject_cn,
                        row.lineage,
                        str(row.asset_variant_count),
                        str(row.current_certificate_count),
                        str(row.max_concurrent),
                        str(row.max_overlap_days),
                        row.overlap_class,
                        row.details,
                    ]
                    for row in assessment.overlap_past_rows[:20]
                ],
            )
        )
        lines.append("")
    lines.append("## Chapter 2: Current Red Flags")
    lines.append("")
    lines.append("**Management Summary**")
    lines.append("")
    lines.extend(
        [
            f"- Current overlap red flags: {len(assessment.overlap_current_rows)} Subject-CN asset lineages.",
            f"- Current Subject DN drift: {len(assessment.dn_current_rows)} Subject CN values.",
            f"- Current CA lineage drift: {len(assessment.vendor_current_rows)} Subject CN values.",
            f"- Current SAN drift: {len(assessment.san_current_rows)} Subject CN values.",
            "- This chapter is the shortest route to the names that deserve present-tense manual review.",
        ]
    )
    lines.append("")
    if assessment.current_red_flag_rows:
        lines.extend(
            md_table(
                ["Subject CN", "Score", "Certs", "Current", "Flags", "Issuer Mix"],
                [
                    [
                        row.subject_cn,
                        str(row.score),
                        str(row.certificate_count),
                        str(row.current_certificate_count),
                        row.flags,
                        row.notes,
                    ]
                    for row in assessment.current_red_flag_rows[:30]
                ],
            )
        )
        lines.append("")
    else:
        lines.append("No current red flags were found under the configured rules.")
        lines.append("")
    lines.append("## Chapter 3: Past Red Flags Now Fixed")
    lines.append("")
    lines.append("**Management Summary**")
    lines.append("")
    lines.extend(
        [
            f"- Past-only overlap red flags now fixed: {len(assessment.overlap_past_rows)} Subject-CN asset lineages.",
            f"- Past-only Subject DN drift now fixed: {len(assessment.dn_past_rows)} Subject CN values.",
            f"- Past-only CA lineage drift now fixed: {len(assessment.vendor_past_rows)} Subject CN values.",
            f"- Past-only SAN drift now fixed: {len(assessment.san_past_rows)} Subject CN values.",
            "- These are not present-tense problems, but they matter because they show how the estate used to behave.",
        ]
    )
    lines.append("")
    if assessment.past_red_flag_rows:
        lines.extend(
            md_table(
                ["Subject CN", "Score", "Certs", "Current", "Flags", "Issuer Mix"],
                [
                    [
                        row.subject_cn,
                        str(row.score),
                        str(row.certificate_count),
                        str(row.current_certificate_count),
                        row.flags,
                        row.notes,
                    ]
                    for row in assessment.past_red_flag_rows[:30]
                ],
            )
        )
        lines.append("")
    else:
        lines.append("No historical red flags were found under the configured rules.")
        lines.append("")
    lines.append("## Chapter 4: Subject DN Drift")
    lines.append("")
    lines.append("**Management Summary**")
    lines.append("")
    lines.extend(
        [
            f"- Current Subject DN drift: {len(assessment.dn_current_rows)}.",
            f"- Past-only Subject DN drift now fixed: {len(assessment.dn_past_rows)}.",
            f"- Total Subject CN values with more than one Subject DN across history: {len(assessment.dn_rows)}.",
            "- This is relevant because it means the hostname stayed the same while the full subject identity string changed.",
            "- That does not automatically imply a security problem, but it is exactly the kind of drift that deserves review when you care about ownership, issuance policy, or certificate governance.",
        ]
    )
    lines.append("")
    if assessment.dn_current_rows:
        lines.append("### Current Subject DN Drift")
        lines.append("")
        lines.extend(
            md_table(
                ["Subject CN", "Certs", "Current", "Distinct Subject DNs", "Issuer Families", "Subject DN Samples"],
                [
                    [
                        row.subject_cn,
                        str(row.certificate_count),
                        str(row.current_certificate_count),
                        str(row.distinct_value_count),
                        row.issuer_families,
                        row.details,
                    ]
                    for row in assessment.dn_current_rows[:20]
                ],
            )
        )
        lines.append("")
    if assessment.dn_past_rows:
        lines.append("### Past Subject DN Drift Now Fixed")
        lines.append("")
        lines.extend(
            md_table(
                ["Subject CN", "Certs", "Current", "Distinct Subject DNs", "Issuer Families", "Subject DN Samples"],
                [
                    [
                        row.subject_cn,
                        str(row.certificate_count),
                        str(row.current_certificate_count),
                        str(row.distinct_value_count),
                        row.issuer_families,
                        row.details,
                    ]
                    for row in assessment.dn_past_rows[:20]
                ],
            )
        )
        lines.append("")
    if not assessment.dn_rows:
        lines.append("No cases were found.")
        lines.append("")
    lines.append("## Chapter 5: CA Lineage Drift")
    lines.append("")
    lines.append("**Management Summary**")
    lines.append("")
    lines.extend(
        [
            f"- Exact issuer-name changes across history: {len(assessment.issuer_rows)} Subject CN values.",
            f"- Current CA lineage drift: {len(assessment.vendor_current_rows)} Subject CN values.",
            f"- Past-only CA lineage drift now fixed: {len(assessment.vendor_past_rows)} Subject CN values.",
            "- Exact issuer changes inside one lineage can be operationally normal. The stronger red flag is a drift between different CA lineages, with COMODO and Sectigo deliberately collapsed into one lineage here.",
        ]
    )
    lines.append("")
    if assessment.vendor_current_rows:
        lines.append("### Current CA Lineage Drift")
        lines.append("")
        lines.extend(
            md_table(
                ["Subject CN", "Certs", "Current", "Distinct Lineages", "Lineage Mix", "Lineages Seen"],
                [
                    [
                        row.subject_cn,
                        str(row.certificate_count),
                        str(row.current_certificate_count),
                        str(row.distinct_value_count),
                        row.issuer_families,
                        row.details,
                    ]
                    for row in assessment.vendor_current_rows[:20]
                ],
            )
        )
        lines.append("")
    if assessment.vendor_past_rows:
        lines.append("### Past CA Lineage Drift Now Fixed")
        lines.append("")
        lines.extend(
            md_table(
                ["Subject CN", "Certs", "Current", "Distinct Lineages", "Lineage Mix", "Lineages Seen"],
                [
                    [
                        row.subject_cn,
                        str(row.certificate_count),
                        str(row.current_certificate_count),
                        str(row.distinct_value_count),
                        row.issuer_families,
                        row.details,
                    ]
                    for row in assessment.vendor_past_rows[:20]
                ],
            )
        )
        lines.append("")
    if assessment.issuer_rows:
        lines.append("### Exact Issuer Changes Inside The Same Or Different Lineages")
        lines.append("")
        lines.extend(
            md_table(
                ["Subject CN", "Certs", "Current", "Distinct Issuers", "Lineage Mix", "Issuer Samples"],
                [
                    [
                        row.subject_cn,
                        str(row.certificate_count),
                        str(row.current_certificate_count),
                        str(row.distinct_value_count),
                        row.issuer_families,
                        row.details,
                    ]
                    for row in assessment.issuer_rows[:20]
                ],
            )
        )
        lines.append("")
    lines.append("## Chapter 6: SAN Profile Drift")
    lines.append("")
    lines.append("**Management Summary**")
    lines.append("")
    lines.extend(
        [
            f"- Current SAN drift: {len(assessment.san_current_rows)} Subject CN values.",
            f"- Past-only SAN drift now fixed: {len(assessment.san_past_rows)} Subject CN values.",
            f"- Total Subject CN values with more than one distinct SAN profile across history: {len(assessment.san_rows)}.",
            f"- Top SAN-delta pattern classes: {', '.join(f'{name} ({count})' for name, count in assessment.san_pattern_counts.most_common()) or 'none'}.",
            "- This shows whether the service name stayed stable while the covered endpoint set expanded, contracted, or shifted shape.",
        ]
    )
    lines.append("")
    if assessment.san_current_rows:
        lines.append("### Current SAN Drift")
        lines.append("")
        lines.extend(
            md_table(
                [
                    "Subject CN",
                    "Certs",
                    "Current",
                    "SAN Profiles",
                    "Stable SANs",
                    "Variable SANs",
                    "Delta Pattern",
                    "Representative Delta",
                ],
                [
                    [
                        row.subject_cn,
                        str(row.certificate_count),
                        str(row.current_certificate_count),
                        str(row.distinct_san_profiles),
                        str(row.stable_entries),
                        str(row.variable_entries),
                        row.delta_pattern,
                        row.representative_delta,
                    ]
                    for row in assessment.san_current_rows[:20]
                ],
            )
        )
        lines.append("")
    if assessment.san_past_rows:
        lines.append("### Past SAN Drift Now Fixed")
        lines.append("")
        lines.extend(
            md_table(
                [
                    "Subject CN",
                    "Certs",
                    "Current",
                    "SAN Profiles",
                    "Stable SANs",
                    "Variable SANs",
                    "Delta Pattern",
                    "Representative Delta",
                ],
                [
                    [
                        row.subject_cn,
                        str(row.certificate_count),
                        str(row.current_certificate_count),
                        str(row.distinct_san_profiles),
                        str(row.stable_entries),
                        str(row.variable_entries),
                        row.delta_pattern,
                        row.representative_delta,
                    ]
                    for row in assessment.san_past_rows[:20]
                ],
            )
        )
        lines.append("")
    lines.append("## Chapter 7: Historic Issuance Bursts And Step Changes")
    lines.append("")
    lines.append("**Management Summary**")
    lines.append("")
    lines.extend(
        [
            "- This chapter includes expired certificates on purpose, because step changes are historical phenomena rather than current-only phenomena.",
            "- Strong same-day or same-week issuance bursts usually signal planned renewal waves, platform migrations, or bulk onboarding of service families.",
            f"- Top issuance start dates: {', '.join(f'{row.start_day} ({row.certificate_count})' for row in assessment.day_rows[:6])}.",
        ]
    )
    lines.append("")
    lines.append("### Top Start Dates")
    lines.append("")
    lines.extend(
        md_table(
            ["Start Day", "Certificates", "Top Subject CNs", "Top Issuer Families"],
            [[row.start_day, str(row.certificate_count), row.top_subjects, row.top_issuers] for row in assessment.day_rows],
        )
    )
    lines.append("")
    lines.append("### Step Weeks")
    lines.append("")
    if assessment.week_rows:
        lines.extend(
            md_table(
                ["Week Start", "Certificates", "Prior 8-Week Avg", "Top Subject CNs", "Top Issuer Families"],
                [
                    [
                        row.week_start,
                        str(row.certificate_count),
                        row.prior_eight_week_avg,
                        row.top_subjects,
                        row.top_issuers,
                    ]
                    for row in assessment.week_rows[:20]
                ],
            )
        )
        lines.append("")
    else:
        lines.append("No step weeks met the configured threshold.")
        lines.append("")
    lines.append("## Chapter 8: Interpretation")
    lines.append("")
    lines.append("The main operational picture is not one of single certificates mapped one-to-one to service names. It is a layered certificate lineage model. The normal case is rollover inside a stable renewal asset lineage with less than fifty days of overlap. The red flags are the exceptions layered on top of that baseline: overlap that persists for fifty days or more, Subject DN drift, CA lineage drift, and SAN drift. The current-versus-past split matters because it distinguishes live governance concerns from issues that appear to have been corrected already.")
    lines.append("")
    args.markdown_output.write_text("\n".join(lines) + "\n", encoding="utf-8")


def render_latex(args: argparse.Namespace, assessment: HistoricalAssessment) -> None:
    args.latex_output.parent.mkdir(parents=True, exist_ok=True)
    certificates = assessment.certificates
    current_count = sum(1 for item in certificates if item.current)
    cn_groups = assessment.cn_groups
    repeated_cn_count = sum(1 for values in cn_groups.values() if len(values) > 1)
    same_cn_same_dn = sum(1 for values in cn_groups.values() if len(values) > 1 and len({item.subject_dn for item in values}) == 1)

    lines: list[str] = [
        r"\documentclass[11pt]{article}",
        r"\usepackage[a4paper,margin=18mm]{geometry}",
        r"\usepackage{fontspec}",
        r"\usepackage[table]{xcolor}",
        r"\usepackage{microtype}",
        r"\usepackage{hyperref}",
        r"\usepackage{xurl}",
        r"\usepackage{array}",
        r"\usepackage{booktabs}",
        r"\usepackage{longtable}",
        r"\usepackage{enumitem}",
        r"\usepackage{fancyhdr}",
        r"\usepackage{titlesec}",
        r"\usepackage[most]{tcolorbox}",
        r"\defaultfontfeatures{Ligatures=TeX,Scale=MatchLowercase}",
        r"\setmainfont{Palatino}",
        r"\setsansfont{Avenir Next}",
        r"\setmonofont{Menlo}",
        r"\definecolor{Ink}{HTML}{17202A}",
        r"\definecolor{Line}{HTML}{D0D5DD}",
        r"\definecolor{Panel}{HTML}{F8FAFC}",
        r"\definecolor{Accent}{HTML}{0F766E}",
        r"\hypersetup{colorlinks=true,linkcolor=Accent,urlcolor=Accent,pdfauthor={CertTransparencySearch},pdftitle={Historical Certificate Lineage Analysis}}",
        r"\setlength{\parindent}{0pt}",
        r"\setlength{\parskip}{6pt}",
        r"\setcounter{tocdepth}{2}",
        r"\pagestyle{fancy}",
        r"\fancyhf{}",
        r"\fancyhead[L]{\sffamily\footnotesize Historical Certificate Lineage Analysis}",
        r"\fancyhead[R]{\sffamily\footnotesize \nouppercase{\leftmark}}",
        r"\fancyfoot[C]{\sffamily\footnotesize \thepage}",
        r"\titleformat{\section}{\sffamily\bfseries\LARGE\color{Ink}}{\thesection}{0.8em}{}",
        r"\titleformat{\subsection}{\sffamily\bfseries\Large\color{Ink}}{\thesubsection}{0.8em}{}",
        r"\tcbset{panel/.style={enhanced,breakable,boxrule=0.55pt,arc=3pt,left=9pt,right=9pt,top=8pt,bottom=8pt,colback=white,colframe=Line}}",
        r"\newcommand{\SummaryBox}[1]{\begin{tcolorbox}[panel,colback=Panel]#1\end{tcolorbox}}",
        r"\begin{document}",
        r"\begin{titlepage}",
        r"\vspace*{18mm}",
        r"{\sffamily\bfseries\fontsize{24}{28}\selectfont Historical Certificate Lineage Analysis\par}",
        r"\vspace{8pt}",
        r"{\Large A historical study of Subject CN reuse, subject drift, issuer drift, SAN drift, and issuance bursts\par}",
        r"\vspace{18pt}",
        rf"\textbf{{Generated}}: {ct_scan.latex_escape(ct_scan.utc_iso(datetime.now(UTC)))}\par",
        rf"\textbf{{Configured search terms file}}: {ct_scan.latex_escape(args.domains_file.name)}\par",
        r"\vspace{12pt}",
        r"\SummaryBox{"
        + rf"\textbf{{Headline}}: {len(certificates)} historical leaf certificates, {current_count} currently valid, {len(cn_groups)} Subject CN values, {repeated_cn_count} multi-certificate CN lineages."
        + r"}",
        r"\end{titlepage}",
        r"\tableofcontents",
        r"\clearpage",
    ]

    def add_summary(items: list[str]) -> None:
        lines.append(r"\SummaryBox{\textbf{Management Summary}\begin{itemize}[leftmargin=1.4em]")
        for item in items:
            lines.append(rf"\item {ct_scan.latex_escape(item)}")
        lines.append(r"\end{itemize}}")

    lines.append(r"\section{Executive Summary}")
    add_summary(
        [
            f"Historical unique leaf certificates in scope: {len(certificates)}.",
            f"Currently valid subset inside that historical corpus: {current_count}.",
            f"Distinct Subject CN values: {len(cn_groups)}.",
            f"Subject CN values with more than one certificate over time: {repeated_cn_count}.",
            f"Normal renewal asset lineages with overlap below 50 days: {assessment.normal_reissuance_assets}.",
            f"Current overlap red flags: {len(assessment.overlap_current_rows)}.",
            f"Past-only overlap red flags now fixed: {len(assessment.overlap_past_rows)}.",
        ]
    )
    lines.append(
        r"This report treats Subject CN as a hostname label, not as a unique asset key. The goal is to observe how certificate lineages evolve over time across renewals, issuer changes, SAN changes, and issuance bursts, while separating normal rollover from genuine red flags."
    )

    lines.append(r"\section{Reading Notes}")
    lines.append(r"\begin{itemize}[leftmargin=1.4em]")
    for item in [
        "Subject CN is the hostname placed in the certificate's Common Name field.",
        "Subject DN is the full subject identity string, not just the hostname.",
        "SAN profile means the complete set of SAN entries carried by a certificate.",
        "CA lineage collapses exact issuer names into vendor-level families. Legacy COMODO and Sectigo are treated as one lineage here: Sectigo/COMODO.",
        "A renewal asset lineage means the same Subject CN, same Subject DN, same SAN profile, and same CA lineage reissued over time.",
        "The overlap threshold used here is simple: less than 50 days is normal rollover, 50 days or more is a red flag.",
        "A past-only red flag means it appears historically but no currently valid certificate still carries that same condition.",
    ]:
        lines.append(rf"\item {ct_scan.latex_escape(item)}")
    lines.append(r"\end{itemize}")

    lines.append(r"\section{Renewal Baseline Versus Overlap Red Flags}")
    add_summary(
        [
            f"{repeated_cn_count} of {len(cn_groups)} Subject CN values have more than one certificate across the historical corpus.",
            f"{assessment.repeated_asset_count} renewal asset lineages contain more than one certificate.",
            f"{assessment.normal_reissuance_assets} of those renewal asset lineages stay below the 50-day overlap threshold and fit the normal renewal model.",
            f"{len(assessment.overlap_current_rows)} still have a current overlap red flag.",
            f"{len(assessment.overlap_past_rows)} had an overlap red flag historically, but that issue is not current anymore.",
            f"{same_cn_same_dn} repeated Subject CN values keep the same Subject DN while rotating serial number, validity span, or SAN profile.",
        ]
    )
    lines.append(
        r"The baseline is ordinary certificate rollover: successor and predecessor overlap briefly while deployment is switched over. The red flag is not reissuance itself, but overlap that persists for fifty days or longer for what otherwise looks like the same renewal asset lineage."
    )
    if assessment.overlap_current_rows:
        lines.append(r"\subsection{Current Overlap Red Flags}")
        lines.extend(
            [
                r"\begin{longtable}{>{\raggedright\arraybackslash}p{0.14\linewidth} >{\raggedright\arraybackslash}p{0.12\linewidth} >{\raggedleft\arraybackslash}p{0.07\linewidth} >{\raggedleft\arraybackslash}p{0.06\linewidth} >{\raggedleft\arraybackslash}p{0.08\linewidth} >{\raggedleft\arraybackslash}p{0.08\linewidth} >{\raggedright\arraybackslash}p{0.13\linewidth} >{\raggedright\arraybackslash}p{0.24\linewidth}}",
                r"\toprule",
                r"Subject CN & Lineage & Asset Certs & Current & Max Concurrent & Max Overlap Days & Class & Asset Details \\",
                r"\midrule",
            ]
        )
        for row in assessment.overlap_current_rows[:20]:
            lines.append(
                rf"{ct_scan.latex_escape(row.subject_cn)} & {ct_scan.latex_escape(row.lineage)} & {row.asset_variant_count} & {row.current_certificate_count} & {row.max_concurrent} & {row.max_overlap_days} & {ct_scan.latex_escape(row.overlap_class)} & {ct_scan.latex_escape(row.details)} \\"
            )
        lines.extend([r"\bottomrule", r"\end{longtable}"])
    if assessment.overlap_past_rows:
        lines.append(r"\subsection{Past Overlap Red Flags Now Fixed}")
        lines.extend(
            [
                r"\begin{longtable}{>{\raggedright\arraybackslash}p{0.14\linewidth} >{\raggedright\arraybackslash}p{0.12\linewidth} >{\raggedleft\arraybackslash}p{0.07\linewidth} >{\raggedleft\arraybackslash}p{0.06\linewidth} >{\raggedleft\arraybackslash}p{0.08\linewidth} >{\raggedleft\arraybackslash}p{0.08\linewidth} >{\raggedright\arraybackslash}p{0.13\linewidth} >{\raggedright\arraybackslash}p{0.24\linewidth}}",
                r"\toprule",
                r"Subject CN & Lineage & Asset Certs & Current & Max Concurrent & Max Overlap Days & Class & Asset Details \\",
                r"\midrule",
            ]
        )
        for row in assessment.overlap_past_rows[:20]:
            lines.append(
                rf"{ct_scan.latex_escape(row.subject_cn)} & {ct_scan.latex_escape(row.lineage)} & {row.asset_variant_count} & {row.current_certificate_count} & {row.max_concurrent} & {row.max_overlap_days} & {ct_scan.latex_escape(row.overlap_class)} & {ct_scan.latex_escape(row.details)} \\"
            )
        lines.extend([r"\bottomrule", r"\end{longtable}"])

    lines.append(r"\section{Current Red Flags}")
    add_summary(
        [
            f"Current overlap red flags: {len(assessment.overlap_current_rows)} Subject-CN asset lineages.",
            f"Current Subject DN drift: {len(assessment.dn_current_rows)} Subject CN values.",
            f"Current CA lineage drift: {len(assessment.vendor_current_rows)} Subject CN values.",
            f"Current SAN drift: {len(assessment.san_current_rows)} Subject CN values.",
        ]
    )
    if assessment.current_red_flag_rows:
        lines.extend(
            [
                r"\begin{longtable}{>{\raggedright\arraybackslash}p{0.18\linewidth} >{\raggedleft\arraybackslash}p{0.06\linewidth} >{\raggedleft\arraybackslash}p{0.06\linewidth} >{\raggedleft\arraybackslash}p{0.06\linewidth} >{\raggedright\arraybackslash}p{0.30\linewidth} >{\raggedright\arraybackslash}p{0.26\linewidth}}",
                r"\toprule",
                r"Subject CN & Score & Certs & Current & Flags & Issuer Mix \\",
                r"\midrule",
            ]
        )
        for row in assessment.current_red_flag_rows[:30]:
            lines.append(
                rf"{ct_scan.latex_escape(row.subject_cn)} & {row.score} & {row.certificate_count} & {row.current_certificate_count} & {ct_scan.latex_escape(row.flags)} & {ct_scan.latex_escape(row.notes)} \\"
            )
        lines.extend([r"\bottomrule", r"\end{longtable}"])
    else:
        lines.append(r"No current red flags were found under the configured rules.")

    lines.append(r"\section{Past Red Flags Now Fixed}")
    add_summary(
        [
            f"Past-only overlap red flags now fixed: {len(assessment.overlap_past_rows)} Subject-CN asset lineages.",
            f"Past-only Subject DN drift now fixed: {len(assessment.dn_past_rows)} Subject CN values.",
            f"Past-only CA lineage drift now fixed: {len(assessment.vendor_past_rows)} Subject CN values.",
            f"Past-only SAN drift now fixed: {len(assessment.san_past_rows)} Subject CN values.",
        ]
    )
    if assessment.past_red_flag_rows:
        lines.extend(
            [
                r"\begin{longtable}{>{\raggedright\arraybackslash}p{0.18\linewidth} >{\raggedleft\arraybackslash}p{0.06\linewidth} >{\raggedleft\arraybackslash}p{0.06\linewidth} >{\raggedleft\arraybackslash}p{0.06\linewidth} >{\raggedright\arraybackslash}p{0.30\linewidth} >{\raggedright\arraybackslash}p{0.26\linewidth}}",
                r"\toprule",
                r"Subject CN & Score & Certs & Current & Flags & Issuer Mix \\",
                r"\midrule",
            ]
        )
        for row in assessment.past_red_flag_rows[:30]:
            lines.append(
                rf"{ct_scan.latex_escape(row.subject_cn)} & {row.score} & {row.certificate_count} & {row.current_certificate_count} & {ct_scan.latex_escape(row.flags)} & {ct_scan.latex_escape(row.notes)} \\"
            )
        lines.extend([r"\bottomrule", r"\end{longtable}"])
    else:
        lines.append(r"No historical red flags were found under the configured rules.")

    lines.append(r"\section{Subject DN Drift}")
    add_summary(
        [
            f"Current Subject DN drift: {len(assessment.dn_current_rows)}.",
            f"Past-only Subject DN drift now fixed: {len(assessment.dn_past_rows)}.",
            f"Total Subject CN values with more than one Subject DN across history: {len(assessment.dn_rows)}.",
            "This matters because the hostname stayed the same while the full subject identity string changed.",
            "That is not automatically a security problem, but it is relevant governance drift.",
        ]
    )
    if assessment.dn_current_rows:
        lines.append(r"\subsection{Current Subject DN Drift}")
        lines.extend(
            [
                r"\begin{longtable}{>{\raggedright\arraybackslash}p{0.20\linewidth} >{\raggedleft\arraybackslash}p{0.07\linewidth} >{\raggedleft\arraybackslash}p{0.07\linewidth} >{\raggedleft\arraybackslash}p{0.09\linewidth} >{\raggedright\arraybackslash}p{0.20\linewidth} >{\raggedright\arraybackslash}p{0.29\linewidth}}",
                r"\toprule",
                r"Subject CN & Certs & Current & Distinct Subject DNs & Issuer Families & Subject DN Samples \\",
                r"\midrule",
            ]
        )
        for row in assessment.dn_current_rows[:20]:
            lines.append(
                rf"{ct_scan.latex_escape(row.subject_cn)} & {row.certificate_count} & {row.current_certificate_count} & {row.distinct_value_count} & {ct_scan.latex_escape(row.issuer_families)} & {ct_scan.latex_escape(row.details)} \\"
            )
        lines.extend([r"\bottomrule", r"\end{longtable}"])
    if assessment.dn_past_rows:
        lines.append(r"\subsection{Past Subject DN Drift Now Fixed}")
        lines.extend(
            [
                r"\begin{longtable}{>{\raggedright\arraybackslash}p{0.20\linewidth} >{\raggedleft\arraybackslash}p{0.07\linewidth} >{\raggedleft\arraybackslash}p{0.07\linewidth} >{\raggedleft\arraybackslash}p{0.09\linewidth} >{\raggedright\arraybackslash}p{0.20\linewidth} >{\raggedright\arraybackslash}p{0.29\linewidth}}",
                r"\toprule",
                r"Subject CN & Certs & Current & Distinct Subject DNs & Issuer Families & Subject DN Samples \\",
                r"\midrule",
            ]
        )
        for row in assessment.dn_past_rows[:20]:
            lines.append(
                rf"{ct_scan.latex_escape(row.subject_cn)} & {row.certificate_count} & {row.current_certificate_count} & {row.distinct_value_count} & {ct_scan.latex_escape(row.issuer_families)} & {ct_scan.latex_escape(row.details)} \\"
            )
        lines.extend([r"\bottomrule", r"\end{longtable}"])
    if not assessment.dn_rows:
        lines.append(r"No cases were found.")

    lines.append(r"\section{CA Lineage Drift}")
    add_summary(
        [
            f"Exact issuer-name changes across history: {len(assessment.issuer_rows)} Subject CN values.",
            f"Current CA lineage drift: {len(assessment.vendor_current_rows)} Subject CN values.",
            f"Past-only CA lineage drift now fixed: {len(assessment.vendor_past_rows)} Subject CN values.",
            "Exact issuer changes inside one lineage can be operationally normal. CA lineage drift is the stronger signal, with COMODO and Sectigo deliberately collapsed into one lineage.",
        ]
    )
    if assessment.vendor_current_rows:
        lines.append(r"\subsection{Current CA Lineage Drift}")
        lines.extend(
            [
                r"\begin{longtable}{>{\raggedright\arraybackslash}p{0.20\linewidth} >{\raggedleft\arraybackslash}p{0.07\linewidth} >{\raggedleft\arraybackslash}p{0.07\linewidth} >{\raggedleft\arraybackslash}p{0.08\linewidth} >{\raggedright\arraybackslash}p{0.18\linewidth} >{\raggedright\arraybackslash}p{0.32\linewidth}}",
                r"\toprule",
                r"Subject CN & Certs & Current & Distinct Lineages & Lineage Mix & Lineages Seen \\",
                r"\midrule",
            ]
        )
        for row in assessment.vendor_current_rows[:20]:
            lines.append(
                rf"{ct_scan.latex_escape(row.subject_cn)} & {row.certificate_count} & {row.current_certificate_count} & {row.distinct_value_count} & {ct_scan.latex_escape(row.issuer_families)} & {ct_scan.latex_escape(row.details)} \\"
            )
        lines.extend([r"\bottomrule", r"\end{longtable}"])
    if assessment.vendor_past_rows:
        lines.append(r"\subsection{Past CA Lineage Drift Now Fixed}")
        lines.extend(
            [
                r"\begin{longtable}{>{\raggedright\arraybackslash}p{0.20\linewidth} >{\raggedleft\arraybackslash}p{0.07\linewidth} >{\raggedleft\arraybackslash}p{0.07\linewidth} >{\raggedleft\arraybackslash}p{0.08\linewidth} >{\raggedright\arraybackslash}p{0.18\linewidth} >{\raggedright\arraybackslash}p{0.32\linewidth}}",
                r"\toprule",
                r"Subject CN & Certs & Current & Distinct Lineages & Lineage Mix & Lineages Seen \\",
                r"\midrule",
            ]
        )
        for row in assessment.vendor_past_rows[:20]:
            lines.append(
                rf"{ct_scan.latex_escape(row.subject_cn)} & {row.certificate_count} & {row.current_certificate_count} & {row.distinct_value_count} & {ct_scan.latex_escape(row.issuer_families)} & {ct_scan.latex_escape(row.details)} \\"
            )
        lines.extend([r"\bottomrule", r"\end{longtable}"])
    if assessment.issuer_rows:
        lines.append(r"\subsection{Exact Issuer Changes Inside The Same Or Different Lineages}")
        lines.extend(
            [
                r"\begin{longtable}{>{\raggedright\arraybackslash}p{0.20\linewidth} >{\raggedleft\arraybackslash}p{0.07\linewidth} >{\raggedleft\arraybackslash}p{0.07\linewidth} >{\raggedleft\arraybackslash}p{0.08\linewidth} >{\raggedright\arraybackslash}p{0.18\linewidth} >{\raggedright\arraybackslash}p{0.32\linewidth}}",
                r"\toprule",
                r"Subject CN & Certs & Current & Distinct Issuers & Lineage Mix & Issuer Samples \\",
                r"\midrule",
            ]
        )
        for row in assessment.issuer_rows[:20]:
            lines.append(
                rf"{ct_scan.latex_escape(row.subject_cn)} & {row.certificate_count} & {row.current_certificate_count} & {row.distinct_value_count} & {ct_scan.latex_escape(row.issuer_families)} & {ct_scan.latex_escape(row.details)} \\"
            )
        lines.extend([r"\bottomrule", r"\end{longtable}"])

    lines.append(r"\section{SAN Profile Drift}")
    add_summary(
        [
            f"Current SAN drift: {len(assessment.san_current_rows)} Subject CN values.",
            f"Past-only SAN drift now fixed: {len(assessment.san_past_rows)} Subject CN values.",
            f"Total Subject CN values with more than one SAN profile across history: {len(assessment.san_rows)}.",
            f"Top SAN-delta pattern classes: {', '.join(f'{name} ({count})' for name, count in assessment.san_pattern_counts.most_common()) or 'none'}.",
            "This reveals whether the endpoint surface under the same hostname stayed stable or changed shape over time.",
        ]
    )
    if assessment.san_current_rows:
        lines.append(r"\subsection{Current SAN Drift}")
        lines.extend(
            [
                r"\begin{longtable}{>{\raggedright\arraybackslash}p{0.16\linewidth} >{\raggedleft\arraybackslash}p{0.06\linewidth} >{\raggedleft\arraybackslash}p{0.06\linewidth} >{\raggedleft\arraybackslash}p{0.07\linewidth} >{\raggedleft\arraybackslash}p{0.07\linewidth} >{\raggedleft\arraybackslash}p{0.07\linewidth} >{\raggedright\arraybackslash}p{0.18\linewidth} >{\raggedright\arraybackslash}p{0.25\linewidth}}",
                r"\toprule",
                r"Subject CN & Certs & Current & Profiles & Stable & Variable & Delta Pattern & Representative Delta \\",
                r"\midrule",
            ]
        )
        for row in assessment.san_current_rows[:20]:
            lines.append(
                rf"{ct_scan.latex_escape(row.subject_cn)} & {row.certificate_count} & {row.current_certificate_count} & {row.distinct_san_profiles} & {row.stable_entries} & {row.variable_entries} & {ct_scan.latex_escape(row.delta_pattern)} & {ct_scan.latex_escape(row.representative_delta)} \\"
            )
        lines.extend([r"\bottomrule", r"\end{longtable}"])
    if assessment.san_past_rows:
        lines.append(r"\subsection{Past SAN Drift Now Fixed}")
        lines.extend(
            [
                r"\begin{longtable}{>{\raggedright\arraybackslash}p{0.16\linewidth} >{\raggedleft\arraybackslash}p{0.06\linewidth} >{\raggedleft\arraybackslash}p{0.06\linewidth} >{\raggedleft\arraybackslash}p{0.07\linewidth} >{\raggedleft\arraybackslash}p{0.07\linewidth} >{\raggedleft\arraybackslash}p{0.07\linewidth} >{\raggedright\arraybackslash}p{0.18\linewidth} >{\raggedright\arraybackslash}p{0.25\linewidth}}",
                r"\toprule",
                r"Subject CN & Certs & Current & Profiles & Stable & Variable & Delta Pattern & Representative Delta \\",
                r"\midrule",
            ]
        )
        for row in assessment.san_past_rows[:20]:
            lines.append(
                rf"{ct_scan.latex_escape(row.subject_cn)} & {row.certificate_count} & {row.current_certificate_count} & {row.distinct_san_profiles} & {row.stable_entries} & {row.variable_entries} & {ct_scan.latex_escape(row.delta_pattern)} & {ct_scan.latex_escape(row.representative_delta)} \\"
            )
        lines.extend([r"\bottomrule", r"\end{longtable}"])

    lines.append(r"\section{Historic Issuance Bursts And Step Changes}")
    add_summary(
        [
            "This chapter includes expired certificates on purpose, because issuance bursts are historical phenomena rather than current-only phenomena.",
            f"Top issuance start dates are {', '.join(f'{row.start_day} ({row.certificate_count})' for row in assessment.day_rows[:6])}.",
            "Strong same-day or same-week bursts usually indicate planned renewal waves, platform migrations, or bulk onboarding of service families.",
        ]
    )
    lines.append(r"\subsection{Top Start Dates}")
    lines.extend(
        [
            r"\begin{longtable}{>{\raggedright\arraybackslash}p{0.13\linewidth} >{\raggedleft\arraybackslash}p{0.09\linewidth} >{\raggedright\arraybackslash}p{0.43\linewidth} >{\raggedright\arraybackslash}p{0.27\linewidth}}",
            r"\toprule",
            r"Start Day & Certificates & Top Subject CNs & Top Issuer Families \\",
            r"\midrule",
        ]
    )
    for row in assessment.day_rows:
        lines.append(
            rf"{ct_scan.latex_escape(row.start_day)} & {row.certificate_count} & {ct_scan.latex_escape(row.top_subjects)} & {ct_scan.latex_escape(row.top_issuers)} \\"
        )
    lines.extend([r"\bottomrule", r"\end{longtable}"])
    lines.append(r"\subsection{Step Weeks}")
    if assessment.week_rows:
        lines.extend(
            [
                r"\begin{longtable}{>{\raggedright\arraybackslash}p{0.13\linewidth} >{\raggedleft\arraybackslash}p{0.08\linewidth} >{\raggedleft\arraybackslash}p{0.10\linewidth} >{\raggedright\arraybackslash}p{0.35\linewidth} >{\raggedright\arraybackslash}p{0.24\linewidth}}",
                r"\toprule",
                r"Week Start & Certs & Prior 8-Week Avg & Top Subject CNs & Top Issuer Families \\",
                r"\midrule",
            ]
        )
        for row in assessment.week_rows[:20]:
            lines.append(
                rf"{ct_scan.latex_escape(row.week_start)} & {row.certificate_count} & {ct_scan.latex_escape(row.prior_eight_week_avg)} & {ct_scan.latex_escape(row.top_subjects)} & {ct_scan.latex_escape(row.top_issuers)} \\"
            )
        lines.extend([r"\bottomrule", r"\end{longtable}"])
    else:
        lines.append(r"No step weeks met the configured threshold.")

    lines.append(r"\section{Interpretation}")
    lines.append(
        r"The public certificate view is not just a static inventory. It is a change log. The normal case is rollover inside a stable renewal asset lineage with less than fifty days of overlap. The red flags are the exceptions layered on top of that baseline: overlap of fifty days or more, Subject DN drift, CA lineage drift, and SAN drift. The current-versus-past split matters because it separates live governance concerns from issues that appear to have been corrected already."
    )
    lines.extend([r"\end{document}"])
    args.latex_output.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    assessment = build_assessment(args)
    render_markdown(args, assessment)
    render_latex(args, assessment)
    if not args.skip_pdf:
        ct_scan.compile_latex_to_pdf(args.latex_output, args.pdf_output, args.pdf_engine)
    if not args.quiet:
        print(
            f"[report] historical_leaf={len(assessment.certificates)} markdown={args.markdown_output} latex={args.latex_output}"
            + ("" if args.skip_pdf else f" pdf={args.pdf_output}"),
            file=__import__("sys").stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
