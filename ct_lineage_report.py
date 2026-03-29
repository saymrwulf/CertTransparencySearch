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
    0 AS revoked_count,
    NULL::timestamp AS revocation_date,
    NULL::integer AS reason_code,
    NULL::timestamp AS last_seen_check_date,
    0 AS active_crl_count,
    NULL::timestamp AS crl_last_checked,
    ci.certificate
FROM ci
JOIN ca ON ca.id = ci.issuer_ca_id
JOIN certificate_lifecycle cl ON cl.certificate_id = ci.id
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
    san_entries: list[str]
    first_seen: datetime | None
    current: bool
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyse historical certificate lineage, CN reuse, issuer drift, SAN drift, and issuance bursts."
    )
    parser.add_argument("--domains-file", type=Path, default=Path("domains.local.txt"))
    parser.add_argument("--cache-dir", type=Path, default=Path(".cache/ct-history"))
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
    if "sectigo" in lowered:
        return "Sectigo"
    if "comodo" in lowered:
        return "COMODO"
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
    with ct_scan.connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(HISTORICAL_QUERY_SQL, params)
        rows = cur.fetchall()
    return [ct_scan.row_to_record(domain, row) for row in rows]


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
            hit = HistoricalCertificate(
                fingerprint_sha256=fingerprint_sha256,
                subject_cn=subject_cn,
                subject_dn=cert.subject.rfc4514_string(),
                issuer_name=record.issuer_name,
                issuer_family=short_issuer(record.issuer_name),
                validity_not_before=record.not_before,
                validity_not_after=record.not_after,
                san_entries=ct_scan.extract_san_entries(cert),
                first_seen=record.first_seen,
                current=record.not_before <= now <= record.not_after,
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


def render_markdown(
    args: argparse.Namespace,
    domains: list[str],
    certificates: list[HistoricalCertificate],
    dn_rows: list[CnCollisionRow],
    issuer_rows: list[CnCollisionRow],
    vendor_rows: list[CnCollisionRow],
    san_rows: list[SanChangeRow],
    san_pattern_counts: Counter[str],
    day_rows: list[StartDayRow],
    week_rows: list[StepWeekRow],
) -> None:
    args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
    current_count = sum(1 for item in certificates if item.current)
    cn_groups = group_by_subject_cn(certificates)
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
            f"- Same Subject CN with different Subject DN: **{len(dn_rows)}**.",
            f"- Same Subject CN with different exact issuer names: **{len(issuer_rows)}**.",
            f"- Same Subject CN with different issuer families or vendors: **{len(vendor_rows)}**.",
            f"- Same Subject CN with different SAN profiles: **{len(san_rows)}**.",
        ]
    )
    lines.append("")
    lines.append("This report treats Subject CN as a hostname label, not as a unique asset key. The point is to follow certificate lineage through renewals, issuer changes, SAN changes, and issuance bursts across both current and expired certificates.")
    lines.append("")
    lines.append("## Reading Notes")
    lines.append("")
    lines.extend(
        [
            "- **Subject CN** is the hostname placed in the certificate's Common Name field.",
            "- **Subject DN** is the full subject identity string, not just the hostname.",
            "- **SAN profile** means the complete set of SAN entries carried by a certificate.",
            "- **Issuer family** collapses exact issuer names into vendor-level families such as Amazon, Sectigo, COMODO, and Google Trust Services.",
        ]
    )
    lines.append("")
    lines.append("## Chapter 1: Reissuance Is The Rule, Not The Exception")
    lines.append("")
    lines.append("**Management Summary**")
    lines.append("")
    lines.extend(
        [
            f"- {repeated_cn_count} of {len(cn_groups)} Subject CN values have more than one certificate across the historical corpus.",
            f"- {same_cn_same_dn} repeated Subject CN values keep the same Subject DN while rotating serial number, validity span, or SAN profile.",
            "- That means Subject CN does not behave like a singleton asset key. It behaves more like a service label under which certificates are renewed and sometimes reshaped.",
        ]
    )
    lines.append("")
    lines.append("This is the baseline that matters before any anomaly analysis. Most service names are not single certificates frozen in time. They are lineages of certificates issued, renewed, and sometimes restructured under the same public hostname.")
    lines.append("")
    lines.append("## Chapter 2: Same Subject CN, Different Subject DN")
    lines.append("")
    lines.append("**Management Summary**")
    lines.append("")
    lines.extend(
        [
            f"- Subject CN values with more than one Subject DN: {len(dn_rows)}.",
            "- This is relevant because it means the hostname stayed the same while the full subject identity string changed.",
            "- That does not automatically imply a security problem, but it is exactly the kind of drift that deserves review when you care about ownership, issuance policy, or certificate governance.",
        ]
    )
    lines.append("")
    if dn_rows:
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
                    for row in dn_rows[:20]
                ],
            )
        )
        lines.append("")
    else:
        lines.append("No cases were found.")
        lines.append("")
    lines.append("## Chapter 3: Same Subject CN, Different Issuing CA")
    lines.append("")
    lines.append("**Management Summary**")
    lines.append("")
    lines.extend(
        [
            f"- Subject CN values with more than one exact issuer name: {len(issuer_rows)}.",
            f"- Subject CN values spanning more than one issuer family or vendor: {len(vendor_rows)}.",
            "- This reveals whether the same service name moved between CA products, CA lineages, or cloud-managed issuance stacks over time.",
        ]
    )
    lines.append("")
    if issuer_rows:
        lines.append("### Exact Issuer Changes")
        lines.append("")
        lines.extend(
            md_table(
                ["Subject CN", "Certs", "Current", "Distinct Issuers", "Issuer Families", "Issuer Samples"],
                [
                    [
                        row.subject_cn,
                        str(row.certificate_count),
                        str(row.current_certificate_count),
                        str(row.distinct_value_count),
                        row.issuer_families,
                        row.details,
                    ]
                    for row in issuer_rows[:20]
                ],
            )
        )
        lines.append("")
    if vendor_rows:
        lines.append("### Vendor-Level Changes")
        lines.append("")
        lines.extend(
            md_table(
                ["Subject CN", "Certs", "Current", "Distinct Vendors", "Vendor Mix", "Vendors Seen"],
                [
                    [
                        row.subject_cn,
                        str(row.certificate_count),
                        str(row.current_certificate_count),
                        str(row.distinct_value_count),
                        row.issuer_families,
                        row.details,
                    ]
                    for row in vendor_rows[:20]
                ],
            )
        )
        lines.append("")
    lines.append("## Chapter 4: Same Subject CN, Different SAN Profiles")
    lines.append("")
    lines.append("**Management Summary**")
    lines.append("")
    lines.extend(
        [
            f"- Subject CN values with more than one distinct SAN profile: {len(san_rows)}.",
            f"- Top SAN-delta pattern classes: {', '.join(f'{name} ({count})' for name, count in san_pattern_counts.most_common()) or 'none'}.",
            "- This shows whether the service name stayed stable while the covered endpoint set expanded, contracted, or shifted shape.",
        ]
    )
    lines.append("")
    if san_rows:
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
                    for row in san_rows[:30]
                ],
            )
        )
        lines.append("")
    lines.append("## Chapter 5: Historic Issuance Bursts And Step Changes")
    lines.append("")
    lines.append("**Management Summary**")
    lines.append("")
    lines.extend(
        [
            "- This chapter includes expired certificates on purpose, because step changes are historical phenomena rather than current-only phenomena.",
            "- Strong same-day or same-week issuance bursts usually signal planned renewal waves, platform migrations, or bulk onboarding of service families.",
            f"- Top issuance start dates: {', '.join(f'{row.start_day} ({row.certificate_count})' for row in day_rows[:6])}.",
        ]
    )
    lines.append("")
    lines.append("### Top Start Dates")
    lines.append("")
    lines.extend(
        md_table(
            ["Start Day", "Certificates", "Top Subject CNs", "Top Issuer Families"],
            [[row.start_day, str(row.certificate_count), row.top_subjects, row.top_issuers] for row in day_rows],
        )
    )
    lines.append("")
    lines.append("### Step Weeks")
    lines.append("")
    if week_rows:
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
                    for row in week_rows[:20]
                ],
            )
        )
        lines.append("")
    else:
        lines.append("No step weeks met the configured threshold.")
        lines.append("")
    lines.append("## Chapter 6: Interpretation")
    lines.append("")
    lines.append("The main operational picture is not one of single certificates mapped one-to-one to service names. It is a layered certificate lineage model. Some Subject CN values are stable and renewed under the same subject identity. Others migrate across issuer families, reshape their SAN surface, or move in bulk issuance campaigns. That matters because the public certificate view is not just a static inventory. It is a change log of service ownership, CA strategy, and platform rollout over time.")
    lines.append("")
    args.markdown_output.write_text("\n".join(lines) + "\n", encoding="utf-8")


def render_latex(
    args: argparse.Namespace,
    domains: list[str],
    certificates: list[HistoricalCertificate],
    dn_rows: list[CnCollisionRow],
    issuer_rows: list[CnCollisionRow],
    vendor_rows: list[CnCollisionRow],
    san_rows: list[SanChangeRow],
    san_pattern_counts: Counter[str],
    day_rows: list[StartDayRow],
    week_rows: list[StepWeekRow],
) -> None:
    args.latex_output.parent.mkdir(parents=True, exist_ok=True)
    current_count = sum(1 for item in certificates if item.current)
    cn_groups = group_by_subject_cn(certificates)
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
        ]
    )
    lines.append(
        r"This report treats Subject CN as a hostname label, not as a unique asset key. The goal is to observe how certificate lineages evolve over time across renewals, issuer changes, SAN changes, and issuance bursts."
    )

    lines.append(r"\section{Reading Notes}")
    lines.append(r"\begin{itemize}[leftmargin=1.4em]")
    for item in [
        "Subject CN is the hostname placed in the certificate's Common Name field.",
        "Subject DN is the full subject identity string, not just the hostname.",
        "SAN profile means the complete set of SAN entries carried by a certificate.",
        "Issuer family collapses exact issuer names into vendor-level families such as Amazon, Sectigo, COMODO, and Google Trust Services.",
    ]:
        lines.append(rf"\item {ct_scan.latex_escape(item)}")
    lines.append(r"\end{itemize}")

    lines.append(r"\section{Reissuance Is The Rule, Not The Exception}")
    add_summary(
        [
            f"{repeated_cn_count} of {len(cn_groups)} Subject CN values have more than one certificate across the historical corpus.",
            f"{same_cn_same_dn} repeated Subject CN values keep the same Subject DN while rotating serial number, validity span, or SAN profile.",
            "Subject CN behaves more like a service label than a singleton certificate asset key.",
        ]
    )

    lines.append(r"\section{Same Subject CN, Different Subject DN}")
    add_summary(
        [
            f"Subject CN values with more than one Subject DN: {len(dn_rows)}.",
            "This matters because the hostname stayed the same while the full subject identity string changed.",
            "That is not automatically a security problem, but it is relevant governance drift.",
        ]
    )
    if dn_rows:
        lines.extend(
            [
                r"\begin{longtable}{>{\raggedright\arraybackslash}p{0.20\linewidth} >{\raggedleft\arraybackslash}p{0.07\linewidth} >{\raggedleft\arraybackslash}p{0.07\linewidth} >{\raggedleft\arraybackslash}p{0.09\linewidth} >{\raggedright\arraybackslash}p{0.20\linewidth} >{\raggedright\arraybackslash}p{0.29\linewidth}}",
                r"\toprule",
                r"Subject CN & Certs & Current & Distinct Subject DNs & Issuer Families & Subject DN Samples \\",
                r"\midrule",
            ]
        )
        for row in dn_rows[:20]:
            lines.append(
                rf"{ct_scan.latex_escape(row.subject_cn)} & {row.certificate_count} & {row.current_certificate_count} & {row.distinct_value_count} & {ct_scan.latex_escape(row.issuer_families)} & {ct_scan.latex_escape(row.details)} \\"
            )
        lines.extend([r"\bottomrule", r"\end{longtable}"])
    else:
        lines.append(r"No cases were found.")

    lines.append(r"\section{Same Subject CN, Different Issuing CA}")
    add_summary(
        [
            f"Subject CN values with more than one exact issuer name: {len(issuer_rows)}.",
            f"Subject CN values spanning more than one issuer family or vendor: {len(vendor_rows)}.",
            "This reveals hostname continuity across CA product changes or vendor changes.",
        ]
    )
    if issuer_rows:
        lines.append(r"\subsection{Exact Issuer Changes}")
        lines.extend(
            [
                r"\begin{longtable}{>{\raggedright\arraybackslash}p{0.20\linewidth} >{\raggedleft\arraybackslash}p{0.07\linewidth} >{\raggedleft\arraybackslash}p{0.07\linewidth} >{\raggedleft\arraybackslash}p{0.08\linewidth} >{\raggedright\arraybackslash}p{0.18\linewidth} >{\raggedright\arraybackslash}p{0.32\linewidth}}",
                r"\toprule",
                r"Subject CN & Certs & Current & Distinct Issuers & Issuer Families & Issuer Samples \\",
                r"\midrule",
            ]
        )
        for row in issuer_rows[:20]:
            lines.append(
                rf"{ct_scan.latex_escape(row.subject_cn)} & {row.certificate_count} & {row.current_certificate_count} & {row.distinct_value_count} & {ct_scan.latex_escape(row.issuer_families)} & {ct_scan.latex_escape(row.details)} \\"
            )
        lines.extend([r"\bottomrule", r"\end{longtable}"])
    if vendor_rows:
        lines.append(r"\subsection{Vendor-Level Changes}")
        lines.extend(
            [
                r"\begin{longtable}{>{\raggedright\arraybackslash}p{0.20\linewidth} >{\raggedleft\arraybackslash}p{0.07\linewidth} >{\raggedleft\arraybackslash}p{0.07\linewidth} >{\raggedleft\arraybackslash}p{0.08\linewidth} >{\raggedright\arraybackslash}p{0.18\linewidth} >{\raggedright\arraybackslash}p{0.32\linewidth}}",
                r"\toprule",
                r"Subject CN & Certs & Current & Distinct Vendors & Vendor Mix & Vendors Seen \\",
                r"\midrule",
            ]
        )
        for row in vendor_rows[:20]:
            lines.append(
                rf"{ct_scan.latex_escape(row.subject_cn)} & {row.certificate_count} & {row.current_certificate_count} & {row.distinct_value_count} & {ct_scan.latex_escape(row.issuer_families)} & {ct_scan.latex_escape(row.details)} \\"
            )
        lines.extend([r"\bottomrule", r"\end{longtable}"])

    lines.append(r"\section{Same Subject CN, Different SAN Profiles}")
    add_summary(
        [
            f"Subject CN values with more than one SAN profile: {len(san_rows)}.",
            f"Top SAN-delta pattern classes: {', '.join(f'{name} ({count})' for name, count in san_pattern_counts.most_common()) or 'none'}.",
            "This reveals whether the endpoint surface under the same hostname stayed stable or changed shape over time.",
        ]
    )
    if san_rows:
        lines.extend(
            [
                r"\begin{longtable}{>{\raggedright\arraybackslash}p{0.16\linewidth} >{\raggedleft\arraybackslash}p{0.06\linewidth} >{\raggedleft\arraybackslash}p{0.06\linewidth} >{\raggedleft\arraybackslash}p{0.07\linewidth} >{\raggedleft\arraybackslash}p{0.07\linewidth} >{\raggedleft\arraybackslash}p{0.07\linewidth} >{\raggedright\arraybackslash}p{0.18\linewidth} >{\raggedright\arraybackslash}p{0.25\linewidth}}",
                r"\toprule",
                r"Subject CN & Certs & Current & Profiles & Stable & Variable & Delta Pattern & Representative Delta \\",
                r"\midrule",
            ]
        )
        for row in san_rows[:30]:
            lines.append(
                rf"{ct_scan.latex_escape(row.subject_cn)} & {row.certificate_count} & {row.current_certificate_count} & {row.distinct_san_profiles} & {row.stable_entries} & {row.variable_entries} & {ct_scan.latex_escape(row.delta_pattern)} & {ct_scan.latex_escape(row.representative_delta)} \\"
            )
        lines.extend([r"\bottomrule", r"\end{longtable}"])

    lines.append(r"\section{Historic Issuance Bursts And Step Changes}")
    add_summary(
        [
            "This chapter includes expired certificates on purpose, because issuance bursts are historical phenomena rather than current-only phenomena.",
            f"Top issuance start dates are {', '.join(f'{row.start_day} ({row.certificate_count})' for row in day_rows[:6])}.",
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
    for row in day_rows:
        lines.append(
            rf"{ct_scan.latex_escape(row.start_day)} & {row.certificate_count} & {ct_scan.latex_escape(row.top_subjects)} & {ct_scan.latex_escape(row.top_issuers)} \\"
        )
    lines.extend([r"\bottomrule", r"\end{longtable}"])
    lines.append(r"\subsection{Step Weeks}")
    if week_rows:
        lines.extend(
            [
                r"\begin{longtable}{>{\raggedright\arraybackslash}p{0.13\linewidth} >{\raggedleft\arraybackslash}p{0.08\linewidth} >{\raggedleft\arraybackslash}p{0.10\linewidth} >{\raggedright\arraybackslash}p{0.35\linewidth} >{\raggedright\arraybackslash}p{0.24\linewidth}}",
                r"\toprule",
                r"Week Start & Certs & Prior 8-Week Avg & Top Subject CNs & Top Issuer Families \\",
                r"\midrule",
            ]
        )
        for row in week_rows[:20]:
            lines.append(
                rf"{ct_scan.latex_escape(row.week_start)} & {row.certificate_count} & {ct_scan.latex_escape(row.prior_eight_week_avg)} & {ct_scan.latex_escape(row.top_subjects)} & {ct_scan.latex_escape(row.top_issuers)} \\"
            )
        lines.extend([r"\bottomrule", r"\end{longtable}"])
    else:
        lines.append(r"No step weeks met the configured threshold.")

    lines.append(r"\section{Interpretation}")
    lines.append(
        r"The public certificate view is not just a static inventory. It is a change log. Stable Subject CN values can sit on top of several successive certificates, several SAN shapes, and sometimes several issuer families. That matters because the observable certificate surface reflects renewal operations, migration waves, and platform strategy over time."
    )
    lines.extend([r"\end{document}"])
    args.latex_output.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    domains, records = load_records(args)
    certificates = build_certificates(records)
    cn_groups = group_by_subject_cn(certificates)
    dn_rows = dn_change_rows(cn_groups)
    issuer_rows, vendor_rows = issuer_change_rows(cn_groups)
    san_rows, san_pattern_counts = san_change_rows(cn_groups)
    day_rows = top_start_days(certificates)
    week_rows = spike_weeks(certificates)
    render_markdown(
        args,
        domains,
        certificates,
        dn_rows,
        issuer_rows,
        vendor_rows,
        san_rows,
        san_pattern_counts,
        day_rows,
        week_rows,
    )
    render_latex(
        args,
        domains,
        certificates,
        dn_rows,
        issuer_rows,
        vendor_rows,
        san_rows,
        san_pattern_counts,
        day_rows,
        week_rows,
    )
    if not args.skip_pdf:
        ct_scan.compile_latex_to_pdf(args.latex_output, args.pdf_output, args.pdf_engine)
    if not args.quiet:
        print(
            f"[report] historical_leaf={len(certificates)} markdown={args.markdown_output} latex={args.latex_output}"
            + ("" if args.skip_pdf else f" pdf={args.pdf_output}"),
            file=__import__("sys").stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
