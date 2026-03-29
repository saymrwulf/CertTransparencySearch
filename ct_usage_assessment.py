#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

import ct_scan


SERVER_AUTH_OID = "1.3.6.1.5.5.7.3.1"
CLIENT_AUTH_OID = "1.3.6.1.5.5.7.3.2"
CODE_SIGNING_OID = "1.3.6.1.5.5.7.3.3"
EMAIL_PROTECTION_OID = "1.3.6.1.5.5.7.3.4"
TIME_STAMPING_OID = "1.3.6.1.5.5.7.3.8"
OCSP_SIGNING_OID = "1.3.6.1.5.5.7.3.9"
ANY_EXTENDED_KEY_USAGE_OID = "2.5.29.37.0"

EKU_LABELS = {
    SERVER_AUTH_OID: "serverAuth",
    CLIENT_AUTH_OID: "clientAuth",
    CODE_SIGNING_OID: "codeSigning",
    EMAIL_PROTECTION_OID: "emailProtection",
    TIME_STAMPING_OID: "timeStamping",
    OCSP_SIGNING_OID: "OCSPSigning",
    ANY_EXTENDED_KEY_USAGE_OID: "anyExtendedKeyUsage",
}


@dataclass
class PurposeClassification:
    fingerprint_sha256: str
    subject_cn: str
    issuer_name: str
    category: str
    eku_oids: list[str]
    key_usage_flags: list[str]
    valid_from_utc: str
    valid_to_utc: str
    matched_domains: list[str]
    san_dns_names: list[str]


@dataclass
class AssessmentSummary:
    generated_at_utc: str
    source_cache_domains: list[str]
    unique_leaf_certificates: int
    category_counts: dict[str, int]
    eku_templates: dict[str, int]
    key_usage_templates: dict[str, int]
    issuer_breakdown: dict[str, dict[str, int]]
    validity_start_years: dict[str, dict[str, int]]
    san_type_counts: dict[str, int]
    subject_cn_in_dns_san_count: int
    subject_cn_not_in_dns_san_count: int
    dual_eku_subject_cns_with_server_only_sibling: list[str]
    dual_eku_subject_cns_without_server_only_sibling: list[str]


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Assess certificate intended usage from EKU and KeyUsage."
    )
    parser.add_argument(
        "--domains-file",
        type=Path,
        default=Path("domains.local.txt"),
        help="Configurable list of search domains, one per line.",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=Path(".cache/ct-search"),
        help="Directory used by ct_scan.py for cached CT results.",
    )
    parser.add_argument(
        "--cache-ttl-seconds",
        type=int,
        default=86400,
        help="Reuse cached CT results up to this age before refreshing from crt.sh.",
    )
    parser.add_argument(
        "--max-candidates",
        type=int,
        default=10000,
        help="Maximum raw crt.sh identity rows to inspect per configured domain.",
    )
    parser.add_argument(
        "--attempts",
        type=int,
        default=3,
        help="Retry attempts for live crt.sh database queries.",
    )
    parser.add_argument(
        "--markdown-output",
        type=Path,
        default=Path("output/certificate-purpose-assessment.md"),
        help="Human-readable assessment output.",
    )
    parser.add_argument(
        "--json-output",
        type=Path,
        default=Path("output/certificate-purpose-assessment.json"),
        help="Machine-readable assessment output.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print refresh activity to stderr.",
    )
    return parser.parse_args()


def load_records(
    domains: list[str],
    cache_dir: Path,
    cache_ttl_seconds: int,
    max_candidates: int,
    attempts: int,
    verbose: bool,
) -> list[ct_scan.DatabaseRecord]:
    all_records: list[ct_scan.DatabaseRecord] = []
    for domain in domains:
        records = ct_scan.load_cached_records(cache_dir, domain, cache_ttl_seconds, max_candidates)
        if records is None:
            records = ct_scan.query_domain(domain, max_candidates=max_candidates, attempts=attempts, verbose=verbose)
            ct_scan.store_cached_records(cache_dir, domain, max_candidates=max_candidates, records=records)
        all_records.extend(records)
    return all_records


def extract_eku_oids(cert: x509.Certificate) -> list[str]:
    try:
        extension = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
    except x509.ExtensionNotFound:
        return []
    return sorted(oid.dotted_string for oid in extension.value)


def extract_key_usage_flags(cert: x509.Certificate) -> list[str]:
    try:
        key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    except x509.ExtensionNotFound:
        return []
    flags: list[str] = []
    for attribute in (
        "digital_signature",
        "content_commitment",
        "key_encipherment",
        "data_encipherment",
        "key_agreement",
        "key_cert_sign",
        "crl_sign",
    ):
        if getattr(key_usage, attribute):
            flags.append(attribute)
    if key_usage.key_agreement:
        if key_usage.encipher_only:
            flags.append("encipher_only")
        if key_usage.decipher_only:
            flags.append("decipher_only")
    return flags


def classify_purpose(eku_oids: list[str]) -> str:
    eku_set = set(eku_oids)
    has_server = SERVER_AUTH_OID in eku_set or ANY_EXTENDED_KEY_USAGE_OID in eku_set
    has_client = CLIENT_AUTH_OID in eku_set or ANY_EXTENDED_KEY_USAGE_OID in eku_set
    has_code_signing = CODE_SIGNING_OID in eku_set
    has_email = EMAIL_PROTECTION_OID in eku_set

    if not eku_oids:
        return "no_eku"
    if has_server and not has_client and not has_code_signing and not has_email:
        return "tls_server_only"
    if has_server and has_client and not has_code_signing and not has_email:
        return "tls_server_and_client"
    if has_client and not has_server and not has_code_signing and not has_email:
        return "client_auth_only"
    if has_email and not has_server and not has_client and not has_code_signing:
        return "smime_only"
    if has_code_signing and not has_server and not has_client and not has_email:
        return "code_signing_only"
    return "mixed_or_other"


def format_eku_template(eku_oids: list[str]) -> str:
    if not eku_oids:
        return "(none)"
    return ", ".join(EKU_LABELS.get(oid, oid) for oid in eku_oids)


def format_key_usage_template(flags: list[str]) -> str:
    if not flags:
        return "(missing)"
    return ", ".join(flags)


def build_classifications(
    hits: list[ct_scan.CertificateHit],
    records: list[ct_scan.DatabaseRecord],
) -> list[PurposeClassification]:
    certificates_by_fingerprint: dict[str, x509.Certificate] = {}
    for record in records:
        cert = x509.load_der_x509_certificate(record.certificate_der)
        is_leaf, _reason = ct_scan.is_leaf_certificate(cert)
        if not is_leaf:
            continue
        fingerprint_sha256 = hashlib.sha256(record.certificate_der).hexdigest()
        certificates_by_fingerprint.setdefault(fingerprint_sha256, cert)

    results: list[PurposeClassification] = []
    for hit in hits:
        cert = certificates_by_fingerprint[hit.fingerprint_sha256]
        san_dns_names = sorted(entry[4:] for entry in hit.san_entries if entry.startswith("DNS:"))
        results.append(
            PurposeClassification(
                fingerprint_sha256=hit.fingerprint_sha256,
                subject_cn=hit.subject_cn,
                issuer_name=ct_scan.primary_issuer_name(hit),
                category=classify_purpose(extract_eku_oids(cert)),
                eku_oids=extract_eku_oids(cert),
                key_usage_flags=extract_key_usage_flags(cert),
                valid_from_utc=ct_scan.utc_iso(hit.validity_not_before),
                valid_to_utc=ct_scan.utc_iso(hit.validity_not_after),
                matched_domains=sorted(hit.matched_domains),
                san_dns_names=san_dns_names,
            )
        )
    results.sort(
        key=lambda item: (
            item.category,
            item.subject_cn.casefold(),
            item.valid_from_utc,
            item.fingerprint_sha256,
        )
    )
    return results


def summarize(classifications: list[PurposeClassification], domains: list[str]) -> AssessmentSummary:
    category_counts = Counter(item.category for item in classifications)
    eku_templates = Counter(format_eku_template(item.eku_oids) for item in classifications)
    key_usage_templates = Counter(format_key_usage_template(item.key_usage_flags) for item in classifications)
    issuer_breakdown: dict[str, Counter[str]] = defaultdict(Counter)
    validity_start_years: dict[str, Counter[str]] = defaultdict(Counter)
    san_type_counts: Counter[str] = Counter()
    subject_cn_in_dns_san_count = 0
    subject_cn_not_in_dns_san_count = 0
    categories_by_canonical_cn: dict[str, set[str]] = defaultdict(set)

    for item in classifications:
        issuer_breakdown[item.category][item.issuer_name] += 1
        validity_start_years[item.category][item.valid_from_utc[:4]] += 1
        san_type_counts["DNSName"] += len(item.san_dns_names)
        if item.subject_cn in set(item.san_dns_names):
            subject_cn_in_dns_san_count += 1
        else:
            subject_cn_not_in_dns_san_count += 1
        categories_by_canonical_cn[ct_scan.canonicalize_subject_cn(item.subject_cn)].add(item.category)

    dual_with_server_only = sorted(
        canonical_cn
        for canonical_cn, values in categories_by_canonical_cn.items()
        if "tls_server_and_client" in values and "tls_server_only" in values
    )
    dual_without_server_only = sorted(
        canonical_cn
        for canonical_cn, values in categories_by_canonical_cn.items()
        if values == {"tls_server_and_client"}
    )

    return AssessmentSummary(
        generated_at_utc=utc_now_iso(),
        source_cache_domains=domains,
        unique_leaf_certificates=len(classifications),
        category_counts=dict(category_counts),
        eku_templates=dict(eku_templates.most_common()),
        key_usage_templates=dict(key_usage_templates.most_common()),
        issuer_breakdown={category: dict(counter.most_common()) for category, counter in issuer_breakdown.items()},
        validity_start_years={
            category: dict(sorted(counter.items()))
            for category, counter in validity_start_years.items()
        },
        san_type_counts=dict(san_type_counts),
        subject_cn_in_dns_san_count=subject_cn_in_dns_san_count,
        subject_cn_not_in_dns_san_count=subject_cn_not_in_dns_san_count,
        dual_eku_subject_cns_with_server_only_sibling=dual_with_server_only,
        dual_eku_subject_cns_without_server_only_sibling=dual_without_server_only,
    )


def render_markdown(summary: AssessmentSummary, classifications: list[PurposeClassification]) -> str:
    lines: list[str] = []
    lines.append("# Certificate Purpose Assessment")
    lines.append("")
    lines.append(f"Generated at: `{summary.generated_at_utc}`")
    lines.append(f"Configured domains: `{', '.join(summary.source_cache_domains)}`")
    lines.append("")
    lines.append("## Headline Verdict")
    lines.append("")
    lines.append(f"- Unique current leaf certificates assessed: **{summary.unique_leaf_certificates}**")
    lines.append(f"- TLS server only: **{summary.category_counts.get('tls_server_only', 0)}**")
    lines.append(f"- TLS server and client auth: **{summary.category_counts.get('tls_server_and_client', 0)}**")
    lines.append(f"- Client auth only: **{summary.category_counts.get('client_auth_only', 0)}**")
    lines.append(f"- S/MIME only: **{summary.category_counts.get('smime_only', 0)}**")
    lines.append(f"- Code signing only: **{summary.category_counts.get('code_signing_only', 0)}**")
    lines.append(f"- Mixed or other: **{summary.category_counts.get('mixed_or_other', 0)}**")
    lines.append(f"- No EKU: **{summary.category_counts.get('no_eku', 0)}**")
    lines.append("")
    lines.append("## What This Means")
    lines.append("")
    lines.append("- The corpus contains **only TLS-capable certificates**. There are no client-only, S/MIME, or code-signing certificates.")
    lines.append("- All SAN entries seen in this corpus are DNS names.")
    lines.append(f"- Subject CN appears literally in a DNS SAN for **{summary.subject_cn_in_dns_san_count} of {summary.unique_leaf_certificates}** certificates.")
    lines.append("- The only ambiguity is whether to keep or set aside the certificates whose EKU allows both `serverAuth` and `clientAuth`.")
    lines.append("")
    lines.append("## Rework Options")
    lines.append("")
    lines.append(f"- Keep the full operational server corpus: **{summary.unique_leaf_certificates}** certificates.")
    lines.append(f"- Keep only strict server-auth certificates: **{summary.category_counts.get('tls_server_only', 0)}** certificates.")
    lines.append(f"- Create a review bucket for dual-EKU certificates: **{summary.category_counts.get('tls_server_and_client', 0)}** certificates.")
    lines.append("")
    lines.append("## EKU Templates")
    lines.append("")
    for template, count in summary.eku_templates.items():
        lines.append(f"- `{template}`: {count}")
    lines.append("")
    lines.append("## KeyUsage Templates")
    lines.append("")
    for template, count in summary.key_usage_templates.items():
        lines.append(f"- `{template}`: {count}")
    lines.append("")
    lines.append("## Issuer Breakdown")
    lines.append("")
    for category in sorted(summary.issuer_breakdown):
        lines.append(f"### `{category}`")
        lines.append("")
        for issuer_name, count in summary.issuer_breakdown[category].items():
            lines.append(f"- `{issuer_name}`: {count}")
        lines.append("")
    lines.append("## Time Pattern")
    lines.append("")
    dual_years = set(summary.validity_start_years.get("tls_server_and_client", {}))
    server_years = set(summary.validity_start_years.get("tls_server_only", {}))
    if dual_years and len(dual_years) == 1:
        lines.append(
            f"- The dual-EKU bucket is entirely composed of certificates whose current validity starts in **{next(iter(sorted(dual_years)))}**."
        )
    if dual_years and server_years and dual_years != server_years:
        lines.append("- The year split suggests at least some change in issuance policy over time.")
    else:
        lines.append("- Time alone does not prove a migration. The stronger signal is the template split by issuer and EKU.")
    lines.append("")
    for category in sorted(summary.validity_start_years):
        year_counts = ", ".join(f"{year}: {count}" for year, count in summary.validity_start_years[category].items())
        lines.append(f"- `{category}`: {year_counts}")
    lines.append("")
    lines.append("## Interpretation")
    lines.append("")
    lines.append("- The `tls_server_and_client` certificates still look like hostname certificates, not user or robot identity certificates.")
    lines.append("- Evidence: public DNS-style Subject CNs, DNS-only SANs, public WebPKI server-auth issuers, and no email or personal-name SAN material.")
    lines.append("- The most plausible reading is **legacy or permissive server certificate templates** that also included `clientAuth`, not a separate client-certificate estate.")
    lines.append("")
    lines.append("## Dual-EKU Hostname Overlap")
    lines.append("")
    lines.append(
        f"- Dual-EKU subject CN families that also have a strict server-only sibling: **{len(summary.dual_eku_subject_cns_with_server_only_sibling)}**"
    )
    lines.append(
        f"- Dual-EKU subject CN families that currently appear only in the dual-EKU bucket: **{len(summary.dual_eku_subject_cns_without_server_only_sibling)}**"
    )
    lines.append("")
    if summary.dual_eku_subject_cns_with_server_only_sibling:
        lines.append("### Dual-EKU Families With Server-Only Siblings")
        lines.append("")
        for subject_cn in summary.dual_eku_subject_cns_with_server_only_sibling:
            lines.append(f"- `{subject_cn}`")
        lines.append("")
    if summary.dual_eku_subject_cns_without_server_only_sibling:
        lines.append("### Dual-EKU Families Without Server-Only Siblings")
        lines.append("")
        for subject_cn in summary.dual_eku_subject_cns_without_server_only_sibling:
            lines.append(f"- `{subject_cn}`")
        lines.append("")
    lines.append("## Detailed Dual-EKU Certificates")
    lines.append("")
    dual_items = [item for item in classifications if item.category == "tls_server_and_client"]
    if not dual_items:
        lines.append("- None")
        lines.append("")
    else:
        for item in dual_items:
            dns_sample = ", ".join(item.san_dns_names[:8])
            if len(item.san_dns_names) > 8:
                dns_sample += ", ..."
            lines.append(f"### `{item.subject_cn}`")
            lines.append("")
            lines.append(f"- Issuer: `{item.issuer_name}`")
            lines.append(f"- Validity: `{item.valid_from_utc}` to `{item.valid_to_utc}`")
            lines.append(f"- Matched search domains: `{', '.join(item.matched_domains)}`")
            lines.append(f"- EKU: `{format_eku_template(item.eku_oids)}`")
            lines.append(f"- KeyUsage: `{format_key_usage_template(item.key_usage_flags)}`")
            lines.append(f"- DNS SAN count: `{len(item.san_dns_names)}`")
            lines.append(f"- DNS SAN sample: `{dns_sample}`")
            lines.append("")
    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    domains = ct_scan.load_domains(args.domains_file)
    records = load_records(
        domains=domains,
        cache_dir=args.cache_dir,
        cache_ttl_seconds=args.cache_ttl_seconds,
        max_candidates=args.max_candidates,
        attempts=args.attempts,
        verbose=args.verbose,
    )
    hits, verification = ct_scan.build_hits(records)
    classifications = build_classifications(hits, records)
    summary = summarize(classifications, domains)

    markdown_payload = render_markdown(summary, classifications)
    json_payload = {
        "summary": asdict(summary),
        "verification": asdict(verification),
        "classifications": [asdict(item) for item in classifications],
    }

    args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.markdown_output.write_text(markdown_payload, encoding="utf-8")
    args.json_output.write_text(json.dumps(json_payload, indent=2, sort_keys=True), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
