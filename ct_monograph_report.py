#!/usr/bin/env python3

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

import ct_caa_analysis
import ct_dns_utils
import ct_focus_subjects
import ct_lineage_report
import ct_master_report
import ct_scan


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a complete monograph-style CT and DNS report with appendices."
    )
    parser.add_argument("--domains-file", type=Path, default=Path("domains.local.txt"))
    parser.add_argument("--cache-dir", type=Path, default=Path(".cache/ct-search"))
    parser.add_argument("--dns-cache-dir", type=Path, default=Path(".cache/dns-scan"))
    parser.add_argument("--caa-cache-dir", type=Path, default=Path(".cache/caa-scan"))
    parser.add_argument("--history-cache-dir", type=Path, default=Path(".cache/ct-history-v2"))
    parser.add_argument("--focus-subjects-file", type=Path, default=Path("focus_subjects.local.txt"))
    parser.add_argument("--cache-ttl-seconds", type=int, default=0)
    parser.add_argument("--dns-cache-ttl-seconds", type=int, default=86400)
    parser.add_argument("--caa-cache-ttl-seconds", type=int, default=86400)
    parser.add_argument("--max-candidates-per-domain", type=int, default=10000)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--markdown-output", type=Path, default=Path("output/corpus/monograph.md"))
    parser.add_argument("--latex-output", type=Path, default=Path("output/corpus/monograph.tex"))
    parser.add_argument("--pdf-output", type=Path, default=Path("output/corpus/monograph.pdf"))
    parser.add_argument("--appendix-markdown-output", type=Path, default=Path(".cache/monograph-temp/appendix-inventory.md"))
    parser.add_argument("--appendix-latex-output", type=Path, default=Path(".cache/monograph-temp/appendix-inventory.tex"))
    parser.add_argument("--appendix-pdf-output", type=Path, default=Path(".cache/monograph-temp/appendix-inventory.pdf"))
    parser.add_argument("--skip-pdf", action="store_true")
    parser.add_argument("--pdf-engine", default="xelatex")
    parser.add_argument("--quiet", action="store_true")
    return parser.parse_args()


def build_scan_stats(report: dict[str, object]) -> ct_scan.ScanStats:
    groups = report["groups"]
    hits = report["hits"]
    verification = report["verification"]
    return ct_scan.ScanStats(
        generated_at_utc=report["generated_at_utc"],
        configured_domains=report["domains"],
        unique_leaf_certificates=len(hits),
        groups_total=len(groups),
        groups_multi_member=sum(1 for group in groups if group.member_count > 1),
        groups_singleton=sum(1 for group in groups if group.member_count == 1),
        groups_by_type=dict(Counter(group.group_type for group in groups)),
        verification=verification,
    )


def render_appendix_inventory(args: argparse.Namespace, report: dict[str, object]) -> None:
    stats = build_scan_stats(report)
    ct_scan.render_markdown_report(
        args.appendix_markdown_output,
        report["hits"],
        report["groups"],
        stats,
        report["issuer_trust"],
    )
    ct_scan.render_latex_report(
        args.appendix_latex_output,
        report["hits"],
        report["groups"],
        stats,
        report["issuer_trust"],
        show_page_numbers=False,
    )
    if not args.skip_pdf:
        ct_scan.compile_latex_to_pdf(args.appendix_latex_output, args.appendix_pdf_output, args.pdf_engine)


def md_table(headers: list[str], rows: list[list[str]]) -> list[str]:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return lines


def latex_escape(value: str) -> str:
    return ct_scan.latex_escape(value)


def short_issuer(issuer_name: str) -> str:
    lowered = issuer_name.lower()
    if "amazon" in lowered:
        return "Amazon"
    if "sectigo" in lowered or "comodo" in lowered:
        return "Sectigo/COMODO"
    if "google trust services" in lowered or "cn=we1" in lowered:
        return "Google Trust Services"
    return issuer_name


def pct(count: int, total: int) -> str:
    if total <= 0:
        return "0.0%"
    return f"{(count / total) * 100:.1f}%"


def purpose_label(category: str) -> str:
    return {
        "tls_server_only": "TLS server only",
        "tls_server_and_client": "TLS server and client auth",
        "client_auth_only": "Client auth only",
        "smime_only": "S/MIME only",
        "code_signing_only": "Code signing only",
        "mixed_or_other": "Mixed or other",
        "no_eku": "No EKU",
    }.get(category, category)


def purpose_meaning(category: str) -> str:
    return {
        "tls_server_only": "Standard public website or API endpoint certificate.",
        "tls_server_and_client": "Server certificate whose EKU also permits client-certificate use.",
        "client_auth_only": "Identity-style certificate for a person, robot, or agent in mTLS.",
        "smime_only": "Email-signing or email-encryption certificate.",
        "code_signing_only": "Software-signing certificate rather than a web-endpoint certificate.",
        "mixed_or_other": "Unusual or mixed EKU combination requiring case-by-case review.",
        "no_eku": "Certificate without an Extended Key Usage extension.",
    }.get(category, "Certificate purpose category.")


def collapse_issuer_counts_by_family(issuer_counts: dict[str, int]) -> Counter[str]:
    families: Counter[str] = Counter()
    for issuer_name, count in issuer_counts.items():
        families[short_issuer(issuer_name)] += count
    return families


def build_issuer_family_rows(report: dict[str, object]) -> list[dict[str, str]]:
    issuer_trust = report["issuer_trust"]
    families: dict[str, dict[str, object]] = {}
    for issuer_name, count in report["issuer_counts"].most_common():
        family = short_issuer(issuer_name)
        row = families.setdefault(
            family,
            {
                "family": family,
                "certificates": 0,
                "variants": [],
                "major_webpki": True,
            },
        )
        row["certificates"] += count
        row["variants"].append(issuer_name)
        row["major_webpki"] = bool(row["major_webpki"] and issuer_trust[issuer_name].major_webpki)
    ordered = sorted(
        families.values(),
        key=lambda item: (-int(item["certificates"]), str(item["family"]).casefold()),
    )
    result: list[dict[str, str]] = []
    for item in ordered:
        variant_labels = [
            str(name).split("CN=")[-1]
            for name in sorted(item["variants"], key=str.casefold)
        ]
        result.append(
            {
                "family": str(item["family"]),
                "certificates": str(item["certificates"]),
                "variant_count": str(len(variant_labels)),
                "major_webpki": "yes" if item["major_webpki"] else "no",
                "variants": ", ".join(variant_labels),
            }
        )
    return result


def build_history_args(args: argparse.Namespace) -> argparse.Namespace:
    return argparse.Namespace(
        domains_file=args.domains_file,
        cache_dir=args.history_cache_dir,
        cache_ttl_seconds=args.cache_ttl_seconds,
        max_candidates_per_domain=args.max_candidates_per_domain,
        retries=args.retries,
        quiet=args.quiet,
        markdown_output=Path(".cache/monograph-temp/unused-history.md"),
        latex_output=Path(".cache/monograph-temp/unused-history.tex"),
        pdf_output=Path(".cache/monograph-temp/unused-history.pdf"),
        skip_pdf=True,
        pdf_engine=args.pdf_engine,
    )


def historical_repeated_cn_count(assessment: ct_lineage_report.HistoricalAssessment) -> int:
    return sum(1 for values in assessment.cn_groups.values() if len(values) > 1)


def truncate_text(value: str, limit: int = 88) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3].rstrip() + "..."


def first_list_item(value: str) -> str:
    return value.split(", ")[0] if value else "-"


def compact_list_items(value: str, keep: int = 2, limit: int = 96) -> str:
    if not value:
        return "-"
    parts = value.split(", ")
    if len(parts) <= keep:
        return truncate_text(value, limit)
    return truncate_text(", ".join(parts[:keep]) + f", ... (+{len(parts) - keep} more)", limit)


def compact_family_basis(value: str) -> str:
    prefixes = {
        "CN pattern with running-number slot: ": "Numbered family: ",
        "Same endpoint CN family (exact CN; www. grouped with base name): ": "Exact endpoint family: ",
    }
    for prefix, replacement in prefixes.items():
        if value.startswith(prefix):
            return value.replace(prefix, replacement, 1)
    return truncate_text(value, 92)


def latex_table_cell(value: str) -> str:
    escaped = latex_escape(value)
    for token in [".", "/", "-", ":", ";", ",", "="]:
        escaped = escaped.replace(token, token + r"\allowbreak{}")
    return escaped


def append_longtable(
    lines: list[str],
    spec: str,
    headers: list[str],
    rows: list[list[str]],
    *,
    font: str = "small",
    tabcolsep: str | None = "3.8pt",
) -> None:
    lines.append(r"\begingroup")
    if font:
        lines.append(rf"\{font}")
    if tabcolsep:
        lines.append(rf"\setlength{{\tabcolsep}}{{{tabcolsep}}}")
    lines.append(rf"\begin{{longtable}}{{{spec}}}")
    header_line = " & ".join(latex_escape(header) for header in headers) + r" \\"
    lines.extend(
        [
            r"\toprule",
            header_line,
            r"\midrule",
            r"\endfirsthead",
            r"\toprule",
            header_line,
            r"\midrule",
            r"\endhead",
            r"\midrule",
            rf"\multicolumn{{{len(headers)}}}{{r}}{{\footnotesize\itshape Continued on next page}} \\",
            r"\midrule",
            r"\endfoot",
            r"\bottomrule",
            r"\endlastfoot",
        ]
    )
    for row in rows:
        lines.append(" & ".join(latex_table_cell(cell) for cell in row) + r" \\")
    lines.extend([r"\end{longtable}", r"\endgroup"])


def nonzero_purpose_rows(purpose_rows: list[list[str]]) -> list[list[str]]:
    return [row for row in purpose_rows if row[1] != "0"]


def driver_summary(subjects: str, issuers: str) -> str:
    return f"{truncate_text(first_list_item(subjects), 48)}; {truncate_text(first_list_item(issuers), 28)}"


def counter_text(counter: Counter[str], limit: int = 4) -> str:
    if not counter:
        return "-"
    items = [f"{name} ({count})" for name, count in counter.most_common(limit)]
    if len(counter) > limit:
        items.append(f"... (+{len(counter) - limit} more)")
    return ", ".join(items)


def overlap_signal(details: str) -> str:
    parts = []
    for piece in details.split("; "):
        if piece.startswith("DN=") or piece.startswith("SANs="):
            parts.append(piece)
    return truncate_text("; ".join(parts) if parts else details, 108)


def caa_source_label(source_kind: str) -> str:
    return {
        "exact": "Exact-name CAA",
        "alias_target": "Alias-target CAA",
        "parent": "Inherited parent CAA",
        "parent_alias_target": "Inherited parent CAA reached through alias following",
        "none": "No CAA found",
    }.get(source_kind, source_kind)


def caa_policy_label(families: tuple[str, ...]) -> str:
    if families == ("UNRESTRICTED",):
        return "No published CAA restriction"
    if families == ("Amazon",):
        return "Amazon-only issuance policy"
    if families == ("DigiCert/QuoVadis", "Sectigo/COMODO"):
        return "Corporate broad policy"
    if families == ("Amazon", "DigiCert/QuoVadis", "Sectigo/COMODO"):
        return "Mixed corporate-plus-Amazon policy"
    if families == ("Google Trust Services", "Sectigo/COMODO"):
        return "Google plus Sectigo policy"
    if "Let's Encrypt" in families or "Telia" in families:
        return "Vendor-delegated broad policy"
    return "Mixed named policy"


def caa_policy_explanation(families: tuple[str, ...]) -> str:
    if families == ("UNRESTRICTED",):
        return "No CAA restriction is published, so WebPKI issuance is not limited by DNS policy."
    if families == ("Amazon",):
        return "Only Amazon Trust Services identifiers are authorized by DNS policy."
    if families == ("DigiCert/QuoVadis", "Sectigo/COMODO"):
        return "The name inherits the broad corporate policy that permits the main non-Amazon public CA families seen in this estate."
    if families == ("Amazon", "DigiCert/QuoVadis", "Sectigo/COMODO"):
        return "The name permits both the broad corporate CA set and Amazon Trust Services."
    if families == ("Google Trust Services", "Sectigo/COMODO"):
        return "This is a narrow exception that permits Google Trust Services alongside the Sectigo lineage."
    if "Let's Encrypt" in families or "Telia" in families:
        return "The allowed CA set is wider and looks delegated to a specialist external platform or vendor."
    return "The DNS policy allows a mixed set of public CA families."


def service_anchor_label(name: str, zone: str) -> str:
    if zone == "other":
        return name
    if name == zone:
        return zone
    relative = name[: -(len(zone) + 1)]
    parts = relative.split(".")
    if not parts:
        return zone
    return parts[-1]


def caa_zone_policy_rows(
    analysis: ct_caa_analysis.CaaAnalysis,
    zone: str,
) -> list[list[str]]:
    rows = ct_caa_analysis.rows_for_zone(analysis, zone)
    policy_counts = ct_caa_analysis.policy_counter(rows)
    return [
        [
            caa_policy_label(policy),
            str(count),
            caa_policy_explanation(policy),
        ]
        for policy, count in policy_counts.most_common()
    ]


def caa_source_rows(analysis: ct_caa_analysis.CaaAnalysis) -> list[list[str]]:
    return [
        [
            caa_source_label(source_kind),
            str(count),
            {
                "exact": "The queried DNS name itself published the effective CAA.",
                "alias_target": "The queried DNS name resolved through an alias and the effective CAA came from what that alias chain exposed.",
                "parent": "The leaf name had no CAA, so issuance policy was inherited from a parent DNS node.",
                "parent_alias_target": "The leaf name inherited from a parent DNS node, and that parent policy was itself exposed through an alias response.",
                "none": "No effective CAA was found at the name or its parents.",
            }.get(source_kind, "CAA discovery result."),
        ]
        for source_kind, count in analysis.source_kind_counts.most_common()
    ]


def top_caa_overlap_rows(analysis: ct_caa_analysis.CaaAnalysis, limit: int = 15) -> list[list[str]]:
    rows = [row for row in analysis.rows if row.current_multi_family_overlap]
    ordered = sorted(rows, key=lambda row: (row.zone, service_anchor_label(row.name, row.zone), row.name))
    return [
        [
            row.name,
            row.zone,
            ", ".join(row.current_covering_families),
            compact_list_items(", ".join(row.current_covering_subject_cns), keep=2, limit=64),
        ]
        for row in ordered[:limit]
    ]


def top_caa_mismatch_rows(analysis: ct_caa_analysis.CaaAnalysis, limit: int = 15) -> list[list[str]]:
    rows = [row for row in analysis.rows if row.current_policy_mismatch]
    ordered = sorted(rows, key=lambda row: (row.zone, service_anchor_label(row.name, row.zone), row.name))
    return [
        [
            row.name,
            row.zone,
            ", ".join(row.current_covering_families),
            ", ".join(row.allowed_ca_families) or "UNRESTRICTED",
            caa_source_label(row.source_kind),
        ]
        for row in ordered[:limit]
    ]


def caa_concentration_text(analysis: ct_caa_analysis.CaaAnalysis, zone: str) -> str:
    rows = [row for row in ct_caa_analysis.rows_for_zone(analysis, zone) if row.current_policy_mismatch or row.current_multi_family_overlap]
    if not rows:
        return "none"
    counts = Counter(service_anchor_label(row.name, zone) for row in rows)
    return ", ".join(f"{label} ({count})" for label, count in counts.most_common(6))


def focus_comparison_rows(focus_analysis: ct_focus_subjects.FocusCohortAnalysis) -> list[list[str]]:
    return [
        [
            "Current direct Subject CN names",
            str(focus_analysis.current_direct_subjects_count),
            str(len(focus_analysis.rest_current_subject_dns_classes) and sum(focus_analysis.rest_current_subject_dns_classes.values()) or 0),
            "Shows whether the cohort is mostly made of live direct front-door names or of carried SAN passengers.",
        ],
        [
            "Current certificates",
            str(focus_analysis.current_focus_certificate_count),
            str(focus_analysis.current_rest_certificate_count),
            "Shows the raw current certificate weight of the cohort against the rest of the estate.",
        ],
        [
            "Issuer families in current certificates",
            counter_text(focus_analysis.focus_current_issuer_families, 3),
            counter_text(focus_analysis.rest_current_issuer_families, 3),
            "Separates the older Sectigo/COMODO-style public web cohort from the Amazon-heavy operational rail population.",
        ],
        [
            "Revoked share inside current certificates",
            focus_analysis.focus_revoked_share,
            focus_analysis.rest_revoked_share,
            "A high revoked share points to rapid replacement churn or short-lived issuance iterations.",
        ],
        [
            "Median SAN entries per current certificate",
            str(focus_analysis.focus_median_san_entries),
            str(focus_analysis.rest_median_san_entries),
            "Small SAN sets usually indicate standalone front doors; large SAN sets usually indicate bundled platform coverage.",
        ],
        [
            "Current multi-zone certificates",
            str(focus_analysis.focus_multi_zone_certificate_count),
            str(focus_analysis.rest_multi_zone_certificate_count),
            "Multi-zone certificates are strong evidence of shared-service or bridge certificates rather than one-name service fronts.",
        ],
    ]


def focus_bucket_details(
    focus_analysis: ct_focus_subjects.FocusCohortAnalysis,
    bucket: str,
) -> list[ct_focus_subjects.FocusSubjectDetail]:
    return [
        detail
        for detail in focus_analysis.details
        if detail.taxonomy_bucket == bucket
    ]


def focus_bucket_examples(
    focus_analysis: ct_focus_subjects.FocusCohortAnalysis,
    bucket: str,
    limit: int = 4,
) -> str:
    details = focus_bucket_details(focus_analysis, bucket)
    if not details:
        return "-"
    ordered = sorted(
        details,
        key=lambda item: (
            -item.current_direct_certificates,
            -item.historical_direct_certificates,
            item.subject_cn.casefold(),
        ),
    )
    names = [detail.subject_cn for detail in ordered[:limit]]
    if len(ordered) > limit:
        names.append(f"... (+{len(ordered) - limit} more)")
    return ", ".join(names)


def focus_bucket_summary_rows(focus_analysis: ct_focus_subjects.FocusCohortAnalysis) -> list[list[str]]:
    meanings = {
        "direct_front_door": (
            "Direct branded, service, identity, or vendor-facing names with small SAN sets and one-zone scope.",
            "These are the names a human operator is most likely to remember as visible service fronts rather than as hidden platform rails.",
        ),
        "platform_matrix_anchor": (
            "Umbrella certificates with large SAN matrices encoding environment, tenant, service-cell, or monitoring axes.",
            "These names anchor a managed platform slice rather than a single public page or API front.",
        ),
        "ambiguous_legacy": (
            "Historical residue, carried SAN passengers, opaque labels, or mixed-shape names that no longer fit a clean live pattern.",
            "This bucket captures the messy edge cases where migration, retirement, or naming opacity matters more than current front-door behavior.",
        ),
    }
    rows: list[list[str]] = []
    for bucket in ["direct_front_door", "platform_matrix_anchor", "ambiguous_legacy"]:
        meaning, why = meanings[bucket]
        rows.append(
            [
                ct_focus_subjects.taxonomy_bucket_label(bucket),
                str(focus_analysis.bucket_counts.get(bucket, 0)),
                truncate_text(focus_bucket_examples(focus_analysis, bucket), 72),
                meaning,
                why,
            ]
        )
    return rows


def focus_representative_rows(focus_analysis: ct_focus_subjects.FocusCohortAnalysis) -> list[list[str]]:
    rows: list[list[str]] = []
    for bucket in ["direct_front_door", "platform_matrix_anchor", "ambiguous_legacy"]:
        details = focus_bucket_details(focus_analysis, bucket)
        if not details:
            continue
        ordered = sorted(
            details,
            key=lambda item: (
                -item.current_direct_certificates,
                -item.historical_direct_certificates,
                -item.current_non_focus_san_carriers,
                item.subject_cn.casefold(),
            ),
        )
        for detail in ordered[:4]:
            rows.append(
                [
                    ct_focus_subjects.taxonomy_bucket_label(bucket),
                    detail.subject_cn,
                    truncate_text(detail.observed_role, 30),
                    f"{detail.current_direct_certificates}/{detail.historical_direct_certificates}",
                    truncate_text(
                        f"current SANs={detail.current_san_size_span}, historical SANs={detail.historical_san_size_span}, DNS={detail.current_dns_outcome}",
                        78,
                    ),
                ]
            )
    return rows


def focus_appendix_rows(
    focus_analysis: ct_focus_subjects.FocusCohortAnalysis,
    bucket: str,
) -> list[list[str]]:
    rows: list[list[str]] = []
    for detail in focus_bucket_details(focus_analysis, bucket):
        rows.append(
            [
                detail.subject_cn,
                truncate_text(detail.taxonomy_reason, 40),
                truncate_text(detail.analyst_note, 28),
                truncate_text(detail.observed_role, 28),
                f"{detail.current_direct_certificates}/{detail.historical_direct_certificates}",
                f"{detail.current_non_focus_san_carriers}/{detail.historical_non_focus_san_carriers}",
                truncate_text(f"{detail.current_san_size_span}/{detail.historical_san_size_span}", 16),
                truncate_text(detail.current_dns_outcome, 24),
                f"revoked={detail.current_revoked_certificates}, live={detail.current_not_revoked_certificates}",
                truncate_text(detail.current_red_flags, 24),
                truncate_text(detail.past_red_flags, 24),
            ]
        )
    return rows


def example_pattern_label(title: str) -> str:
    return {
        "Shared operational rail": "Numbered fleet or operational-rail naming",
        "Environment matrix certificate": "Environment-matrix and lifecycle naming",
        "Brand-platform splice": "Cross-brand namespace and migration-residue naming",
        "Cross-zone bridge": "Cross-zone bridge or shared-service naming",
    }.get(title, "Naming pattern")


def delivery_pattern_meaning(label: str) -> str:
    return {
        "Adobe Campaign -> AWS ALB": "The public name first aliases into Adobe Campaign naming and then lands on Amazon load-balancing infrastructure. In plain terms, a messaging or campaign front appears to sit in front of AWS-hosted delivery.",
        "Adobe Campaign -> AWS CloudFront": "The public name first aliases into Adobe Campaign naming and then into Amazon CloudFront. That usually means campaign or messaging traffic delivered through a CDN edge.",
        "Adobe Campaign direct IP": "Adobe Campaign naming is visible in the DNS trail, but the public name lands straight on an address rather than on an obvious CDN or load balancer hostname.",
        "AWS CloudFront": "The public name lands on Amazon's CDN edge without an Adobe layer. This usually means edge delivery for web or API traffic.",
        "Google Apigee": "The public name lands on a managed API front door. That normally means the endpoint is being exposed as a governed API rather than directly from an application host.",
        "Pega Cloud -> AWS ALB": "The public name points to Pega-managed application hosting that ultimately lands on AWS load-balancing infrastructure.",
        "Direct AWS": "The public name lands directly on AWS-hosted infrastructure without a visible intermediary platform in public DNS.",
        "Direct Microsoft edge": "The public name lands on Microsoft's front-door edge addresses rather than directly on a private application host.",
        "CNAME to address (provider unclear)": "The public name aliases to another hostname and then to an address, but the public clues are too weak to assign a platform vendor confidently.",
        "Direct address (provider unclear)": "The public name resolves straight to an address, with no strong provider clue visible in public DNS.",
        "No public DNS (NXDOMAIN)": "The name contained in certificates does not currently exist in public DNS.",
        "No public address data": "The name exists in DNS, but no public A or AAAA address was returned during the scan.",
        "Dangling agency alias": "The name aliases to a third-party intermediary hostname that no longer resolves cleanly. That usually indicates stale or partially removed DNS.",
    }.get(label, "Recurring public DNS outcome derived from the observed answer chain.")


def delivery_pattern_rule(label: str) -> str:
    return {
        "Adobe Campaign -> AWS ALB": "Used when the alias chain contains Adobe Campaign naming and the terminal DNS clues point to AWS load-balancer or AWS-hosted infrastructure.",
        "Adobe Campaign -> AWS CloudFront": "Used when the alias chain contains Adobe Campaign naming and the terminal target contains CloudFront clues.",
        "Adobe Campaign direct IP": "Used when Adobe Campaign naming is visible but the name lands directly on an IP address.",
        "AWS CloudFront": "Used when the terminal DNS target contains CloudFront clues without an Adobe Campaign layer in front of it.",
        "Google Apigee": "Used when the alias chain or terminal target contains Apigee or Google API gateway clues such as apigee.net.",
        "Pega Cloud -> AWS ALB": "Used when the DNS trail contains Pega-hosting clues and then AWS load-balancer clues.",
        "Direct AWS": "Used when the name lands directly on AWS clues without an intermediate branded platform layer.",
        "Direct Microsoft edge": "Used when the address falls in the public Microsoft front-door ranges used in this heuristic.",
        "CNAME to address (provider unclear)": "Used when a CNAME chain exists, but no recognized provider clue appears in the public DNS trail.",
        "Direct address (provider unclear)": "Used when the name resolves directly to an address and no recognized provider clue appears.",
        "No public DNS (NXDOMAIN)": "Used when the DNS lookup returns NXDOMAIN.",
        "No public address data": "Used when DNS exists but returns no public address data.",
        "Dangling agency alias": "Used when the alias chain points to the agency-style intermediary namespace but does not resolve to a live endpoint.",
    }.get(label, "Derived from the public DNS answer shape and the provider clues seen in names, targets, and PTRs.")


def render_markdown(
    args: argparse.Namespace,
    report: dict[str, object],
    assessment: ct_lineage_report.HistoricalAssessment,
    caa_analysis: ct_caa_analysis.CaaAnalysis,
    focus_analysis: ct_focus_subjects.FocusCohortAnalysis | None,
) -> None:
    args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
    appendix_markdown = args.appendix_markdown_output.read_text(encoding="utf-8")
    hits = report["hits"]
    groups = report["groups"]
    purpose_summary = report["purpose_summary"]
    total_certificates = len(report["classifications"])
    dual_items = [item for item in report["classifications"] if item.category == "tls_server_and_client"]
    dual_issuer_counts = Counter(short_issuer(item.issuer_name) for item in dual_items)
    server_only_count = purpose_summary.category_counts.get("tls_server_only", 0)
    dual_count = purpose_summary.category_counts.get("tls_server_and_client", 0)
    server_only_issuer_families = collapse_issuer_counts_by_family(
        purpose_summary.issuer_breakdown.get("tls_server_only", {})
    )
    historical_count = len(assessment.certificates)
    historical_current_count = sum(1 for item in assessment.certificates if item.current)
    repeated_cn_count = historical_repeated_cn_count(assessment)
    purpose_rows = [
        [
            purpose_label(category),
            str(count),
            pct(count, total_certificates),
            purpose_meaning(category),
        ]
        for category, count in [
            ("tls_server_only", purpose_summary.category_counts.get("tls_server_only", 0)),
            ("tls_server_and_client", purpose_summary.category_counts.get("tls_server_and_client", 0)),
            ("client_auth_only", purpose_summary.category_counts.get("client_auth_only", 0)),
            ("smime_only", purpose_summary.category_counts.get("smime_only", 0)),
            ("code_signing_only", purpose_summary.category_counts.get("code_signing_only", 0)),
            ("mixed_or_other", purpose_summary.category_counts.get("mixed_or_other", 0)),
            ("no_eku", purpose_summary.category_counts.get("no_eku", 0)),
        ]
    ]
    visible_purpose_rows = nonzero_purpose_rows(purpose_rows)
    eku_template_rows = [
        [template, str(count), pct(count, total_certificates)]
        for template, count in purpose_summary.eku_templates.items()
    ]
    key_usage_rows = [
        [template, str(count), pct(count, total_certificates)]
        for template, count in purpose_summary.key_usage_templates.items()
    ]
    issuer_rows = [
        [
            row["family"],
            row["certificates"],
            row["variant_count"],
            row["major_webpki"],
            row["variants"],
        ]
        for row in build_issuer_family_rows(report)
    ]
    family_rows = [
        [
            compact_family_basis(row["basis"]),
            str(row["certificates"]),
            str(row["subjects"]),
            first_list_item(row["top_stacks"]),
        ]
        for row in report["group_digest"]
    ]
    dual_rows = [
        [
            item.subject_cn,
            item.valid_from_utc[:10],
            item.valid_to_utc[:10],
            short_issuer(item.issuer_name),
            str(len(item.san_dns_names)),
        ]
        for item in dual_items
    ]
    dns_stack_rows = [
        [label, str(count)]
        for label, count in report["dns_stack_counts"].most_common(12)
    ]
    dns_class_counts = report["dns_class_counts"]
    alias_to_address_count = dns_class_counts.get("cname_to_address", 0)
    direct_address_count = dns_class_counts.get("direct_address", 0)
    nxdomain_count = dns_class_counts.get("nxdomain", 0)
    dangling_count = dns_class_counts.get("dangling_cname", 0)
    no_data_count = dns_class_counts.get("no_data", 0)
    top_dns_patterns = report["dns_stack_counts"].most_common(8)
    dns_pattern_rows = [
        [label, str(count), delivery_pattern_meaning(label)]
        for label, count in top_dns_patterns
    ]
    focus_comparison = focus_comparison_rows(focus_analysis) if focus_analysis else []
    focus_bucket_summary = focus_bucket_summary_rows(focus_analysis) if focus_analysis else []
    focus_representatives = focus_representative_rows(focus_analysis) if focus_analysis else []
    has_focus = focus_analysis is not None
    caa_zone_rows = {
        zone: caa_zone_policy_rows(caa_analysis, zone)
        for zone in caa_analysis.configured_domains
    }
    primary_zone = report["domains"][0] if report["domains"] else "configured primary zone"
    secondary_zone = report["domains"][1] if len(report["domains"]) > 1 else None
    synthesis_chapter = 9 if has_focus else 8
    limits_chapter = 10 if has_focus else 9
    caa_appendix = "C"
    focus_appendix = "D" if has_focus else None
    detailed_inventory_appendix = "E" if has_focus else "D"
    lines: list[str] = []
    lines.append("# CT and DNS Monograph")
    lines.append("")
    lines.append(f"Generated: {report['generated_at_utc']}")
    lines.append(f"Configured search terms file: `{args.domains_file.name}`")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.extend(
        [
            f"- **{len(hits)}** current leaf certificates are in scope on this run.",
            f"- **{len(groups)}** CN families reduce the estate into readable naming clusters.",
            f"- **{purpose_summary.category_counts.get('tls_server_only', 0)}** certificates are ordinary public TLS server certificates, while **{purpose_summary.category_counts.get('tls_server_and_client', 0)}** come from templates that also permit client-certificate use.",
            f"- **{historical_count}** historical leaf certificates show how these names evolved over time, including expired renewal history.",
            f"- **{len(report['unique_dns_names'])}** unique DNS SAN names were scanned live.",
            f"- **{caa_analysis.total_names}** DNS names were also assessed for effective CAA policy, revealing where issuance is centrally governed, delegated, or left unrestricted.",
            "- The estate is best understood as several layers laid on top of one another: brand naming, service naming, platform naming, delivery-stack naming, issuance-policy control, and migration residue.",
        ]
    )
    lines.append("")
    lines.append("## Reading Guide")
    lines.append("")
    lines.extend(
        [
            "- Read Chapter 1 if you want to know whether the corpus is complete and trustworthy.",
            "- Read Chapters 2 and 3 if you want the current certificate-side story: issuers, trust, and purpose.",
            "- Read Chapter 4 if you want the historical lifecycle view and the red flags split into current versus fixed-in-the-past.",
            "- Read Chapters 5 and 6 if you want the naming and DNS story.",
            "- Read Chapter 7 if you want the issuance-policy view: which public CAs are authorized by DNS and where that control is absent, inherited, or delegated.",
            *(
                ["- Read Chapter 8 if you want the focused Subject-CN cohort analysis and why that subset behaves differently from the wider estate."]
                if has_focus
                else []
            ),
            f"- Read Chapter {synthesis_chapter} if you want the synthesis that ties business naming, service architecture, and hosting patterns together.",
            "- Use the appendices when you need the fine-grained evidence rather than the argument.",
        ]
    )
    lines.append("")
    lines.append("## Chapter 1: Scope, Completeness, and Proof")
    lines.append("")
    lines.append("**Management Summary**")
    lines.append("")
    lines.extend(
        [
            f"- The first broad crt.sh search returned {', '.join(f'{domain}={count} matching index rows' for domain, count in report['raw_match_counts'].items())}. Those rows are leads, not final certificate count.",
            f"- The scanner was allowed to collect up to {report['cap']} candidate rows per search term. Because the live match counts stayed below that limit, nothing was silently cut off.",
            f"- After downloading and parsing the actual certificate bodies, {report['verification'].unique_leaf_certificates} genuine leaf certificates remained. {report['verification'].non_leaf_filtered} CA-style certificates and {report['verification'].precertificate_poison_filtered} precertificate marker objects were rejected.",
            f"- Certificates missing the searched-for domains in their DNS SANs after full parsing: {report['missing_matching_san']}.",
        ]
    )
    lines.append("")
    lines.append("This chapter answers the first and most important question: whether the report is built on a complete and trustworthy corpus. The scanner now checks the live raw match count before issuing the capped query. If the cap is too low, it fails instead of silently undercounting.")
    lines.append("")
    lines.append("The first crt.sh row count is intentionally larger than the final certificate count because Certificate Transparency search results are index rows, not de-duplicated certificates. The report therefore reads the binary certificate body itself, removes duplicates, rejects CA certificates and precertificate marker objects, and only then builds the working corpus.")
    lines.append("")
    lines.append("In other words: this publication is not based on search-result snippets alone. It is based on the parsed X.509 certificate bodies.")
    lines.append("")
    lines.append("## Chapter 2: The Certificate Corpus")
    lines.append("")
    lines.append("**Management Summary**")
    lines.append("")
    lines.extend(
        [
            f"- Issuer families by certificate count: {', '.join(f'{name} ({count})' for name, count in report['issuer_family_counts'].most_common())}.",
            f"- Revocation state in plain terms: {report['rev_counts'].get('not_revoked', 0)} certificates are not marked revoked, and {report['rev_counts'].get('revoked', 0)} were later marked invalid by their issuing CA before natural expiry.",
            f"- For every current certificate, the main Subject CN hostname also appears literally in the DNS SAN list. The headline name on the certificate is therefore one of the real covered hostnames, not a decorative label.",
            f"- All visible issuer families in this corpus are currently trusted by the major public browser and operating-system trust stores for ordinary web server use.",
        ]
    )
    lines.append("")
    lines.append("A certificate corpus can look random when viewed as a flat list. It becomes intelligible once you group it by issuer family, Subject CN construction, validity history, and SAN design. That is why the appendices are arranged as families rather than raw rows.")
    lines.append("")
    lines.append("### Issuer Trust Table")
    lines.append("")
    lines.extend(md_table(["Issuer Family", "Certificates", "Variants", "Major WebPKI"], [row[:4] for row in issuer_rows]))
    lines.append("")
    lines.append("**What WebPKI trust means**")
    lines.append("")
    lines.append("A WebPKI-trusted issuer is a certificate authority trusted by mainstream browser and operating-system trust stores for public TLS. That matters because it tells you these certificates are not part of a private PKI hidden inside one organisation. They are intended to be valid in the public Internet trust model.")
    lines.append("")
    lines.append("This view should answer one question only: how many publicly trusted issuer families are present in the estate. The exact subordinate issuer names are supporting evidence, so they stay in the appendix inventory rather than cluttering the main chapter.")
    lines.append("")
    lines.append("## Chapter 3: Intended Purpose of the Certificates")
    lines.append("")
    lines.append("**Management Summary**")
    lines.append("")
    lines.extend(
        [
            f"- Certificates whose allowed purpose is ordinary server authentication only: {purpose_summary.category_counts.get('tls_server_only', 0)}.",
            f"- Certificates whose policy allows both server use and client-certificate use: {purpose_summary.category_counts.get('tls_server_and_client', 0)}.",
            "- Certificates dedicated only to client identity, email signing, or code signing: 0.",
        ]
    )
    lines.append("")
    lines.append("This chapter addresses a key ambiguity. A certificate can be technically valid for several uses, and the hostname alone does not settle that question. The corpus was therefore assessed from the X.509 usage fields themselves: EKU and KeyUsage.")
    lines.append("")
    lines.append("### Purpose Map")
    lines.append("")
    lines.extend(md_table(["Usage Class", "Certificates", "Share", "Meaning"], visible_purpose_rows))
    lines.append("")
    lines.append("This view should answer only what kind of certificates these are. Zero-count categories are deliberately removed here because they add noise without changing the conclusion.")
    lines.append("")
    lines.append("The basic picture is simple: the corpus is overwhelmingly made of ordinary public TLS server certificates, with a smaller minority whose EKU also permits client-certificate use.")
    lines.append("")
    lines.append("**Plain-language explanation of the usage categories**")
    lines.append("")
    lines.extend(
        [
            "- **TLS server certificate**: the certificate a website or API presents to a browser, app, or machine client.",
            "- **Server and client auth certificate**: a certificate whose EKU allows both server use and client-certificate use. That does not automatically mean it is actually used as a client certificate, but it leaves that door open.",
            "- **Client auth only**: the kind of certificate you would expect for a user, robot, or agent identity in mutual TLS.",
            "- **S/MIME**: email-signing or email-encryption certificates.",
            "- **Code signing**: certificates used to sign software rather than to secure a web endpoint.",
        ]
    )
    lines.append("")
    lines.append("The result is clean. This corpus is entirely TLS-capable. There is no evidence of a separate S/MIME or code-signing estate, and there are no client-auth-only certificates.")
    lines.append("")
    lines.append("### EKU and KeyUsage Templates")
    lines.append("")
    lines.append("At the template level, the corpus is even simpler than the certificate count suggests. Here, a template simply means a repeated combination of usage fields. Only two EKU combinations appear at all, and one KeyUsage pattern dominates almost completely.")
    lines.append("")
    lines.extend(md_table(["EKU Template", "Certificates", "Share"], eku_template_rows))
    lines.append("")
    lines.extend(md_table(["KeyUsage Template", "Certificates", "Share"], key_usage_rows))
    lines.append("")
    lines.append("### The Majority Pattern: Server-Only Public TLS")
    lines.append("")
    lines.extend(
        [
            f"- Server-only certificates account for {server_only_count} of {total_certificates} certificates, or {pct(server_only_count, total_certificates)} of the corpus.",
            f"- Server-only validity starts are split between {', '.join(f'{year} ({count})' for year, count in purpose_summary.validity_start_years.get('tls_server_only', {}).items())}.",
            f"- Server-only issuer-family concentration: {', '.join(f'{name} ({count})' for name, count in server_only_issuer_families.most_common())}.",
            "- This is the normal public WebPKI server-certificate pattern for websites, APIs, and edge service front doors.",
        ]
    )
    lines.append("")
    lines.append("This majority group is not background noise. It is the main operational reality visible in the scan: public DNS names covered by publicly trusted endpoint certificates.")
    lines.append("")
    if dual_rows:
        lines.append("### The Minority Pattern: Dual EKU")
        lines.append("")
        lines.append("EKU means *allowed purpose*, not *observed real-world use*. A dual-EKU certificate is a certificate whose X.509 policy says it may be used both as a TLS server certificate and as a TLS client certificate.")
        lines.append("")
        lines.extend(
            [
                f"- Dual-EKU certificates in this corpus: {dual_count}, or {pct(dual_count, total_certificates)} of the corpus.",
                f"- Issuer-family concentration inside the dual-EKU group: {', '.join(f'{name} ({count})' for name, count in dual_issuer_counts.most_common())}.",
                f"- Dual-EKU Subject CN families that also have a strict server-only sibling: {len(purpose_summary.dual_eku_subject_cns_with_server_only_sibling)}.",
                f"- Dual-EKU Subject CN families that appear only in the dual-EKU group: {len(purpose_summary.dual_eku_subject_cns_without_server_only_sibling)}.",
                f"- Dual-EKU validity starts are split between {', '.join(f'{year} ({count})' for year, count in purpose_summary.validity_start_years.get('tls_server_and_client', {}).items())}.",
            ]
        )
        lines.append("")
        lines.append("The important interpretation point is this: these still look like public hostname certificates, not person or robot identity certificates. They have DNS-style Subject CN values, DNS SAN lists, and public WebPKI issuers. The best reading is therefore not 'this is a separate client-certificate estate', but rather 'some server certificates were issued from a template that also allowed clientAuth'.")
        lines.append("")
    lines.append("### What Is Not Present")
    lines.append("")
    lines.extend(
        [
            "- There are no client-auth-only certificates in the corpus.",
            "- There are no S/MIME certificates in the corpus.",
            "- There are no code-signing certificates in the corpus.",
            "- There are no mixed-or-other EKU combinations and no certificates missing EKU entirely.",
        ]
    )
    lines.append("")
    lines.append("## Chapter 4: Historical Renewal, Drift, and Red Flags")
    lines.append("")
    lines.append("**Management Summary**")
    lines.append("")
    lines.extend(
        [
            f"- Looking across expired and current history, the corpus contains {historical_count} leaf certificates; {historical_current_count} of them are still valid today.",
            f"- {repeated_cn_count} Subject CN values recur over time rather than appearing as one-off singletons.",
            f"- {assessment.normal_reissuance_assets} renewal families look operationally normal: predecessor and successor overlap for fewer than 50 days.",
            f"- {len(assessment.overlap_current_rows)} names still show long overlap of 50 days or more today.",
            f"- {len(assessment.overlap_past_rows)} names showed the same long-overlap behaviour in the past, but not anymore in currently valid certificates.",
            f"- Current non-overlap anomalies are limited: {len(assessment.dn_current_rows)} live Subject DN drift cases, {len(assessment.vendor_current_rows)} live CA-family drift cases, and {len(assessment.san_current_rows)} live SAN-drift cases.",
            f"- Past-only fixed anomalies were broader: {len(assessment.dn_past_rows)} historical Subject DN drift cases, {len(assessment.vendor_past_rows)} historical CA-family drift cases, and {len(assessment.san_past_rows)} historical SAN-drift cases.",
        ]
    )
    lines.append("")
    lines.append("This chapter is the historical check on whether the current picture follows a clean renewal pattern. It answers a different question from the current-corpus chapters above: not just what certificates exist now, but how the hostname estate has behaved over time.")
    lines.append("")
    lines.append("For this chapter, a renewal family means repeated certificates that keep the same apparent identity over time: the same Subject CN, the same full Subject DN, the same SAN profile, and the same CA family. A normal renewal reissues that same apparent certificate identity with a new key and a new validity span, and predecessor and successor overlap only briefly. In this monograph, anything below 50 days of overlap is treated as normal. Fifty days or more is treated as a red flag. COMODO and Sectigo are treated as one CA family from the outset, so movement between those names is not counted here as CA-family drift.")
    lines.append("")
    lines.append("A red flag in this chapter is not the same thing as a breach or a compromise. It means the certificate history diverged from the clean rollover pattern that one would normally expect and therefore deserves closer review.")
    lines.append("")
    lines.append("### Current Red-Flag Inventory")
    lines.append("")
    if assessment.current_red_flag_rows:
        lines.extend(
            md_table(
                ["Subject CN", "Live Certs", "Current Concern", "Immediate Supporting Context"],
                [
                    [
                        row.subject_cn,
                        str(row.current_certificate_count),
                        row.flags,
                        truncate_text(row.notes, 72),
                    ]
                    for row in assessment.current_red_flag_rows[:25]
                ],
            )
        )
    else:
        lines.append("No current red flags were found under the configured rules.")
    lines.append("")
    lines.append("### Past Red Flags Now Fixed")
    lines.append("")
    if assessment.past_red_flag_rows:
        lines.extend(
            md_table(
                ["Subject CN", "Historic Certs", "Historical Concern", "Immediate Supporting Context"],
                [
                    [
                        row.subject_cn,
                        str(row.certificate_count),
                        row.flags,
                        truncate_text(row.notes, 72),
                    ]
                    for row in assessment.past_red_flag_rows[:25]
                ],
            )
        )
    else:
        lines.append("No past-only red flags were found under the configured rules.")
    lines.append("")
    lines.append("### What The Historical Red Flags Mean")
    lines.append("")
    lines.append("The two short tables above are screening tables. They answer which names deserve attention now, and which names used to be problematic but no longer look live. The appendices below keep the narrower evidence tables that explain why each name is there.")
    lines.append("")
    lines.extend(
        [
            f"- **Overlap red flag**: a predecessor and successor inside the same renewal family coexist for 50 days or more. Current cases: {len(assessment.overlap_current_rows)}. Past-only fixed cases: {len(assessment.overlap_past_rows)}.",
            f"- **Subject DN drift**: the same Subject CN appears under more than one full Subject DN. In plain terms, the headline hostname is being issued under different formal subject identities. Current cases: {len(assessment.dn_current_rows)}. Past-only fixed cases: {len(assessment.dn_past_rows)}.",
            f"- **CA-family drift**: the same Subject CN appears under more than one CA family, after collapsing COMODO and Sectigo together. Current cases: {len(assessment.vendor_current_rows)}. Past-only fixed cases: {len(assessment.vendor_past_rows)}.",
            f"- **SAN drift**: the same Subject CN appears with more than one SAN profile. In plain terms, the hostname keeps being bundled with different companion names. Current cases: {len(assessment.san_current_rows)}. Past-only fixed cases: {len(assessment.san_past_rows)}.",
            f"- **Exact issuer-name changes** inside one CA family also exist: {len(assessment.issuer_rows)} Subject CN values. Those are tracked as context, not as first-order red flags.",
        ]
    )
    lines.append("")
    lines.append("### Historical Step Changes")
    lines.append("")
    lines.extend(
        [
            f"- Top issuance start dates: {', '.join(f'{row.start_day} ({row.certificate_count})' for row in assessment.day_rows[:6])}.",
            f"- Strong step weeks: {', '.join(f'{row.week_start} ({row.certificate_count} vs prior avg {row.prior_eight_week_avg})' for row in assessment.week_rows[:4]) or 'none'}.",
            "- These bursts matter because they show where certificate behaviour was driven by platform-scale operations rather than one-off manual issuance.",
        ]
    )
    lines.append("")
    lines.append("## Chapter 5: Naming Architecture")
    lines.append("")
    lines.append("**Management Summary**")
    lines.append("")
    lines.extend(
        [
            f"- Numbered CN families: {len(report['numbered_groups'])}.",
            f"- Multi-zone SAN sets: {report['multi_zone_hit_count']}.",
            f"- Frequent naming tokens: {', '.join(f'{token} ({count})' for token, count in report['top_env_tokens'][:8])}.",
            "- The strongest naming signals come from numbered rails, environment markers, cross-brand labels, and cross-zone SAN composition. `www` is weak evidence either way.",
        ]
    )
    lines.append("")
    lines.append("What looks arbitrary at first glance is usually the result of different naming pressures colliding. Customer-facing naming wants short memorable brands. Platform naming wants stable operational rails. Delivery naming wants environment labels, release slots, or fleet indices. Migration naming preserves old labels because changing a working name can be risky and expensive.")
    lines.append("")
    lines.append("### How To Read The Names")
    lines.append("")
    lines.extend(
        [
            "- In most of these names, the left-most label tells you the endpoint role, node slot, or environment slice, while the zone on the right tells you which public namespace the service is answering under.",
            "- Standard delivery shorthand appears throughout the corpus: `dev`, `qa`, `uat`, `sit`, `stg`, `preprod`, and `prod` are ordinary environment markers rather than mysterious product names.",
            "- `www` is a weak signal both when present and when absent. Its presence often reflects compatibility, redirect history, or old web conventions; its absence does not imply any deeper architectural distinction.",
            "- In this corpus, `nwg` reads as NatWest Group shorthand. Names like `rbs`, `natwest`, `ulsterbank`, `lombard`, `natwestpayments`, `coutts`, and `nwgwealth` are best read as parallel business or service namespaces within a wider shared estate, not as random unrelated domains.",
            "- Some short forms remain inferential rather than provable. For example, `nft` clearly behaves like a non-production stage label, but Certificate Transparency alone cannot prove the local expansion used inside the company.",
        ]
    )
    lines.append("")
    lines.append("### Key Pattern Examples")
    lines.append("")
    lines.append("These four boxes are not four isolated hostnames. Each one uses a concrete Subject CN as the evidence anchor for a broader naming methodology that appears elsewhere in the estate as well.")
    lines.append("")
    for example in report["examples"]:
        lines.append(f"#### {example.title}")
        lines.append("")
        lines.append(f"- Pattern shown: {example_pattern_label(example.title)}.")
        lines.append(f"- Concrete example: `{example.subject_cn}`")
        lines.append(f"- What this proves: {example.why_it_matters}")
        for point in example.evidence:
            lines.append(f"- Evidence: {point}")
        lines.append("")
    lines.append("### Why These Four Examples")
    lines.append("")
    lines.append("Taken together, these four examples explain most of the naming behaviour in the corpus. The first shows platform fleet naming, the second shows environment-and-release naming, the third shows cross-brand namespace splicing and migration residue, and the fourth shows shared-service bridging across several business namespaces.")
    lines.append("")
    lines.append("## Chapter 6: DNS Delivery Architecture")
    lines.append("")
    lines.append("**Management Summary**")
    lines.append("")
    lines.extend(
        [
            f"- Most names resolve indirectly: {alias_to_address_count} public names first point to another hostname and only then reach an address, while only {direct_address_count} names resolve straight to an address.",
            f"- The most common public DNS outcomes are Adobe Campaign in front of AWS load-balancing ({report['dns_stack_counts'].get('Adobe Campaign -> AWS ALB', 0)}), Adobe Campaign in front of AWS CloudFront ({report['dns_stack_counts'].get('Adobe Campaign -> AWS CloudFront', 0)}), and plain AWS CloudFront without an Adobe layer ({report['dns_stack_counts'].get('AWS CloudFront', 0)}).",
            f"- Smaller but still meaningful subsets behave like managed API fronts or specialist application platforms: Google Apigee ({report['dns_stack_counts'].get('Google Apigee', 0)}) and Pega Cloud on AWS ({report['dns_stack_counts'].get('Pega Cloud -> AWS ALB', 0)}).",
            f"- Some certificate names do not lead to a live public endpoint today: {nxdomain_count} do not exist in public DNS at all, {dangling_count} still exist only as broken aliases, and {no_data_count} exist in DNS but returned no public A or AAAA address during the scan.",
        ]
    )
    lines.append("")
    lines.append("DNS is the public routing layer. It does not tell you everything about an application, but it does tell you where a public name lands: directly on an IP, through an alias chain, through a CDN, through an API gateway, or onto a specialist platform.")
    lines.append("")
    lines.append("This chapter does not claim to know the full private architecture behind each service. It only claims what the public DNS trail supports. For each DNS SAN name in the certificate corpus, the scanner queried public `CNAME`, `A`, `AAAA`, and `PTR` data. It then summarized that public answer trail with a short label. Those labels are not arbitrary brand names invented by the report; they are compact descriptions of what the public DNS evidence most strongly suggests.")
    lines.append("")
    lines.append("One important caution follows from that last bullet: a hostname can remain visible in certificate history even after its public DNS has been removed or partially dismantled. Certificate history and current DNS are related, but they do not move in lockstep.")
    lines.append("")
    lines.append("### How The DNS Evidence Is Read")
    lines.append("")
    lines.extend(
        [
            "- A `CNAME` shows that one public name is really an alias for another public name.",
            "- The terminal hostname, returned addresses, and reverse-DNS names often reveal platform clues such as `cloudfront.net`, `elb.amazonaws.com`, `apigee.net`, or `campaign.adobe.com`.",
            "- The report combines the answer shape and those clues into one short description. For example, `Adobe Campaign -> AWS ALB` means the alias chain contains Adobe Campaign naming and the terminal clues point to AWS load-balancing infrastructure.",
            "- These labels are therefore evidence summaries, not claims of legal ownership or full internal design.",
        ]
    )
    lines.append("")
    lines.append("### What The Public DNS Names Resolve To")
    lines.append("")
    lines.extend(md_table(["Observed DNS Outcome", "Count", "Plain-Language Meaning"], dns_pattern_rows))
    lines.append("")
    lines.append("### Why Each DNS Label Was Used")
    lines.append("")
    for label, _count in top_dns_patterns[:6]:
        lines.append(f"- **{label}**: {delivery_pattern_rule(label)}")
    lines.append("")
    lines.append("### Platform And DNS Glossary")
    lines.append("")
    glossary = ct_dns_utils.provider_explanations()
    for term in ["Adobe Campaign", "AWS", "AWS ALB", "AWS CloudFront", "Google Apigee", "Pega Cloud", "Microsoft Edge", "Infinite / agency alias", "CNAME", "A record", "AAAA record", "PTR record", "NXDOMAIN"]:
        lines.append(f"- **{term}**: {glossary[term]}")
    lines.append("")
    lines.append("The glossary terms above are the building blocks used in the DNS-outcome table. This is also why the management summary mentions Adobe Campaign, CloudFront, Apigee, and Pega at all: not because brand names are the point, but because those names reveal what kind of public delivery role a hostname is landing on. CloudFront suggests a distribution edge, Apigee suggests managed API exposure, Adobe Campaign suggests a marketing or communications front, and a load balancer suggests traffic distribution to backend services.")
    lines.append("")
    lines.append("The next chapter stays with the same names but moves from delivery to control. This chapter asked where public traffic lands. The next one asks which public CA families DNS currently authorizes to issue for those same names.")
    lines.append("")
    lines.append("## Chapter 7: DNS Issuance Policy Control (CAA)")
    lines.append("")
    lines.append("**Management Summary**")
    lines.append("")
    for zone in caa_analysis.configured_domains:
        zone_rows = ct_caa_analysis.rows_for_zone(caa_analysis, zone)
        unrestricted_count = sum(1 for row in zone_rows if not row.allowed_ca_families)
        mismatch_count = sum(1 for row in zone_rows if row.current_policy_mismatch)
        overlap_count = sum(1 for row in zone_rows if row.current_multi_family_overlap)
        dominant_policy = ct_caa_analysis.policy_counter(zone_rows).most_common(1)
        dominant_label = caa_policy_label(dominant_policy[0][0]) if dominant_policy else "none"
        lines.append(
            f"- `{zone}`: {len(zone_rows)} names in scope; dominant policy is {dominant_label}; unrestricted names={unrestricted_count}; current policy-mismatch names={mismatch_count}; current multi-family overlap names={overlap_count}."
        )
    lines.extend(
        [
            f"- Effective CAA discovery paths across all names: {', '.join(f'{caa_source_label(kind)}={count}' for kind, count in caa_analysis.source_kind_counts.most_common())}.",
            f"- Current names simultaneously covered by more than one live CA family: {len(caa_analysis.multi_family_overlap_names)}.",
            f"- Current names whose live certificate family does not match today's published CAA policy: {len(caa_analysis.policy_mismatch_names)}.",
        ]
    )
    lines.append("")
    lines.append("CAA is the DNS control layer for public certificate issuance. It does not validate a certificate after issuance; instead, it tells a public CA which CA families are authorized to issue for a DNS name if any restriction is published at all. If no CAA is published, WebPKI issuance is unrestricted from the DNS-policy point of view.")
    lines.append("")
    lines.append("This chapter is the control-plane counterpart to the certificate and DNS chapters. The certificate chapter showed who actually issued. The DNS chapter showed where the names land. The CAA chapter shows which issuers the DNS owner currently allows for those same names.")
    lines.append("")
    lines.append("That distinction matters because hosting and issuance are different decisions. A name can land on AWS and still use a Sectigo-family certificate if DNS policy allows it. A name can also resolve through a vendor platform while still inheriting a first-party corporate CAA policy. The point of this chapter is to show where those decisions line up and where they do not.")
    lines.append("")
    lines.append("CAA is checked per DNS name requested in the certificate, not per Subject DN and not per organisational story. A Subject CN can therefore shift between different Subject DN values without creating a CAA clash, because CAA ignores organisation fields and looks only at the DNS names being certified.")
    lines.append("")
    lines.append("### Why CAA Matters In This Estate")
    lines.append("")
    lines.extend(
        [
            "- If a name has no CAA, DNS is not constraining which public CA family may issue for it.",
            "- If a name inherits a broad corporate policy, that usually means the organisation has left normal brand-facing names under a common default.",
            "- If a name falls under a narrower subtree or alias-derived policy, that is evidence of more deliberate platform or vendor-specific issuance control.",
            "- If a live certificate family sits outside today's CAA policy, or if the same DNS name is live under two CA families at once, that usually points to migration lag, overlapping rollout, or policy that moved faster than certificate cleanup.",
        ]
    )
    lines.append("")
    lines.append("### How To Read The CAA Results")
    lines.append("")
    lines.extend(md_table(["CAA Discovery Result", "Names", "Meaning"], caa_source_rows(caa_analysis)))
    lines.append("")
    lines.append("The key distinction is between ordinary parent inheritance and alias-target-derived policy. Parent inheritance means the leaf name simply relies on a policy published higher in its own DNS tree. Alias-target-derived policy means the effective CAA surfaced through an alias response. In this corpus, that often marks a managed rail or specialist external platform rather than a plain brand-front hostname.")
    lines.append("")
    lines.append("In practical terms, most names in this corpus fall into three shapes: inherited corporate policy, alias-driven managed-platform policy, or no CAA at all. That three-way split is more important than the mechanics themselves, because it shows where issuance control is broad, where it is deliberately narrow, and where it is absent.")
    lines.append("")
    lines.append("### Policy Regimes By Configured Zone")
    lines.append("")
    for zone in caa_analysis.configured_domains:
        lines.append(f"#### `{zone}`")
        lines.append("")
        lines.extend(md_table(["Policy Regime", "Names", "Plain-Language Meaning"], caa_zone_rows[zone]))
        lines.append("")
    if secondary_zone:
        lines.append(f"The contrast between `{primary_zone}` and `{secondary_zone}` is one of the strongest PKI-governance findings in the corpus. `{primary_zone}` is policy-layered and governed, while `{secondary_zone}` is currently CAA-empty in the scanned name set. That does not make `{secondary_zone}` invalid, but it does mean DNS is not constraining public CA choice there.")
        lines.append("")
        lines.append(f"That asymmetry matters more than any one record. `{primary_zone}` looks like a namespace where DNS is being used as an issuance-governance tool. `{secondary_zone}` looks like a namespace where issuance choice is still being handled outside DNS policy, or not being constrained at all.")
        lines.append("")
    lines.append("### How CAA Changes The Reading Of The Estate")
    lines.append("")
    lines.extend(
        [
            "- The CAA layer strengthens the earlier certificate-and-DNS thesis rather than overturning it. The same service families that already looked like shared managed rails from naming and DNS often sit under narrower issuance policy as well.",
            f"- In `{primary_zone}`, the current CAA friction is concentrated rather than diffuse: {caa_concentration_text(caa_analysis, primary_zone)}.",
            "- Broad corporate default policy remains visible on many ordinary brand-facing names. That supports the earlier reading that not every public hostname was moved onto one tightly managed delivery rail.",
            "- Narrower or alias-driven CAA policy appears where the DNS evidence already suggested a managed platform, campaign rail, or vendor-mediated service surface.",
            "- Vendor-style exceptions still exist. Where a name resolves through a specialist external platform and the allowed CA set widens or changes shape, the policy layer supports the earlier vendor-delegation reading rather than contradicting it.",
            "- The chapter therefore adds a governance gradient to the earlier thesis: some parts of the estate are tightly steered, some inherit a broad default, and some are still policy-empty.",
        ]
    )
    lines.append("")
    lines.append("### Why The Next Two Tables Matter")
    lines.append("")
    lines.extend(
        [
            "- The overlap table shows where an old and a new issuance regime are both still live on the same DNS name.",
            "- The mismatch table shows where today's DNS policy has already moved, but one or more live certificates still reflect the older state.",
            "- Read them together, not separately. Together they show whether the estate looks diffusely messy or whether the untidy parts cluster in a small transition zone.",
        ]
    )
    lines.append("")
    lines.append("### Current Multi-Family Overlap")
    lines.append("")
    if caa_analysis.multi_family_overlap_names:
        lines.extend(md_table(["DNS Name", "Zone", "Live CA Families", "Covering Subject CNs"], top_caa_overlap_rows(caa_analysis)))
    else:
        lines.append("No current multi-family overlap names were found.")
    lines.append("")
    lines.append("These overlap names are operationally important. They show where the same public DNS name is currently covered by more than one live CA family at once. In this corpus, that behavior clusters tightly in a few service families rather than being spread randomly across the estate.")
    lines.append("")
    lines.append("### Current Policy Mismatch")
    lines.append("")
    if caa_analysis.policy_mismatch_names:
        lines.extend(md_table(["DNS Name", "Zone", "Live CA Families", "CAA-Allowed Families", "CAA Discovery Result"], top_caa_mismatch_rows(caa_analysis)))
    else:
        lines.append("No current policy-mismatch names were found.")
    lines.append("")
    lines.append("A current policy mismatch does not automatically prove CA misissuance. CAA only proves what DNS authorizes now. Certificates can remain valid after the DNS-side policy has changed, so the right reading here is current policy lag or migration residue unless the historical issuance-time DNS can also be shown.")
    lines.append("")
    lines.append("Taken together, the overlap and mismatch tables support a migration reading more than a disorder reading. If the estate were simply chaotic, the live friction would be spread widely across unrelated names. Instead, it clusters in a small number of service families that were already prominent in the certificate and DNS chapters.")
    lines.append("")
    if focus_analysis:
        lines.append("## Chapter 8: Focused Subject-CN Cohort")
        lines.append("")
        lines.append("**Management Summary**")
        lines.append("")
        lines.extend(
            [
                f"- The focused cohort contains {focus_analysis.provided_subjects_count} analyst-selected Subject CN values. {focus_analysis.historically_seen_subjects_count} are visible somewhere in the historical CT corpus, and {focus_analysis.current_direct_subjects_count} still have direct current certificates.",
                f"- The current focused cohort is structurally different from the rest of the estate: all {focus_analysis.current_focus_certificate_count} current focused certificates are Sectigo/COMODO-lineage, compared with {counter_text(focus_analysis.rest_current_issuer_families, 3)} in the rest of the corpus.",
                f"- The focused cohort uses much smaller certificates: median SAN size {focus_analysis.focus_median_san_entries} versus {focus_analysis.rest_median_san_entries}, and {focus_analysis.focus_multi_zone_certificate_count} current multi-zone certificates versus {focus_analysis.rest_multi_zone_certificate_count} outside the cohort.",
                f"- Revocation churn is much higher inside the focused cohort: {focus_analysis.focus_revoked_current_count} revoked versus {focus_analysis.focus_not_revoked_current_count} not revoked ({focus_analysis.focus_revoked_share}), compared with {focus_analysis.rest_revoked_current_count} versus {focus_analysis.rest_not_revoked_current_count} ({focus_analysis.rest_revoked_share}) outside the cohort.",
                f"- Cross-basket carrying is limited rather than universal. The count of focused entries that appear today only as SAN passengers is {focus_analysis.current_carried_only_subjects_count}, and the count ever seen as SAN passengers inside non-focused certificates at all is {focus_analysis.historical_non_focus_carried_subjects_count}.",
                f"- The cohort splits into three naming buckets rather than one uniform style: {focus_analysis.bucket_counts.get('direct_front_door', 0)} front-door direct names, {focus_analysis.bucket_counts.get('platform_matrix_anchor', 0)} platform-anchor matrix names, and {focus_analysis.bucket_counts.get('ambiguous_legacy', 0)} ambiguous or legacy-residue names.",
            ]
        )
        lines.append("")
        lines.append("This chapter treats the supplied Subject-CN list as an analyst-guided cohort rather than as a neutral statistical sample. The question is not whether these names are the most common names in the estate. The question is why they were memorable enough to be singled out, and whether the certificate and DNS evidence shows that they belong to a different naming and hosting tradition.")
        lines.append("")
        lines.append("The short answer is yes, but not because the cohort is perfectly uniform. The cohort is different from the wider estate because it is weighted toward remembered public fronts and remembered platform anchors, not toward the Amazon-heavy operational rail population that dominates the broader corpus.")
        lines.append("")
        lines.append("### Focused Cohort Versus The Rest Of The Estate")
        lines.append("")
        lines.extend(md_table(["Comparison View", "Focused Cohort", "Rest Of Current Corpus", "Why It Matters"], focus_comparison))
        lines.append("")
        lines.append("### Three Buckets Inside The Cohort")
        lines.append("")
        lines.extend(md_table(["Bucket", "Count", "Representative Names", "What It Looks Like", "Why This Bucket Exists"], focus_bucket_summary))
        lines.append("")
        lines.append("This bucket split is the key to making the cohort intelligible. The memorable names are not all from one naming methodology. Most are direct public fronts. A very small number are platform-anchor certificates with matrix SAN design. The rest are historical leftovers, carried aliases, or opaque labels whose original role is no longer cleanly visible in the current corpus.")
        lines.append("")
        lines.append("### Why This Cohort Feels Different")
        lines.append("")
        lines.extend(
            [
                "- The dominant bucket is the front-door direct bucket. These are small-SAN certificates attached to memorable service, identity, vendor, or brand-like names directly under the branded public zones configured for the scan.",
                "- The platform-anchor bucket is tiny but important. These names carry large SAN matrices that spell out environment, tenant, service-cell, or monitoring coverage, which is exactly what one would expect from a centrally managed operational platform slice.",
                "- The ambiguous bucket matters because it explains the leftover rough edges. These names may be historical-only, partly migrated into other certificates, or too opaque to decode confidently from public evidence alone.",
                "- The public DNS evidence for the current focused Subject CN names is also different. The cohort lands much more often on direct addresses or simple direct AWS clues, while the wider current Subject-CN population is much more dominated by Adobe-managed, Apigee-managed, or NXDOMAIN outcomes.",
                "- Historical red flags are common in the cohort, but they are mostly past rather than current. That is consistent with a legacy or manually managed public-web slice that has been cleaned up over time rather than with a currently chaotic platform core.",
            ]
        )
        lines.append("")
        lines.append("Seen this way, the cohort makes sense. It looks like a remembered estate made of two high-visibility extremes: public-facing service fronts that humans remember because customers and staff encounter them directly, and a small number of operational anchor names that humans remember because administrators, testers, or engineers encounter them repeatedly. The ambiguous bucket is the residue between those two poles.")
        lines.append("")
        lines.append("### Cross-Basket Carrying And Migration")
        lines.append("")
        if focus_analysis.transition_rows:
            lines.extend(
                md_table(
                    ["Subject CN", "Current Basket Status", "Direct/Carried", "Max Direct-To-Carrier Overlap", "Carrier Subjects"],
                    [
                        [
                            detail.subject_cn,
                            detail.basket_status,
                            f"{detail.current_direct_certificates}/{detail.current_non_focus_san_carriers + detail.historical_non_focus_san_carriers}",
                            str(detail.max_direct_to_carrier_overlap_days),
                            truncate_text(detail.carrier_subjects, 48),
                        ]
                        for detail in focus_analysis.transition_rows[:10]
                    ],
                )
            )
        else:
            lines.append("No focused names were seen as SAN passengers inside non-focused certificates.")
        lines.append("")
        lines.append("This migration table answers a narrower question than the rest of the chapter. It asks whether these names were gradually absorbed into broader certificates from outside the cohort. The answer is: only in a limited number of cases. Some names do show SAN-passenger behavior or historical carrying, but that is not the dominant explanation for why the cohort feels different. The dominant explanation is the bucket split above: many remembered direct fronts, a few large platform anchors, and a band of legacy residue.")
        lines.append("")
        lines.append("### Representative Names By Bucket")
        lines.append("")
        lines.extend(md_table(["Bucket", "Subject CN", "Observed Role", "Current/Historical Direct", "Why It Helps Explain The Bucket"], focus_representatives))
        lines.append("")
        lines.append("These examples are evidence anchors, not the whole population. The direct-front examples show the remembered public surface. The platform-anchor examples show the rare but important matrix certificates. The ambiguous examples show why the cohort cannot be reduced to a single neat story without losing the migration and legacy residue that made these names memorable in the first place.")
        lines.append("")
    lines.append(f"## Chapter {synthesis_chapter}: Making The Whole Estate Make Sense")
    lines.append("")
    lines.append("**Management Summary**")
    lines.append("")
    lines.extend(
        [
            "- The certificate, DNS, and CAA layers are not three separate stories. They are three views of the same operating estate.",
            "- Naming shows role and organisational memory; DNS shows where traffic lands; CAA shows how tightly issuance is governed.",
            "- Clean public brand names usually sit closest to the customer surface, while dense SAN sets, numbered families, multi-zone certificates, and narrower CAA policy usually expose the shared platform layer beneath them.",
            "- When the layers disagree, the disagreement usually signals migration or uneven governance maturity rather than a flat contradiction.",
            "- The overall shape is more consistent with a federated operating model with uneven governance maturity than with random hostname sprawl.",
        ]
    )
    lines.append("")
    lines.append("The common ground is operational reality. A branded proposition wants recognisable names. A service team wants a stable endpoint namespace. A platform team wants shared rails and repeatable delivery machinery. A hosting team wants routable front doors that can land on cloud distribution, gateways, or workflow platforms. A security or PKI function wants some names tightly governed and other names left broad or delegated. Certificates, DNS, and CAA tell the same estate story from different angles.")
    lines.append("")
    lines.append("A useful way to combine the layers is to ask four questions in order. First, what does the name itself look like: a direct front door, a numbered rail, an environment slice, or a bridge across business zones? Second, how broad is the SAN set: is this one visible service or a bundled platform certificate? Third, where does public DNS actually land the name: direct host, CDN edge, API gateway, campaign rail, or specialist platform? Fourth, does DNS issuance policy stay broad, narrow sharply, or disappear entirely?")
    lines.append("")
    lines.append("When those answers align, the reading becomes strong. A small-SAN branded name with ordinary inherited policy reads like a direct public front. A dense multi-zone certificate with numbered families, managed DNS landing, and narrower CAA reads like a shared operational rail. A name that lands on AWS but still uses a Sectigo-family certificate shows that hosting choice and CA choice are separate decisions. A name with current overlap and current policy mismatch shows a transition area where the newer issuance model is already in place but the older certificate state has not fully disappeared.")
    lines.append("")
    lines.append("This is why the estate can look both tidy and messy at once. It is tidy within each layer, but messy across layers because the layers are solving different problems. The new CAA evidence sharpens that point rather than contradicting it: the managed rail families are not only named and hosted differently, they are often policy-controlled differently as well. The biggest qualification is that governance is uneven. The primary configured zone shows layered issuance control, while another configured zone remains CAA-empty. That is not random chaos, but it is also not uniform control maturity.")
    lines.append("")
    lines.append(f"## Chapter {limits_chapter}: Limits, Confidence, and Noise")
    lines.append("")
    lines.append("**Management Summary**")
    lines.append("")
    lines.extend(
        [
            "- High-confidence claims are the ones tied directly to observable certificate fields, DNS answers, trust records, and current CAA policy.",
            "- Medium-confidence claims are organisational readings drawn from repeated technical patterns.",
            "- Lower-confidence claims are exact expansions of abbreviations or exact internal ownership boundaries.",
            "- Some DNS names do not resolve publicly today; that does not invalidate the certificate-side evidence because certificate and DNS timelines are not identical.",
            "- A current CAA mismatch does not by itself prove historical CA non-compliance, because DNS policy may have changed after issuance.",
        ]
    )
    lines.append("")
    lines.append("A useful way to read the corpus is to separate signal from noise. Repeated naming schemas are signal. Repeated DNS outcomes are signal. Which public CA family keeps issuing a name is signal. Where CAA is broad, narrow, delegated, or absent is signal. Simple `www` presence or absence is weak evidence either way unless it coincides with stronger differences such as distinct DNS routing, distinct SAN composition, a distinct certificate renewal history, or a distinct issuance-policy shape.")
    lines.append("")
    lines.append("## Appendix A: Full Family Catalogue")
    lines.append("")
    lines.append("This appendix is a compact family map. It is not the place for full per-certificate evidence; that remains in the detailed inventory appendix at the end.")
    lines.append("")
    lines.extend(md_table(["Family Basis", "Certs", "CNs", "Dominant Stack"], family_rows))
    lines.append("")
    lines.append("## Appendix B: Historical Red-Flag Detail")
    lines.append("")
    lines.append("This appendix keeps the detailed historical evidence inside the monograph so that the reader does not need a second report. Each subsection answers one narrow question. If a column does not help answer that question, it has been removed.")
    lines.append("")
    lines.append("In this appendix, a *renewal family* means repeated certificates that keep the same apparent identity over time: the same Subject CN, the same full Subject DN, the same SAN profile, and the same CA family.")
    lines.append("")
    lines.append("### B.1 Current Red-Flag Inventory")
    lines.append("")
    if assessment.current_red_flag_rows:
        lines.extend(
            md_table(
                ["Subject CN", "Live Certs", "Current Concern", "Supporting Context"],
                [
                    [
                        row.subject_cn,
                        str(row.current_certificate_count),
                        row.flags,
                        truncate_text(row.notes, 84),
                    ]
                    for row in assessment.current_red_flag_rows
                ],
            )
        )
    else:
        lines.append("No current red flags were found.")
    lines.append("")
    lines.append("### B.2 Past Red-Flag Inventory Now Fixed")
    lines.append("")
    if assessment.past_red_flag_rows:
        lines.extend(
            md_table(
                ["Subject CN", "Historic Certs", "Historical Concern", "Supporting Context"],
                [
                    [
                        row.subject_cn,
                        str(row.certificate_count),
                        row.flags,
                        truncate_text(row.notes, 84),
                    ]
                    for row in assessment.past_red_flag_rows
                ],
            )
        )
    else:
        lines.append("No past-only red flags were found.")
    lines.append("")
    lines.append("### B.3 Current Overlap Red Flags")
    lines.append("")
    if assessment.overlap_current_rows:
        lines.extend(
            md_table(
                ["Subject CN", "Max Overlap Days", "Live Certs", "What The Renewal Family Looks Like"],
                [
                    [
                        row.subject_cn,
                        str(row.max_overlap_days),
                        str(row.current_certificate_count),
                        f"{row.lineage}; {overlap_signal(row.details)}",
                    ]
                    for row in assessment.overlap_current_rows
                ],
            )
        )
    else:
        lines.append("No current overlap red flags were found.")
    lines.append("")
    lines.append("### B.4 Past Overlap Red Flags Now Fixed")
    lines.append("")
    if assessment.overlap_past_rows:
        lines.extend(
            md_table(
                ["Subject CN", "Max Overlap Days", "Historic Certs", "What The Renewal Family Looks Like"],
                [
                    [
                        row.subject_cn,
                        str(row.max_overlap_days),
                        str(row.asset_variant_count),
                        f"{row.lineage}; {overlap_signal(row.details)}",
                    ]
                    for row in assessment.overlap_past_rows
                ],
            )
        )
    else:
        lines.append("No past overlap red flags were found.")
    lines.append("")
    lines.append("### B.5 Current Subject DN Drift")
    lines.append("")
    if assessment.dn_current_rows:
        lines.extend(
            md_table(
                ["Subject CN", "Distinct Subject DNs", "Live Certs", "Subject DN Samples"],
                [
                    [
                        row.subject_cn,
                        str(row.distinct_value_count),
                        str(row.current_certificate_count),
                        truncate_text(row.details, 92),
                    ]
                    for row in assessment.dn_current_rows
                ],
            )
        )
    else:
        lines.append("No current Subject DN drift was found.")
    lines.append("")
    lines.append("### B.6 Past Subject DN Drift Now Fixed")
    lines.append("")
    if assessment.dn_past_rows:
        lines.extend(
            md_table(
                ["Subject CN", "Distinct Subject DNs", "Historic Certs", "Subject DN Samples"],
                [
                    [
                        row.subject_cn,
                        str(row.distinct_value_count),
                        str(row.certificate_count),
                        truncate_text(row.details, 92),
                    ]
                    for row in assessment.dn_past_rows
                ],
            )
        )
    else:
        lines.append("No past-only Subject DN drift was found.")
    lines.append("")
    lines.append("### B.7 Current CA-Family Drift")
    lines.append("")
    if assessment.vendor_current_rows:
        lines.extend(
            md_table(
                ["Subject CN", "Distinct CA Families", "Live Certs", "CA Families Seen"],
                [
                    [
                        row.subject_cn,
                        str(row.distinct_value_count),
                        str(row.current_certificate_count),
                        truncate_text(row.details, 92),
                    ]
                    for row in assessment.vendor_current_rows
                ],
            )
        )
    else:
        lines.append("No current CA-family drift was found.")
    lines.append("")
    lines.append("### B.8 Past CA-Family Drift Now Fixed")
    lines.append("")
    if assessment.vendor_past_rows:
        lines.extend(
            md_table(
                ["Subject CN", "Distinct CA Families", "Historic Certs", "CA Families Seen"],
                [
                    [
                        row.subject_cn,
                        str(row.distinct_value_count),
                        str(row.certificate_count),
                        truncate_text(row.details, 92),
                    ]
                    for row in assessment.vendor_past_rows
                ],
            )
        )
    else:
        lines.append("No past-only CA-family drift was found.")
    lines.append("")
    lines.append("### B.9 Current SAN Drift")
    lines.append("")
    if assessment.san_current_rows:
        lines.extend(
            md_table(
                ["Subject CN", "SAN Profiles", "Live Certs", "Delta Pattern", "Representative Delta"],
                [
                    [
                        row.subject_cn,
                        str(row.distinct_san_profiles),
                        str(row.current_certificate_count),
                        row.delta_pattern,
                        truncate_text(row.representative_delta, 92),
                    ]
                    for row in assessment.san_current_rows
                ],
            )
        )
    else:
        lines.append("No current SAN drift was found.")
    lines.append("")
    lines.append("### B.10 Past SAN Drift Now Fixed")
    lines.append("")
    if assessment.san_past_rows:
        lines.extend(
            md_table(
                ["Subject CN", "SAN Profiles", "Historic Certs", "Delta Pattern", "Representative Delta"],
                [
                    [
                        row.subject_cn,
                        str(row.distinct_san_profiles),
                        str(row.certificate_count),
                        row.delta_pattern,
                        truncate_text(row.representative_delta, 92),
                    ]
                    for row in assessment.san_past_rows
                ],
            )
        )
    else:
        lines.append("No past-only SAN drift was found.")
    lines.append("")
    lines.append("### B.11 Historic Start Dates")
    lines.append("")
    lines.extend(
        md_table(
            ["Start Day", "Certificates", "Dominant Driver"],
            [[row.start_day, str(row.certificate_count), driver_summary(row.top_subjects, row.top_issuers)] for row in assessment.day_rows],
        )
    )
    lines.append("")
    lines.append("### B.12 Historic Step Weeks")
    lines.append("")
    if assessment.week_rows:
        lines.extend(
            md_table(
                ["Week Start", "Certificates", "Prior 8-Week Avg", "Dominant Driver"],
                [
                    [
                        row.week_start,
                        str(row.certificate_count),
                        row.prior_eight_week_avg,
                        driver_summary(row.top_subjects, row.top_issuers),
                    ]
                    for row in assessment.week_rows
                ],
            )
        )
    else:
        lines.append("No step weeks met the threshold.")
    lines.append("")
    lines.append(f"## Appendix {caa_appendix}: CAA Policy Detail")
    lines.append("")
    lines.append("This appendix keeps the issuance-policy evidence inside the monograph. It answers a narrower question than the DNS appendix: not where a name lands, but which public CA families DNS currently authorizes to issue for that name.")
    lines.append("")
    lines.append("### C.1 CAA Discovery Paths")
    lines.append("")
    lines.extend(md_table(["CAA Discovery Result", "Names", "Meaning"], caa_source_rows(caa_analysis)))
    lines.append("")
    lines.append("### C.2 Policy Regimes By Configured Zone")
    lines.append("")
    for zone in caa_analysis.configured_domains:
        lines.append(f"#### `{zone}`")
        lines.append("")
        lines.extend(md_table(["Policy Regime", "Names", "Plain-Language Meaning"], caa_zone_rows[zone]))
        lines.append("")
    lines.append("### C.3 Current Multi-Family Overlap")
    lines.append("")
    if caa_analysis.multi_family_overlap_names:
        lines.extend(md_table(["DNS Name", "Zone", "Live CA Families", "Covering Subject CNs"], top_caa_overlap_rows(caa_analysis, 40)))
    else:
        lines.append("No current multi-family overlap names were found.")
    lines.append("")
    lines.append("### C.4 Current Policy Mismatch")
    lines.append("")
    if caa_analysis.policy_mismatch_names:
        lines.extend(md_table(["DNS Name", "Zone", "Live CA Families", "CAA-Allowed Families", "CAA Discovery Result"], top_caa_mismatch_rows(caa_analysis, 40)))
    else:
        lines.append("No current policy-mismatch names were found.")
    lines.append("")
    if focus_analysis:
        lines.append(f"## Appendix {focus_appendix}: Focused Subject-CN Detail")
        lines.append("")
        lines.append("This appendix keeps the complete focused-cohort table inside the monograph, but it now follows the three-bucket taxonomy from Chapter 8. That makes it easier to read the cohort as a set of related naming traditions instead of as one flat mixed list.")
        lines.append("")
        appendix_buckets = [
            ("direct_front_door", "### D.1 Front-Door Direct Names"),
            ("platform_matrix_anchor", "### D.2 Platform-Anchor Matrix Names"),
            ("ambiguous_legacy", "### D.3 Ambiguous Or Legacy Residue"),
        ]
        for bucket, heading in appendix_buckets:
            rows = focus_appendix_rows(focus_analysis, bucket)
            lines.append(heading)
            lines.append("")
            lines.append(f"{ct_focus_subjects.taxonomy_bucket_label(bucket)} count: {focus_analysis.bucket_counts.get(bucket, 0)}.")
            lines.append("")
            if rows:
                lines.extend(
                    md_table(
                        [
                            "Subject CN",
                            "Bucket Rationale",
                            "Analyst Note",
                            "Observed Role",
                            "Direct C/H",
                            "Carried C/H",
                            "SANs C/H",
                            "Current DNS Outcome",
                            "Current Revocation Mix",
                            "Current Flags",
                            "Past Flags",
                        ],
                        rows,
                    )
                )
            else:
                lines.append("No subjects fell into this bucket.")
            lines.append("")
    lines.append(f"## Appendix {detailed_inventory_appendix}: Detailed Inventory Appendix")
    lines.append("")
    lines.append("The full issuer-first family inventory is reproduced below so that the monograph remains complete rather than merely interpretive.")
    lines.append("")
    lines.append(appendix_markdown)
    args.markdown_output.write_text("\n".join(lines) + "\n", encoding="utf-8")


def render_latex(
    args: argparse.Namespace,
    report: dict[str, object],
    assessment: ct_lineage_report.HistoricalAssessment,
    caa_analysis: ct_caa_analysis.CaaAnalysis,
    focus_analysis: ct_focus_subjects.FocusCohortAnalysis | None,
) -> None:
    args.latex_output.parent.mkdir(parents=True, exist_ok=True)
    hits = report["hits"]
    groups = report["groups"]
    purpose_summary = report["purpose_summary"]
    total_certificates = len(report["classifications"])
    issuer_trust = report["issuer_trust"]
    issuer_family_rows = build_issuer_family_rows(report)
    family_rows = [
        [
            compact_family_basis(row["basis"]),
            str(row["certificates"]),
            str(row["subjects"]),
            first_list_item(row["top_stacks"]),
        ]
        for row in report["group_digest"]
    ]
    dual_items = [item for item in report["classifications"] if item.category == "tls_server_and_client"]
    dual_issuer_counts = Counter(short_issuer(item.issuer_name) for item in dual_items)
    server_only_count = purpose_summary.category_counts.get("tls_server_only", 0)
    dual_count = purpose_summary.category_counts.get("tls_server_and_client", 0)
    server_only_issuer_families = collapse_issuer_counts_by_family(
        purpose_summary.issuer_breakdown.get("tls_server_only", {})
    )
    historical_count = len(assessment.certificates)
    historical_current_count = sum(1 for item in assessment.certificates if item.current)
    repeated_cn_count = historical_repeated_cn_count(assessment)
    purpose_rows = [
        (
            purpose_label(category),
            str(count),
            pct(count, total_certificates),
            purpose_meaning(category),
        )
        for category, count in [
            ("tls_server_only", purpose_summary.category_counts.get("tls_server_only", 0)),
            ("tls_server_and_client", purpose_summary.category_counts.get("tls_server_and_client", 0)),
            ("client_auth_only", purpose_summary.category_counts.get("client_auth_only", 0)),
            ("smime_only", purpose_summary.category_counts.get("smime_only", 0)),
            ("code_signing_only", purpose_summary.category_counts.get("code_signing_only", 0)),
            ("mixed_or_other", purpose_summary.category_counts.get("mixed_or_other", 0)),
            ("no_eku", purpose_summary.category_counts.get("no_eku", 0)),
        ]
    ]
    visible_purpose_rows = [(label, count, share, meaning) for label, count, share, meaning in purpose_rows if count != "0"]
    dns_class_counts = report["dns_class_counts"]
    alias_to_address_count = dns_class_counts.get("cname_to_address", 0)
    direct_address_count = dns_class_counts.get("direct_address", 0)
    nxdomain_count = dns_class_counts.get("nxdomain", 0)
    dangling_count = dns_class_counts.get("dangling_cname", 0)
    no_data_count = dns_class_counts.get("no_data", 0)
    top_dns_patterns = report["dns_stack_counts"].most_common(8)
    focus_comparison = focus_comparison_rows(focus_analysis) if focus_analysis else []
    focus_bucket_summary = focus_bucket_summary_rows(focus_analysis) if focus_analysis else []
    focus_representatives = focus_representative_rows(focus_analysis) if focus_analysis else []
    has_focus = focus_analysis is not None
    caa_zone_rows = {
        zone: caa_zone_policy_rows(caa_analysis, zone)
        for zone in caa_analysis.configured_domains
    }
    primary_zone = report["domains"][0] if report["domains"] else "configured primary zone"
    secondary_zone = report["domains"][1] if len(report["domains"]) > 1 else None
    appendix_pdf_path = args.appendix_pdf_output.resolve().as_posix()
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
        r"\usepackage{tabularx}",
        r"\usepackage{longtable}",
        r"\usepackage{needspace}",
        r"\usepackage{enumitem}",
        r"\usepackage{titlesec}",
        r"\usepackage[most]{tcolorbox}",
        r"\usepackage{pdfpages}",
        r"\defaultfontfeatures{Ligatures=TeX,Scale=MatchLowercase}",
        r"\definecolor{Ink}{HTML}{17202A}",
        r"\definecolor{Muted}{HTML}{667085}",
        r"\definecolor{Line}{HTML}{D0D5DD}",
        r"\definecolor{Panel}{HTML}{F8FAFC}",
        r"\definecolor{Accent}{HTML}{0F766E}",
        r"\hypersetup{colorlinks=true,linkcolor=Accent,urlcolor=Accent,pdfauthor={CertTransparencySearch},pdftitle={CT and DNS Monograph}}",
        r"\setlength{\parindent}{0pt}",
        r"\setlength{\parskip}{6pt}",
        r"\setlength{\emergencystretch}{4em}",
        r"\setlength{\footskip}{24pt}",
        r"\setlength{\tabcolsep}{4.2pt}",
        r"\renewcommand{\arraystretch}{1.12}",
        r"\raggedbottom",
        r"\setcounter{tocdepth}{2}",
        r"\pagestyle{plain}",
        r"\titleformat{\section}{\sffamily\bfseries\LARGE\color{Ink}\raggedright}{\thesection}{0.8em}{}",
        r"\titleformat{\subsection}{\sffamily\bfseries\Large\color{Ink}\raggedright}{\thesubsection}{0.8em}{}",
        r"\titleformat{\subsubsection}{\sffamily\bfseries\normalsize\color{Ink}\raggedright}{\thesubsubsection}{0.8em}{}",
        r"\tcbset{panel/.style={enhanced,breakable,boxrule=0.55pt,arc=3pt,left=9pt,right=9pt,top=8pt,bottom=8pt,colback=white,colframe=Line}}",
        r"\newcommand{\SummaryBox}[1]{\begin{tcolorbox}[enhanced,boxrule=0.55pt,arc=3pt,left=9pt,right=9pt,top=8pt,bottom=8pt,colback=Panel,colframe=Line]#1\end{tcolorbox}}",
        r"\newcommand{\SoftSubsection}[1]{\Needspace{12\baselineskip}\subsection{#1}}",
        r"\newcommand{\SoftSubsubsection}[1]{\Needspace{10\baselineskip}\subsubsection{#1}}",
        r"\begin{document}",
        r"\begin{titlepage}",
        r"\vspace*{16mm}",
        r"{\sffamily\bfseries\fontsize{24}{28}\selectfont CT and DNS Monograph\par}",
        r"\vspace{6pt}",
        r"{\Large A complete publication built from live Certificate Transparency and public DNS evidence\par}",
        r"\vspace{18pt}",
        rf"\textbf{{Generated}}: {latex_escape(report['generated_at_utc'])}\par",
        rf"\textbf{{Configured search terms file}}: {latex_escape(args.domains_file.name)}\par",
        r"\vspace{12pt}",
        r"\SummaryBox{"
        + rf"\textbf{{Headline}}: {len(hits)} leaf certificates, {len(groups)} CN families, "
        + rf"{historical_count} historical leaf certificates, "
        + rf"{len(report['unique_dns_names'])} DNS names, "
        + rf"{purpose_summary.category_counts.get('tls_server_only', 0)} ordinary public TLS server certificates, "
        + rf"{purpose_summary.category_counts.get('tls_server_and_client', 0)} certificates from templates that also permit client-certificate use."
        + r"}",
        r"\end{titlepage}",
        r"\begingroup",
        r"\small",
        r"\setlength{\parskip}{2pt}",
        r"\tableofcontents",
        r"\endgroup",
        r"\clearpage",
    ]

    def add_summary(items: list[str]) -> None:
        lines.append(r"\SummaryBox{\textbf{Management Summary}\begin{itemize}[leftmargin=1.4em]")
        for item in items:
            lines.append(rf"\item {latex_escape(item)}")
        lines.append(r"\end{itemize}}")

    lines.append(r"\section*{Executive Summary}")
    lines.append(r"\addcontentsline{toc}{section}{Executive Summary}")
    add_summary(
        [
            f"{len(hits)} current leaf certificates are in scope on this run.",
            f"{len(groups)} CN families reduce the estate into readable naming clusters.",
            f"{purpose_summary.category_counts.get('tls_server_only', 0)} certificates are ordinary public TLS server certificates, while {purpose_summary.category_counts.get('tls_server_and_client', 0)} come from templates that also permit client-certificate use.",
            f"{historical_count} historical leaf certificates show how the same names evolved over time.",
            f"{len(report['unique_dns_names'])} DNS SAN names were scanned live.",
            f"{caa_analysis.total_names} DNS names were also assessed for effective CAA policy, revealing where issuance is centrally governed, delegated, or left unrestricted.",
            "The estate is best understood as layers of branding, service naming, platform naming, delivery naming, and issuance-policy control rather than as random clutter.",
        ]
    )
    lines.append(
        r"This document is designed as a complete publication rather than a brief. The main chapters carry the argument and the appendices carry the detailed evidence."
    )

    lines.append(r"\section*{Reading Guide}")
    lines.append(r"\addcontentsline{toc}{section}{Reading Guide}")
    add_summary(
        [
            "Chapter 1 proves the corpus and explains why the numbers can be trusted.",
            "Chapters 2 and 3 explain what the current certificates are and what they are for.",
            "Chapter 4 explains the historical lifecycle and splits red flags into current versus fixed-in-the-past.",
            "Chapters 5 and 6 explain naming and DNS delivery.",
            "Chapter 7 explains the issuance-policy layer: which public CAs DNS currently authorizes and where DNS imposes no restriction at all.",
            *(
                ["Chapter 8 explains the focused Subject-CN cohort and why it behaves differently from the wider estate."]
                if has_focus
                else []
            ),
            "The next synthesis chapter ties the whole estate back to operational reality.",
            "The appendices contain the detailed catalogue, the historical red-flag detail, and the full inventory.",
        ]
    )

    lines.append(r"\section{Scope, Completeness, and Proof}")
    add_summary(
        [
            f"The first broad crt.sh search returned {', '.join(f'{domain}={count} matching index rows' for domain, count in report['raw_match_counts'].items())}. Those rows are leads, not final certificate count.",
            f"The scanner was allowed to collect up to {report['cap']} candidate rows per search term. Because the live match counts stayed below that limit, nothing was silently cut off.",
            f"After downloading and parsing the actual certificate bodies, {report['verification'].unique_leaf_certificates} genuine leaf certificates remained. {report['verification'].non_leaf_filtered} CA-style certificates and {report['verification'].precertificate_poison_filtered} precertificate marker objects were rejected.",
            f"Certificates missing the searched-for domains in their DNS SANs after full parsing: {report['missing_matching_san']}.",
        ]
    )
    lines.append(
        r"This chapter answers the first and most important question: whether the report is built on a complete and trustworthy corpus. The scanner now checks the live raw match count before issuing the capped query. If the cap is too low, it fails instead of silently undercounting."
    )
    lines.append(
        r"The first crt.sh row count is intentionally larger than the final certificate count because Certificate Transparency search results are index rows, not de-duplicated certificates. The report therefore reads the binary certificate body itself, removes duplicates, rejects CA certificates and precertificate marker objects, and only then builds the working corpus."
    )
    lines.append(
        r"In other words: this publication is not based on search-result snippets alone. It is based on the parsed X.509 certificate bodies."
    )

    lines.append(r"\section{The Certificate Corpus}")
    add_summary(
        [
            f"Issuer families by certificate count are {', '.join(f'{name} ({count})' for name, count in report['issuer_family_counts'].most_common())}.",
            f"Revocation state in plain terms: {report['rev_counts'].get('not_revoked', 0)} certificates are not marked revoked, and {report['rev_counts'].get('revoked', 0)} were later marked invalid by their issuing CA before natural expiry.",
            "For every current certificate, the main Subject CN hostname also appears literally in the DNS SAN list. The headline name on the certificate is therefore one of the real covered hostnames, not a decorative label.",
            "All visible issuer families in this corpus are currently trusted by the major public browser and operating-system trust stores for ordinary web server use.",
        ]
    )
    lines.append(
        r"A certificate corpus can look random when viewed as a flat list. It becomes intelligible once you group it by issuer family, Subject CN construction, validity history, and SAN design. That is why the appendices are arranged as families rather than raw rows."
    )
    lines.extend(
        [
            r"\subsection{Issuer Trust Table}",
            r"\begin{longtable}{>{\raggedright\arraybackslash}p{0.40\linewidth} >{\raggedleft\arraybackslash}p{0.12\linewidth} >{\raggedleft\arraybackslash}p{0.12\linewidth} >{\raggedleft\arraybackslash}p{0.18\linewidth}}",
            r"\toprule",
            r"Issuer Family & Certs & Variants & Major WebPKI \\",
            r"\midrule",
        ]
    )
    for row in issuer_family_rows:
        lines.append(
            rf"{latex_escape(row['family'])} & {row['certificates']} & {row['variant_count']} & {row['major_webpki']} \\"
    )
    lines.extend([r"\bottomrule", r"\end{longtable}"])
    lines.append(
        r"\textbf{What WebPKI trust means.} A WebPKI-trusted issuer is a certificate authority trusted by mainstream browser and operating-system trust stores for public TLS. That matters because it tells you these certificates are not part of a private PKI hidden inside one organisation. They are intended to be valid in the public Internet trust model."
    )
    lines.append(
        r"This view should answer one question only: how many publicly trusted issuer families are present in the estate. Exact subordinate issuer names are supporting evidence and remain in the detailed inventory appendix."
    )

    lines.append(r"\section{Intended Purpose of the Certificates}")
    add_summary(
        [
            f"Certificates whose allowed purpose is ordinary server authentication only: {purpose_summary.category_counts.get('tls_server_only', 0)}.",
            f"Certificates whose policy allows both server use and client-certificate use: {purpose_summary.category_counts.get('tls_server_and_client', 0)}.",
            "Certificates dedicated only to client identity, email signing, or code signing: 0.",
        ]
    )
    lines.append(
        r"This chapter addresses a key ambiguity. A certificate can be technically valid for several uses, and the hostname alone does not settle that question. The corpus was therefore assessed from the X.509 usage fields themselves: EKU and KeyUsage."
    )
    lines.append(
        r"Extended Key Usage tells software what a certificate is allowed to do. In plain terms, this is the difference between a website certificate, a client-identity certificate, an email certificate, and a code-signing certificate."
    )
    lines.extend(
        [
            r"\subsection{Purpose Map}",
            r"\begin{longtable}{>{\raggedright\arraybackslash}p{0.24\linewidth} >{\raggedleft\arraybackslash}p{0.10\linewidth} >{\raggedleft\arraybackslash}p{0.10\linewidth} >{\raggedright\arraybackslash}p{0.46\linewidth}}",
            r"\toprule",
            r"Usage Class & Certs & Share & Meaning \\",
            r"\midrule",
        ]
    )
    for label, count, share, meaning in visible_purpose_rows:
        lines.append(
            rf"{latex_escape(label)} & {count} & {latex_escape(share)} & {latex_escape(meaning)} \\"
        )
    lines.extend([r"\bottomrule", r"\end{longtable}"])
    lines.append(
        r"This view should answer only what kind of certificates these are. Zero-count categories are removed here because they add noise without changing the conclusion."
    )
    lines.append(
        r"The basic picture is simple: the corpus is overwhelmingly made of ordinary public TLS server certificates, with a smaller minority whose EKU also permits client-certificate use."
    )
    lines.append(
        r"\textbf{Plain-language explanation of the usage categories.} A TLS server certificate is what a website or API presents to a browser, app, or machine client. A server-and-client certificate is one whose policy allows both server use and client-certificate use. That does not automatically mean it is actually used as a client certificate, but it leaves that door open. Client-auth-only certificates are what you would expect for a user, robot, or agent identity in mutual TLS. S/MIME means email signing or encryption. Code-signing means software signing rather than endpoint security."
    )
    lines.append(
        r"The result is clean. This corpus is entirely TLS-capable. There is no evidence of a separate S/MIME or code-signing estate, and there are no client-auth-only certificates."
    )
    lines.extend(
        [
            r"\subsection{EKU and KeyUsage Templates}",
            r"At the template level, the corpus is even simpler than the certificate count suggests. Here, a template simply means a repeated combination of usage fields. Only two EKU combinations appear at all, and one KeyUsage pattern dominates almost completely.",
            r"\begin{longtable}{>{\raggedright\arraybackslash}p{0.58\linewidth} >{\raggedleft\arraybackslash}p{0.14\linewidth} >{\raggedleft\arraybackslash}p{0.14\linewidth}}",
            r"\toprule",
            r"EKU Template & Certs & Share \\",
            r"\midrule",
        ]
    )
    for template, count in purpose_summary.eku_templates.items():
        lines.append(rf"{latex_escape(template)} & {count} & {latex_escape(pct(count, total_certificates))} \\")
    lines.extend([r"\bottomrule", r"\end{longtable}"])
    lines.extend(
        [
            r"\begin{longtable}{>{\raggedright\arraybackslash}p{0.58\linewidth} >{\raggedleft\arraybackslash}p{0.14\linewidth} >{\raggedleft\arraybackslash}p{0.14\linewidth}}",
            r"\toprule",
            r"KeyUsage Template & Certs & Share \\",
            r"\midrule",
        ]
    )
    for template, count in purpose_summary.key_usage_templates.items():
        lines.append(rf"{latex_escape(template)} & {count} & {latex_escape(pct(count, total_certificates))} \\")
    lines.extend([r"\bottomrule", r"\end{longtable}"])
    lines.extend(
        [
            r"\subsection{The Majority Pattern: Server-Only Public TLS}",
            rf"Server-only certificates account for {server_only_count} of {total_certificates} certificates, or {latex_escape(pct(server_only_count, total_certificates))} of the corpus.",
            rf"Server-only validity starts are split between {latex_escape(', '.join(f'{year} ({count})' for year, count in purpose_summary.validity_start_years.get('tls_server_only', {}).items()))}.",
            rf"Server-only issuer-family concentration is {latex_escape(', '.join(f'{name} ({count})' for name, count in server_only_issuer_families.most_common()))}.",
            r"This is the normal public WebPKI server-certificate pattern for websites, APIs, and edge service front doors.",
            r"This majority group is not background noise. It is the main operational reality visible in the scan: public DNS names covered by publicly trusted endpoint certificates.",
        ]
    )
    lines.extend(
        [
            r"\subsection{The Minority Pattern: Dual EKU}",
            rf"In this corpus, {dual_count} certificates carry both \texttt{{serverAuth}} and \texttt{{clientAuth}} in Extended Key Usage. That is {latex_escape(pct(dual_count, total_certificates))} of the corpus. This means the certificate is \emph{{allowed}} to be used in either role. It does not prove that the certificate is actually being used as a client identity in production.",
            rf"The dual-EKU group is concentrated in these issuer families: {latex_escape(', '.join(f'{name} ({count})' for name, count in dual_issuer_counts.most_common()))}.",
            rf"{len(purpose_summary.dual_eku_subject_cns_with_server_only_sibling)} dual-EKU Subject-CN families also have a strict server-only sibling, while {len(purpose_summary.dual_eku_subject_cns_without_server_only_sibling)} currently appear only in the dual-EKU group.",
            rf"Dual-EKU validity starts are split between {latex_escape(', '.join(f'{year} ({count})' for year, count in purpose_summary.validity_start_years.get('tls_server_and_client', {}).items()))}.",
            r"The important interpretation point is that these still look like public hostname certificates: DNS-style Subject CN values, DNS SAN lists, and public WebPKI issuers. The better reading is therefore not ``separate client-certificate estate'', but ``server certificates issued from a template that also allowed clientAuth''.",
            r"\subsection{What Is Not Present}",
            r"There are no client-auth-only certificates, no S/MIME certificates, no code-signing certificates, no mixed-or-other EKU combinations, and no certificates missing EKU entirely.",
        ]
    )

    lines.append(r"\section{Historical Renewal, Drift, and Red Flags}")
    add_summary(
        [
            f"Looking across expired and current history, the corpus contains {historical_count} leaf certificates; {historical_current_count} of them are still valid today.",
            f"{repeated_cn_count} Subject CN values recur over time rather than appearing as one-off singletons.",
            f"{assessment.normal_reissuance_assets} renewal families look operationally normal: predecessor and successor overlap for fewer than 50 days.",
            f"{len(assessment.overlap_current_rows)} names still show long overlap of 50 days or more today.",
            f"{len(assessment.overlap_past_rows)} names showed the same long-overlap behaviour in the past, but not anymore in currently valid certificates.",
            f"Current non-overlap anomalies are limited: {len(assessment.dn_current_rows)} live Subject DN drift cases, {len(assessment.vendor_current_rows)} live CA-family drift cases, and {len(assessment.san_current_rows)} live SAN drift cases.",
            f"Past-only fixed anomalies were broader: {len(assessment.dn_past_rows)} historical Subject DN drift cases, {len(assessment.vendor_past_rows)} historical CA-family drift cases, and {len(assessment.san_past_rows)} historical SAN drift cases.",
        ]
    )
    lines.append(
        r"This chapter is the historical check on whether the current picture follows a clean renewal pattern. It answers a different question from the current-corpus chapters above: not just what certificates exist now, but how the hostname estate has behaved over time."
    )
    lines.append(
        r"For this chapter, a renewal family means repeated certificates that keep the same apparent identity over time: the same Subject CN, the same full Subject DN, the same SAN profile, and the same CA family. A normal renewal reissues that same apparent certificate identity with a new key and a new validity span, and predecessor and successor overlap only briefly. In this monograph, anything below fifty days of overlap is treated as normal. Fifty days or more is treated as a red flag. COMODO and Sectigo are treated as one CA family from the outset, so movement between those names is not counted here as CA-family drift."
    )
    lines.append(
        r"A red flag in this chapter is not the same thing as a breach or a compromise. It means the certificate history diverged from the clean rollover pattern that one would normally expect and therefore deserves closer review."
    )
    lines.extend(
        [
            r"\subsection{Current Red-Flag Inventory}",
        ]
    )
    if assessment.current_red_flag_rows:
        lines.extend(
            [
                r"\begin{longtable}{>{\raggedright\arraybackslash}p{0.27\linewidth} >{\raggedleft\arraybackslash}p{0.10\linewidth} >{\raggedright\arraybackslash}p{0.24\linewidth} >{\raggedright\arraybackslash}p{0.29\linewidth}}",
                r"\toprule",
                r"Subject CN & Live Certs & Current Concern & Immediate Supporting Context \\",
                r"\midrule",
            ]
        )
        for row in assessment.current_red_flag_rows[:25]:
            lines.append(
                rf"{latex_escape(row.subject_cn)} & {row.current_certificate_count} & {latex_escape(row.flags)} & {latex_escape(truncate_text(row.notes, 72))} \\"
            )
        lines.extend([r"\bottomrule", r"\end{longtable}"])
    else:
        lines.append(r"No current red flags were found under the configured rules.")
    lines.append(r"\subsection{Past Red Flags Now Fixed}")
    if assessment.past_red_flag_rows:
        lines.extend(
            [
                r"\begin{longtable}{>{\raggedright\arraybackslash}p{0.27\linewidth} >{\raggedleft\arraybackslash}p{0.10\linewidth} >{\raggedright\arraybackslash}p{0.24\linewidth} >{\raggedright\arraybackslash}p{0.29\linewidth}}",
                r"\toprule",
                r"Subject CN & Historic Certs & Historical Concern & Immediate Supporting Context \\",
                r"\midrule",
            ]
        )
        for row in assessment.past_red_flag_rows[:25]:
            lines.append(
                rf"{latex_escape(row.subject_cn)} & {row.certificate_count} & {latex_escape(row.flags)} & {latex_escape(truncate_text(row.notes, 72))} \\"
            )
        lines.extend([r"\bottomrule", r"\end{longtable}"])
    else:
        lines.append(r"No past-only red flags were found under the configured rules.")
    lines.extend(
        [
            r"\subsection{What The Historical Red Flags Mean}",
            r"The two short tables above are screening tables. They answer which names deserve attention now and which names used to be problematic but no longer look live. The appendix below keeps the narrower evidence tables that explain why each name appears here.",
            rf"Overlap red flags mean predecessor and successor certificates inside the same renewal family coexist for fifty days or more. Current cases: {len(assessment.overlap_current_rows)}. Past-only fixed cases: {len(assessment.overlap_past_rows)}.",
            rf"Subject-DN drift means the same Subject CN appears under more than one full Subject DN. In plain terms, the headline hostname is being issued under different formal subject identities. Current cases: {len(assessment.dn_current_rows)}. Past-only fixed cases: {len(assessment.dn_past_rows)}.",
            rf"CA-family drift means the same Subject CN appears under more than one CA family after collapsing COMODO and Sectigo together. Current cases: {len(assessment.vendor_current_rows)}. Past-only fixed cases: {len(assessment.vendor_past_rows)}.",
            rf"SAN drift means the same Subject CN appears with more than one SAN profile. In plain terms, the hostname keeps being bundled with different companion names. Current cases: {len(assessment.san_current_rows)}. Past-only fixed cases: {len(assessment.san_past_rows)}.",
            rf"Exact issuer-name changes also exist for {len(assessment.issuer_rows)} Subject CN values, but these are supporting context rather than first-order red flags.",
            r"\subsection{Historical Step Changes}",
            rf"Top issuance start dates are {latex_escape(', '.join(f'{row.start_day} ({row.certificate_count})' for row in assessment.day_rows[:6]))}.",
            rf"Strong step weeks are {latex_escape(', '.join(f'{row.week_start} ({row.certificate_count} vs prior avg {row.prior_eight_week_avg})' for row in assessment.week_rows[:4]) or 'none')}.",
        ]
    )

    lines.append(r"\section{Naming Architecture}")
    add_summary(
        [
            f"Numbered CN families: {len(report['numbered_groups'])}.",
            f"Multi-zone SAN sets: {report['multi_zone_hit_count']}.",
            f"Frequent naming tokens are {', '.join(f'{token} ({count})' for token, count in report['top_env_tokens'][:8])}.",
            "The strongest naming signals come from numbered rails, environment markers, cross-brand labels, and cross-zone SAN composition. www is weak evidence either way.",
        ]
    )
    lines.append(
        r"The naming regime becomes intelligible when read as several superimposed languages: brand language, service language, environment language, platform language, and migration residue."
    )
    lines.extend(
        [
            r"\subsection{How To Read The Names}",
            r"\begin{itemize}[leftmargin=1.4em]",
            r"\item In most of these names, the left-most label tells you the endpoint role, node slot, or environment slice, while the zone on the right tells you which public namespace the service is answering under.",
            r"\item Standard delivery shorthand appears throughout the corpus: \texttt{dev}, \texttt{qa}, \texttt{uat}, \texttt{sit}, \texttt{stg}, \texttt{preprod}, and \texttt{prod} are ordinary environment markers rather than mysterious product names.",
            r"\item \texttt{www} is a weak signal both when present and when absent. Its presence often reflects compatibility, redirect history, or old web conventions; its absence does not imply any deeper architectural distinction.",
            r"\item In this corpus, \texttt{nwg} reads as NatWest Group shorthand. Names like \texttt{rbs}, \texttt{natwest}, \texttt{ulsterbank}, \texttt{lombard}, \texttt{natwestpayments}, \texttt{coutts}, and \texttt{nwgwealth} are best read as parallel business or service namespaces within a wider shared estate, not as random unrelated domains.",
            r"\item Some short forms remain inferential rather than provable. For example, \texttt{nft} clearly behaves like a non-production stage label, but Certificate Transparency alone cannot prove the local expansion used inside the company.",
            r"\end{itemize}",
        ]
    )
    lines.append(r"\subsection{Key Pattern Examples}")
    lines.append(
        r"These four boxes are not four isolated hostnames. Each one uses a concrete Subject-CN value as the evidence anchor for a broader naming methodology that appears elsewhere in the estate as well."
    )
    for example in report["examples"]:
        lines.append(r"\SummaryBox{")
        lines.append(rf"\textbf{{{latex_escape(example.title)}}}\par")
        lines.append(rf"\textbf{{Pattern shown}}: {latex_escape(example_pattern_label(example.title))}\par")
        lines.append(rf"\textbf{{Concrete example}}: \texttt{{{latex_escape(example.subject_cn)}}}\par")
        lines.append(rf"\textbf{{What this proves}}: {latex_escape(example.why_it_matters)}\par")
        lines.append(r"\begin{itemize}[leftmargin=1.4em]")
        for point in example.evidence:
            lines.append(rf"\item {latex_escape(point)}")
        lines.append(r"\end{itemize}}")
    lines.extend(
        [
            r"\subsection{Why These Four Examples}",
            r"Taken together, these four examples explain most of the naming behaviour in the corpus. The first shows platform fleet naming, the second shows environment-and-release naming, the third shows cross-brand namespace splicing and migration residue, and the fourth shows shared-service bridging across several business namespaces.",
        ]
    )

    lines.append(r"\section{DNS Delivery Architecture}")
    add_summary(
        [
            f"Most names resolve by first aliasing to another hostname and then to an address: {alias_to_address_count} public names follow an alias chain, while {direct_address_count} names resolve straight to an address.",
            f"The most common public DNS outcomes are Adobe Campaign in front of AWS load-balancing ({report['dns_stack_counts'].get('Adobe Campaign -> AWS ALB', 0)}), Adobe Campaign in front of AWS CloudFront ({report['dns_stack_counts'].get('Adobe Campaign -> AWS CloudFront', 0)}), and plain AWS CloudFront without an Adobe layer ({report['dns_stack_counts'].get('AWS CloudFront', 0)}).",
            f"Smaller but important subsets look like governed API fronts or specialist application platforms: Google Apigee ({report['dns_stack_counts'].get('Google Apigee', 0)}) and Pega Cloud -> AWS ALB ({report['dns_stack_counts'].get('Pega Cloud -> AWS ALB', 0)}).",
            f"Some certificate names do not lead to a live public endpoint today: {nxdomain_count} do not exist in public DNS at all, {dangling_count} still exist only as broken aliases, and {no_data_count} exist in DNS but returned no public A or AAAA address during the scan.",
        ]
    )
    lines.append(
        r"DNS is the public routing layer. It does not tell you everything about an application, but it does tell you where a public name lands: directly on an IP, through an alias chain, through a CDN, through an API gateway, or onto a specialist platform."
    )
    lines.append(
        r"This chapter does not claim to know the full private architecture behind each service. It only claims what the public DNS trail supports. For each DNS SAN name in the certificate corpus, the scanner queried public \texttt{CNAME}, \texttt{A}, \texttt{AAAA}, and \texttt{PTR} data. It then summarized that public answer trail with a short label. Those labels are compact descriptions of the public DNS evidence, not arbitrary platform slogans."
    )
    lines.append(
        r"One important caution follows from that last point: a hostname can remain visible in certificate history even after its public DNS has been removed or partially dismantled. Certificate history and current DNS are related, but they do not move in lockstep."
    )
    lines.extend(
        [
            r"\subsection{How The DNS Evidence Is Read}",
            r"\begin{itemize}[leftmargin=1.4em]",
            r"\item A \texttt{CNAME} shows that one public name is really an alias for another public name.",
            r"\item The terminal hostname, returned addresses, and reverse-DNS names often reveal platform clues such as \texttt{cloudfront.net}, \texttt{elb.amazonaws.com}, \texttt{apigee.net}, or \texttt{campaign.adobe.com}.",
            r"\item The report combines the answer shape and those clues into one short description. For example, ``Adobe Campaign -> AWS ALB'' means the alias chain contains Adobe Campaign naming and the terminal clues point to AWS load-balancing infrastructure.",
            r"\item These labels are therefore evidence summaries, not claims of legal ownership or full internal design.",
            r"\end{itemize}",
            r"\subsection{What The Public DNS Names Resolve To}",
            r"\begin{longtable}{>{\raggedright\arraybackslash}p{0.28\linewidth} >{\raggedleft\arraybackslash}p{0.09\linewidth} >{\raggedright\arraybackslash}p{0.51\linewidth}}",
            r"\toprule",
            r"Observed DNS Outcome & Count & Plain-Language Meaning \\",
            r"\midrule",
        ]
    )
    for label, count in top_dns_patterns:
        lines.append(rf"{latex_escape(label)} & {count} & {latex_escape(delivery_pattern_meaning(label))} \\")
    lines.extend([r"\bottomrule", r"\end{longtable}"])
    lines.extend(
        [
            r"\subsection{Why Each DNS Label Was Used}",
            r"\begin{itemize}[leftmargin=1.4em]",
        ]
    )
    for label, _count in top_dns_patterns[:6]:
        lines.append(rf"\item \textbf{{{latex_escape(label)}}}: {latex_escape(delivery_pattern_rule(label))}")
    lines.extend(
        [
            r"\end{itemize}",
            r"\subsection{Platform And DNS Glossary}",
            r"\begin{longtable}{>{\raggedright\arraybackslash}p{0.22\linewidth} >{\raggedright\arraybackslash}p{0.70\linewidth}}",
            r"\toprule",
            r"Term & Explanation \\",
            r"\midrule",
        ]
    )
    glossary = ct_dns_utils.provider_explanations()
    for term in ["Adobe Campaign", "AWS", "AWS ALB", "AWS CloudFront", "Google Apigee", "Pega Cloud", "Microsoft Edge", "Infinite / agency alias", "CNAME", "A record", "AAAA record", "PTR record", "NXDOMAIN"]:
        lines.append(rf"{latex_escape(term)} & {latex_escape(glossary[term])} \\")
    lines.extend([r"\bottomrule", r"\end{longtable}"])
    lines.append(
        r"The glossary terms above are the building blocks used in the DNS-outcome table. This is also why the management summary mentions Adobe Campaign, CloudFront, Apigee, and Pega at all: not because brand names are the point, but because those names reveal what kind of public delivery role a hostname is landing on. CloudFront suggests a distribution edge, Apigee suggests managed API exposure, Adobe Campaign suggests a marketing or communications front, and a load balancer suggests traffic distribution to backend services."
    )
    lines.append(
        r"The next chapter stays with the same names but moves from delivery to control. This chapter asked where public traffic lands. The next one asks which public CA families DNS currently authorizes to issue for those same names."
    )

    lines.append(r"\section{DNS Issuance Policy Control (CAA)}")
    zone_summary_items: list[str] = []
    for zone in caa_analysis.configured_domains:
        zone_rows = ct_caa_analysis.rows_for_zone(caa_analysis, zone)
        unrestricted_count = sum(1 for row in zone_rows if not row.allowed_ca_families)
        mismatch_count = sum(1 for row in zone_rows if row.current_policy_mismatch)
        overlap_count = sum(1 for row in zone_rows if row.current_multi_family_overlap)
        dominant_policy = ct_caa_analysis.policy_counter(zone_rows).most_common(1)
        dominant_label = caa_policy_label(dominant_policy[0][0]) if dominant_policy else "none"
        zone_summary_items.append(
            f"{zone}: {len(zone_rows)} names in scope; dominant policy is {dominant_label}; unrestricted names={unrestricted_count}; current policy-mismatch names={mismatch_count}; current multi-family overlap names={overlap_count}."
        )
    add_summary(
        zone_summary_items
        + [
            f"Effective CAA discovery paths across all names are {', '.join(f'{caa_source_label(kind)}={count}' for kind, count in caa_analysis.source_kind_counts.most_common())}.",
            f"Current names simultaneously covered by more than one live CA family: {len(caa_analysis.multi_family_overlap_names)}.",
            f"Current names whose live certificate family does not match today's published CAA policy: {len(caa_analysis.policy_mismatch_names)}.",
        ]
    )
    lines.append(
        r"CAA is the DNS control layer for public certificate issuance. It does not validate a certificate after issuance; instead, it tells a public CA which CA families are authorized to issue for a DNS name if any restriction is published at all. If no CAA is published, WebPKI issuance is unrestricted from the DNS-policy point of view."
    )
    lines.append(
        r"This chapter is the control-plane counterpart to the certificate and DNS chapters. The certificate chapter showed who actually issued. The DNS chapter showed where the names land. The CAA chapter shows which issuers the DNS owner currently allows for those same names."
    )
    lines.append(
        r"That distinction matters because hosting and issuance are different decisions. A name can land on AWS and still use a Sectigo-family certificate if DNS policy allows it. A name can also resolve through a vendor platform while still inheriting a first-party corporate CAA policy. The point of this chapter is to show where those decisions line up and where they do not."
    )
    lines.append(
        r"CAA is checked per DNS name requested in the certificate, not per Subject DN and not per organisational story. A Subject CN can therefore shift between different Subject DN values without creating a CAA clash, because CAA ignores organisation fields and looks only at the DNS names being certified."
    )
    lines.extend(
        [
            r"\subsection{Why CAA Matters In This Estate}",
            r"\begin{itemize}[leftmargin=1.4em]",
            r"\item If a name has no CAA, DNS is not constraining which public CA family may issue for it.",
            r"\item If a name inherits a broad corporate policy, that usually means the organisation has left normal brand-facing names under a common default.",
            r"\item If a name falls under a narrower subtree or alias-derived policy, that is evidence of more deliberate platform or vendor-specific issuance control.",
            r"\item If a live certificate family sits outside today's CAA policy, or if the same DNS name is live under two CA families at once, that usually points to migration lag, overlapping rollout, or policy that moved faster than certificate cleanup.",
            r"\end{itemize}",
        ]
    )
    lines.extend(
        [
            r"\subsection{How To Read The CAA Results}",
            r"\begin{longtable}{>{\raggedright\arraybackslash}p{0.24\linewidth} >{\raggedleft\arraybackslash}p{0.10\linewidth} >{\raggedright\arraybackslash}p{0.54\linewidth}}",
            r"\toprule",
            r"CAA Discovery Result & Names & Meaning \\",
            r"\midrule",
        ]
    )
    for label, count, meaning in caa_source_rows(caa_analysis):
        lines.append(rf"{latex_escape(label)} & {latex_escape(count)} & {latex_escape(meaning)} \\")
    lines.extend([r"\bottomrule", r"\end{longtable}"])
    lines.append(
        r"The key distinction is between ordinary parent inheritance and alias-target-derived policy. Parent inheritance means the leaf name simply relies on a policy published higher in its own DNS tree. Alias-target-derived policy means the effective CAA surfaced through an alias response. In this corpus, that often marks a managed rail or specialist external platform rather than a plain brand-front hostname."
    )
    lines.append(
        r"In practical terms, most names in this corpus fall into three shapes: inherited corporate policy, alias-driven managed-platform policy, or no CAA at all. That three-way split is more important than the mechanics themselves, because it shows where issuance control is broad, where it is deliberately narrow, and where it is absent."
    )
    lines.append(r"\subsection{Policy Regimes By Configured Zone}")
    for zone in caa_analysis.configured_domains:
        lines.append(rf"\subsubsection{{{latex_escape(zone)}}}")
        lines.extend(
            [
                r"\begin{longtable}{>{\raggedright\arraybackslash}p{0.25\linewidth} >{\raggedleft\arraybackslash}p{0.10\linewidth} >{\raggedright\arraybackslash}p{0.53\linewidth}}",
                r"\toprule",
                r"Policy Regime & Names & Plain-Language Meaning \\",
                r"\midrule",
            ]
        )
        for regime, count, meaning in caa_zone_rows[zone]:
            lines.append(rf"{latex_escape(regime)} & {latex_escape(count)} & {latex_escape(meaning)} \\")
        lines.extend([r"\bottomrule", r"\end{longtable}"])
    if secondary_zone:
        lines.append(
            rf"The contrast between \texttt{{{latex_escape(primary_zone)}}} and \texttt{{{latex_escape(secondary_zone)}}} is one of the strongest PKI-governance findings in the corpus. \texttt{{{latex_escape(primary_zone)}}} is policy-layered and governed, while \texttt{{{latex_escape(secondary_zone)}}} is currently CAA-empty in the scanned name set. That does not make \texttt{{{latex_escape(secondary_zone)}}} invalid, but it does mean DNS is not constraining public CA choice there."
        )
        lines.append(
            rf"That asymmetry matters more than any one record. \texttt{{{latex_escape(primary_zone)}}} looks like a namespace where DNS is being used as an issuance-governance tool. \texttt{{{latex_escape(secondary_zone)}}} looks like a namespace where issuance choice is still being handled outside DNS policy, or not being constrained at all."
        )
    lines.extend(
        [
            r"\subsection{How CAA Changes The Reading Of The Estate}",
            r"The CAA layer strengthens the earlier certificate-and-DNS thesis rather than overturning it. The same service families that already looked like shared managed rails from naming and DNS often sit under narrower issuance policy as well.",
            rf"In \texttt{{{latex_escape(primary_zone)}}}, the current CAA friction is concentrated rather than diffuse: {latex_escape(caa_concentration_text(caa_analysis, primary_zone))}.",
            r"Broad corporate default policy remains visible on many ordinary brand-facing names. That supports the earlier reading that not every public hostname was moved onto one tightly managed delivery rail.",
            r"Narrower or alias-driven CAA policy appears where the DNS evidence already suggested a managed platform, campaign rail, or vendor-mediated service surface.",
            r"Vendor-style exceptions still exist. Where a name resolves through a specialist external platform and the allowed CA set widens or changes shape, the policy layer supports the earlier vendor-delegation reading rather than contradicting it.",
            r"The chapter therefore adds a governance gradient to the earlier thesis: some parts of the estate are tightly steered, some inherit a broad default, and some are still policy-empty.",
            r"\subsection{Why The Next Two Tables Matter}",
            r"\begin{itemize}[leftmargin=1.4em]",
            r"\item The overlap table shows where an old and a new issuance regime are both still live on the same DNS name.",
            r"\item The mismatch table shows where today's DNS policy has already moved, but one or more live certificates still reflect the older state.",
            r"\item Read them together, not separately. Together they show whether the estate looks diffusely messy or whether the untidy parts cluster in a small transition zone.",
            r"\end{itemize}",
            r"\subsection{Current Multi-Family Overlap}",
        ]
    )
    if caa_analysis.multi_family_overlap_names:
        append_longtable(
            lines,
            r">{\raggedright\arraybackslash}p{0.27\linewidth} >{\raggedright\arraybackslash}p{0.10\linewidth} >{\raggedright\arraybackslash}p{0.16\linewidth} >{\raggedright\arraybackslash}p{0.33\linewidth}",
            ["DNS Name", "Zone", "Live CA Families", "Covering Subject CNs"],
            top_caa_overlap_rows(caa_analysis),
            font="footnotesize",
            tabcolsep="3.2pt",
        )
    else:
        lines.append(r"No current multi-family overlap names were found.")
    lines.append(
        r"These overlap names are operationally important. They show where the same public DNS name is currently covered by more than one live CA family at once. In this corpus, that behavior clusters tightly in a few service families rather than being spread randomly across the estate."
    )
    lines.append(r"\subsection{Current Policy Mismatch}")
    if caa_analysis.policy_mismatch_names:
        append_longtable(
            lines,
            r">{\raggedright\arraybackslash}p{0.24\linewidth} >{\raggedright\arraybackslash}p{0.10\linewidth} >{\raggedright\arraybackslash}p{0.14\linewidth} >{\raggedright\arraybackslash}p{0.16\linewidth} >{\raggedright\arraybackslash}p{0.20\linewidth}",
            ["DNS Name", "Zone", "Live CA Families", "CAA-Allowed Families", "CAA Discovery Result"],
            top_caa_mismatch_rows(caa_analysis),
            font="footnotesize",
            tabcolsep="3.0pt",
        )
    else:
        lines.append(r"No current policy-mismatch names were found.")
    lines.append(
        r"A current policy mismatch does not automatically prove CA misissuance. CAA only proves what DNS authorizes now. Certificates can remain valid after the DNS-side policy has changed, so the right reading here is current policy lag or migration residue unless the historical issuance-time DNS can also be shown."
    )
    lines.append(
        r"Taken together, the overlap and mismatch tables support a migration reading more than a disorder reading. If the estate were simply chaotic, the live friction would be spread widely across unrelated names. Instead, it clusters in a small number of service families that were already prominent in the certificate and DNS chapters."
    )

    if focus_analysis:
        lines.append(r"\section{Focused Subject-CN Cohort}")
        add_summary(
            [
                f"The focused cohort contains {focus_analysis.provided_subjects_count} analyst-selected Subject CN values. {focus_analysis.historically_seen_subjects_count} are visible somewhere in the historical CT corpus, and {focus_analysis.current_direct_subjects_count} still have direct current certificates.",
                f"The current focused cohort is structurally different from the rest of the estate: all {focus_analysis.current_focus_certificate_count} current focused certificates are Sectigo/COMODO-lineage, compared with {counter_text(focus_analysis.rest_current_issuer_families, 3)} in the rest of the corpus.",
                f"The focused cohort uses much smaller certificates: median SAN size {focus_analysis.focus_median_san_entries} versus {focus_analysis.rest_median_san_entries}, and {focus_analysis.focus_multi_zone_certificate_count} current multi-zone certificates versus {focus_analysis.rest_multi_zone_certificate_count} outside the cohort.",
                f"Revocation churn is much higher inside the focused cohort: {focus_analysis.focus_revoked_current_count} revoked versus {focus_analysis.focus_not_revoked_current_count} not revoked ({focus_analysis.focus_revoked_share}), compared with {focus_analysis.rest_revoked_current_count} versus {focus_analysis.rest_not_revoked_current_count} ({focus_analysis.rest_revoked_share}) outside the cohort.",
                f"Cross-basket carrying is limited rather than universal. The count of focused entries that appear today only as SAN passengers is {focus_analysis.current_carried_only_subjects_count}, and the count ever seen as SAN passengers inside non-focused certificates at all is {focus_analysis.historical_non_focus_carried_subjects_count}.",
                f"The cohort splits into three naming buckets rather than one uniform style: {focus_analysis.bucket_counts.get('direct_front_door', 0)} front-door direct names, {focus_analysis.bucket_counts.get('platform_matrix_anchor', 0)} platform-anchor matrix names, and {focus_analysis.bucket_counts.get('ambiguous_legacy', 0)} ambiguous or legacy-residue names.",
            ]
        )
        lines.append(
            r"This chapter treats the supplied Subject-CN list as an analyst-guided cohort rather than as a neutral statistical sample. The question is not whether these names are the most common names in the estate. The question is why they were memorable enough to be singled out, and whether the certificate and DNS evidence shows that they belong to a different naming and hosting tradition."
        )
        lines.append(
            r"The short answer is yes, but not because the cohort is perfectly uniform. The cohort is different from the wider estate because it is weighted toward remembered public fronts and remembered platform anchors, not toward the Amazon-heavy operational rail population that dominates the broader corpus."
        )
        lines.extend(
            [
                r"\subsection{Focused Cohort Versus The Rest Of The Estate}",
            ]
        )
        append_longtable(
            lines,
            r">{\raggedright\arraybackslash}p{0.27\linewidth} >{\raggedright\arraybackslash}p{0.16\linewidth} >{\raggedright\arraybackslash}p{0.16\linewidth} >{\raggedright\arraybackslash}p{0.31\linewidth}",
            ["Comparison View", "Focused Cohort", "Rest Of Current Corpus", "Why It Matters"],
            focus_comparison,
            font="footnotesize",
            tabcolsep="3.2pt",
        )
        lines.extend(
            [
                r"\subsection{Three Buckets Inside The Cohort}",
            ]
        )
        append_longtable(
            lines,
            r">{\raggedright\arraybackslash}p{0.15\linewidth} >{\raggedleft\arraybackslash}p{0.06\linewidth} >{\raggedright\arraybackslash}p{0.19\linewidth} >{\raggedright\arraybackslash}p{0.24\linewidth} >{\raggedright\arraybackslash}p{0.26\linewidth}",
            ["Bucket", "Count", "Representative Names", "What It Looks Like", "Why This Bucket Exists"],
            focus_bucket_summary,
            font="footnotesize",
            tabcolsep="3.0pt",
        )
        lines.extend(
            [
                r"This bucket split is the key to making the cohort intelligible. The memorable names are not all from one naming methodology. Most are direct public fronts. A very small number are platform-anchor certificates with matrix SAN design. The rest are historical leftovers, carried aliases, or opaque labels whose original role is no longer cleanly visible in the current corpus.",
                r"\subsection{Why This Cohort Feels Different}",
                r"\begin{itemize}[leftmargin=1.4em]",
                r"\item The dominant bucket is the front-door direct bucket. These are small-SAN certificates attached to memorable service, identity, vendor, or brand-like names directly under the branded public zones configured for the scan.",
                r"\item The platform-anchor bucket is tiny but important. These names carry large SAN matrices that spell out environment, tenant, service-cell, or monitoring coverage, which is exactly what one would expect from a centrally managed operational platform slice.",
                r"\item The ambiguous bucket matters because it explains the leftover rough edges. These names may be historical-only, partly migrated into other certificates, or too opaque to decode confidently from public evidence alone.",
                r"\item The public DNS evidence for the current focused Subject CN names is also different. The cohort lands much more often on direct addresses or simple direct AWS clues, while the wider current Subject-CN population is much more dominated by Adobe-managed, Apigee-managed, or NXDOMAIN outcomes.",
                r"\item Historical red flags are common in the cohort, but they are mostly past rather than current. That is consistent with a legacy or manually managed public-web slice that has been cleaned up over time rather than with a currently chaotic platform core.",
                r"\end{itemize}",
            ]
        )
        lines.append(
            r"Seen this way, the cohort makes sense. It looks like a remembered estate made of two high-visibility extremes: public-facing service fronts that humans remember because customers and staff encounter them directly, and a small number of operational anchor names that humans remember because administrators, testers, or engineers encounter them repeatedly. The ambiguous bucket is the residue between those two poles."
        )
        lines.append(r"\subsection{Cross-Basket Carrying And Migration}")
        if focus_analysis.transition_rows:
            append_longtable(
                lines,
                r">{\raggedright\arraybackslash}p{0.22\linewidth} >{\raggedright\arraybackslash}p{0.19\linewidth} >{\raggedright\arraybackslash}p{0.11\linewidth} >{\raggedleft\arraybackslash}p{0.09\linewidth} >{\raggedright\arraybackslash}p{0.27\linewidth}",
                ["Subject CN", "Current Basket Status", "Direct / Carried", "Max Overlap Days", "Carrier Subjects"],
                [
                    [
                        detail.subject_cn,
                        detail.basket_status,
                        f"{detail.current_direct_certificates}/{detail.current_non_focus_san_carriers + detail.historical_non_focus_san_carriers}",
                        str(detail.max_direct_to_carrier_overlap_days),
                        truncate_text(detail.carrier_subjects, 48),
                    ]
                    for detail in focus_analysis.transition_rows[:10]
                ],
                font="footnotesize",
                tabcolsep="3.1pt",
            )
        else:
            lines.append(r"No focused names were seen as SAN passengers inside non-focused certificates.")
        lines.append(
            r"This migration table answers a narrower question than the rest of the chapter. It asks whether these names were gradually absorbed into broader certificates from outside the cohort. The answer is: only in a limited number of cases. Some names do show SAN-passenger behavior or historical carrying, but that is not the dominant explanation for why the cohort feels different. The dominant explanation is the bucket split above: many remembered direct fronts, a few large platform anchors, and a band of legacy residue."
        )
        lines.append(r"\subsection{Representative Names By Bucket}")
        append_longtable(
            lines,
            r">{\raggedright\arraybackslash}p{0.14\linewidth} >{\raggedright\arraybackslash}p{0.17\linewidth} >{\raggedright\arraybackslash}p{0.18\linewidth} >{\raggedright\arraybackslash}p{0.09\linewidth} >{\raggedright\arraybackslash}p{0.30\linewidth}",
            ["Bucket", "Subject CN", "Observed Role", "Direct C/H", "Why It Helps Explain The Bucket"],
            focus_representatives,
            font="footnotesize",
            tabcolsep="3.0pt",
        )
        lines.append(
            r"These examples are evidence anchors, not the whole population. The direct-front examples show the remembered public surface. The platform-anchor examples show the rare but important matrix certificates. The ambiguous examples show why the cohort cannot be reduced to a single neat story without losing the migration and legacy residue that made these names memorable in the first place."
        )

    lines.append(r"\Needspace{12\baselineskip}")
    lines.append(r"\section{Making The Whole Estate Make Sense}")
    add_summary(
        [
            "The certificate, DNS, and CAA layers are not three separate stories. They are three views of the same operating estate.",
            "Naming shows role and organisational memory; DNS shows where traffic lands; CAA shows how tightly issuance is governed.",
            "Clean public brand names usually sit closest to the customer surface, while dense SAN sets, numbered families, multi-zone certificates, and narrower CAA policy usually expose the shared platform layer beneath them.",
            "When the layers disagree, the disagreement usually signals migration or uneven governance maturity rather than a flat contradiction.",
            "The overall pattern is more consistent with a federated operating model with uneven governance maturity than with random hostname sprawl.",
        ]
    )
    lines.append(
        r"The common ground is operational reality. A branded proposition wants recognisable names. A service team wants a stable endpoint namespace. A platform team wants shared rails and repeatable delivery machinery. A hosting team wants routable front doors that can land on cloud distribution, gateways, or workflow platforms. A security or PKI function wants some names tightly governed and other names left broad or delegated. Certificates, DNS, and CAA tell the same estate story from different angles."
    )
    lines.append(
        r"A useful way to combine the layers is to ask four questions in order. First, what does the name itself look like: a direct front door, a numbered rail, an environment slice, or a bridge across business zones? Second, how broad is the SAN set: is this one visible service or a bundled platform certificate? Third, where does public DNS actually land the name: direct host, CDN edge, API gateway, campaign rail, or specialist platform? Fourth, does DNS issuance policy stay broad, narrow sharply, or disappear entirely?"
    )
    lines.append(
        r"When those answers align, the reading becomes strong. A small-SAN branded name with ordinary inherited policy reads like a direct public front. A dense multi-zone certificate with numbered families, managed DNS landing, and narrower CAA reads like a shared operational rail. A name that lands on AWS but still uses a Sectigo-family certificate shows that hosting choice and CA choice are separate decisions. A name with current overlap and current policy mismatch shows a transition area where the newer issuance model is already in place but the older certificate state has not fully disappeared."
    )
    lines.append(
        r"This is why the estate can look both tidy and messy at once. It is tidy within each layer, but messy across layers because the layers are solving different problems. The new CAA evidence sharpens that point rather than contradicting it: the managed rail families are not only named and hosted differently, they are often policy-controlled differently as well. The biggest qualification is that governance is uneven. The primary configured zone shows layered issuance control, while another configured zone remains CAA-empty. That is not random chaos, but it is also not uniform control maturity."
    )

    lines.append(r"\section{Limits, Confidence, and Noise}")
    add_summary(
        [
            "High-confidence claims are tied directly to certificate fields, DNS answers, live trust records, and current CAA policy.",
            "Medium-confidence claims are organisational readings drawn from repeated technical patterns.",
            "Lower-confidence claims are exact expansions of abbreviations and exact ownership boundaries inferred from names alone.",
            "A public NXDOMAIN today does not automatically contradict a valid certificate because DNS and certificate lifecycles move on different clocks.",
            "A current CAA mismatch does not by itself prove historical CA non-compliance, because DNS policy may have changed after issuance.",
        ]
    )
    lines.append(
        r"A useful way to read the corpus is to separate signal from noise. Repeated naming schemas are signal. Repeated DNS outcomes are signal. Which public CA family keeps issuing a name is signal. Where CAA is broad, narrow, delegated, or absent is signal. Simple \texttt{www} presence or absence is weak evidence either way unless it coincides with stronger differences such as distinct DNS routing, distinct SAN composition, a distinct certificate renewal history, or a distinct issuance-policy shape."
    )

    lines.extend(
        [
            r"\clearpage",
            r"\appendix",
            r"\section{Full Family Catalogue}",
            r"This appendix is a compact family map. It is not the place for full per-certificate evidence; that remains in the detailed inventory appendix at the end of the monograph.",
        ]
    )
    append_longtable(
        lines,
        r">{\raggedright\arraybackslash}p{0.56\linewidth} >{\raggedleft\arraybackslash}p{0.09\linewidth} >{\raggedleft\arraybackslash}p{0.08\linewidth} >{\raggedright\arraybackslash}p{0.18\linewidth}",
        ["Family Basis", "Certs", "CNs", "Dominant Stack"],
        family_rows,
        font="footnotesize",
        tabcolsep="3.0pt",
    )

    lines.extend(
        [
            r"\section{Historical Red-Flag Detail}",
            r"This appendix keeps the detailed historical evidence inside the monograph so that the reader does not need a second report. Each subsection answers one narrow question. If a column does not help answer that question, it has been removed.",
            r"In this appendix, a renewal family means repeated certificates that keep the same apparent identity over time: the same Subject CN, the same full Subject DN, the same SAN profile, and the same CA family.",
            r"\subsection{Current Red-Flag Inventory}",
        ]
    )
    if assessment.current_red_flag_rows:
        append_longtable(
            lines,
            r">{\raggedright\arraybackslash}p{0.28\linewidth} >{\raggedleft\arraybackslash}p{0.09\linewidth} >{\raggedright\arraybackslash}p{0.24\linewidth} >{\raggedright\arraybackslash}p{0.27\linewidth}",
            ["Subject CN", "Live Certs", "Current Concern", "Supporting Context"],
            [
                [
                    row.subject_cn,
                    str(row.current_certificate_count),
                    row.flags,
                    truncate_text(row.notes, 84),
                ]
                for row in assessment.current_red_flag_rows
            ],
            font="footnotesize",
            tabcolsep="3.0pt",
        )
    else:
        lines.append(r"No current red flags were found.")
    lines.append(r"\subsection{Past Red-Flag Inventory Now Fixed}")
    if assessment.past_red_flag_rows:
        append_longtable(
            lines,
            r">{\raggedright\arraybackslash}p{0.28\linewidth} >{\raggedleft\arraybackslash}p{0.09\linewidth} >{\raggedright\arraybackslash}p{0.24\linewidth} >{\raggedright\arraybackslash}p{0.27\linewidth}",
            ["Subject CN", "Historic Certs", "Historical Concern", "Supporting Context"],
            [
                [
                    row.subject_cn,
                    str(row.certificate_count),
                    row.flags,
                    truncate_text(row.notes, 84),
                ]
                for row in assessment.past_red_flag_rows
            ],
            font="footnotesize",
            tabcolsep="3.0pt",
        )
    else:
        lines.append(r"No past-only red flags were found.")
    lines.append(r"\subsection{Current Overlap Red Flags}")
    if assessment.overlap_current_rows:
        append_longtable(
            lines,
            r">{\raggedright\arraybackslash}p{0.21\linewidth} >{\raggedleft\arraybackslash}p{0.10\linewidth} >{\raggedleft\arraybackslash}p{0.08\linewidth} >{\raggedright\arraybackslash}p{0.51\linewidth}",
            ["Subject CN", "Max Overlap Days", "Live Certs", "What The Renewal Family Looks Like"],
            [
                [
                    row.subject_cn,
                    str(row.max_overlap_days),
                    str(row.current_certificate_count),
                    f"{row.lineage}; {overlap_signal(row.details)}",
                ]
                for row in assessment.overlap_current_rows
            ],
            font="footnotesize",
            tabcolsep="3.0pt",
        )
    else:
        lines.append(r"No current overlap red flags were found.")
    lines.append(r"\subsection{Past Overlap Red Flags Now Fixed}")
    if assessment.overlap_past_rows:
        append_longtable(
            lines,
            r">{\raggedright\arraybackslash}p{0.21\linewidth} >{\raggedleft\arraybackslash}p{0.10\linewidth} >{\raggedleft\arraybackslash}p{0.09\linewidth} >{\raggedright\arraybackslash}p{0.52\linewidth}",
            ["Subject CN", "Max Overlap Days", "Historic Certs", "What The Renewal Family Looks Like"],
            [
                [
                    row.subject_cn,
                    str(row.max_overlap_days),
                    str(row.asset_variant_count),
                    f"{row.lineage}; {overlap_signal(row.details)}",
                ]
                for row in assessment.overlap_past_rows
            ],
            font="footnotesize",
            tabcolsep="3.0pt",
        )
    else:
        lines.append(r"No past overlap red flags were found.")
    lines.append(r"\subsection{Current Subject-DN Drift}")
    if assessment.dn_current_rows:
        append_longtable(
            lines,
            r">{\raggedright\arraybackslash}p{0.25\linewidth} >{\raggedleft\arraybackslash}p{0.10\linewidth} >{\raggedleft\arraybackslash}p{0.08\linewidth} >{\raggedright\arraybackslash}p{0.45\linewidth}",
            ["Subject CN", "Distinct Subject DNs", "Live Certs", "Subject DN Samples"],
            [
                [
                    row.subject_cn,
                    str(row.distinct_value_count),
                    str(row.current_certificate_count),
                    truncate_text(row.details, 92),
                ]
                for row in assessment.dn_current_rows
            ],
            font="footnotesize",
            tabcolsep="3.0pt",
        )
    else:
        lines.append(r"No current Subject-DN drift was found.")
    lines.append(r"\subsection{Past Subject-DN Drift Now Fixed}")
    if assessment.dn_past_rows:
        append_longtable(
            lines,
            r">{\raggedright\arraybackslash}p{0.25\linewidth} >{\raggedleft\arraybackslash}p{0.10\linewidth} >{\raggedleft\arraybackslash}p{0.09\linewidth} >{\raggedright\arraybackslash}p{0.45\linewidth}",
            ["Subject CN", "Distinct Subject DNs", "Historic Certs", "Subject DN Samples"],
            [
                [
                    row.subject_cn,
                    str(row.distinct_value_count),
                    str(row.certificate_count),
                    truncate_text(row.details, 92),
                ]
                for row in assessment.dn_past_rows
            ],
            font="footnotesize",
            tabcolsep="3.0pt",
        )
    else:
        lines.append(r"No past-only Subject-DN drift was found.")
    lines.append(r"\subsection{Current CA-Family Drift}")
    if assessment.vendor_current_rows:
        append_longtable(
            lines,
            r">{\raggedright\arraybackslash}p{0.27\linewidth} >{\raggedleft\arraybackslash}p{0.10\linewidth} >{\raggedleft\arraybackslash}p{0.08\linewidth} >{\raggedright\arraybackslash}p{0.45\linewidth}",
            ["Subject CN", "Distinct CA Families", "Live Certs", "CA Families Seen"],
            [
                [
                    row.subject_cn,
                    str(row.distinct_value_count),
                    str(row.current_certificate_count),
                    truncate_text(row.details, 92),
                ]
                for row in assessment.vendor_current_rows
            ],
            font="footnotesize",
            tabcolsep="3.0pt",
        )
    else:
        lines.append(r"No current CA-family drift was found.")
    lines.append(r"\subsection{Past CA-Family Drift Now Fixed}")
    if assessment.vendor_past_rows:
        append_longtable(
            lines,
            r">{\raggedright\arraybackslash}p{0.27\linewidth} >{\raggedleft\arraybackslash}p{0.10\linewidth} >{\raggedleft\arraybackslash}p{0.09\linewidth} >{\raggedright\arraybackslash}p{0.45\linewidth}",
            ["Subject CN", "Distinct CA Families", "Historic Certs", "CA Families Seen"],
            [
                [
                    row.subject_cn,
                    str(row.distinct_value_count),
                    str(row.certificate_count),
                    truncate_text(row.details, 92),
                ]
                for row in assessment.vendor_past_rows
            ],
            font="footnotesize",
            tabcolsep="3.0pt",
        )
    else:
        lines.append(r"No past-only CA-family drift was found.")
    lines.append(r"\subsection{Current SAN Drift}")
    if assessment.san_current_rows:
        append_longtable(
            lines,
            r">{\raggedright\arraybackslash}p{0.21\linewidth} >{\raggedleft\arraybackslash}p{0.08\linewidth} >{\raggedleft\arraybackslash}p{0.08\linewidth} >{\raggedright\arraybackslash}p{0.18\linewidth} >{\raggedright\arraybackslash}p{0.35\linewidth}",
            ["Subject CN", "Profiles", "Live Certs", "Delta Pattern", "Representative Delta"],
            [
                [
                    row.subject_cn,
                    str(row.distinct_san_profiles),
                    str(row.current_certificate_count),
                    row.delta_pattern,
                    truncate_text(row.representative_delta, 92),
                ]
                for row in assessment.san_current_rows
            ],
            font="footnotesize",
            tabcolsep="3.0pt",
        )
    else:
        lines.append(r"No current SAN drift was found.")
    lines.append(r"\subsection{Past SAN Drift Now Fixed}")
    if assessment.san_past_rows:
        append_longtable(
            lines,
            r">{\raggedright\arraybackslash}p{0.21\linewidth} >{\raggedleft\arraybackslash}p{0.08\linewidth} >{\raggedleft\arraybackslash}p{0.09\linewidth} >{\raggedright\arraybackslash}p{0.18\linewidth} >{\raggedright\arraybackslash}p{0.35\linewidth}",
            ["Subject CN", "Profiles", "Historic Certs", "Delta Pattern", "Representative Delta"],
            [
                [
                    row.subject_cn,
                    str(row.distinct_san_profiles),
                    str(row.certificate_count),
                    row.delta_pattern,
                    truncate_text(row.representative_delta, 92),
                ]
                for row in assessment.san_past_rows
            ],
            font="footnotesize",
            tabcolsep="3.0pt",
        )
    else:
        lines.append(r"No past-only SAN drift was found.")
    lines.append(r"\subsection{Historic Start Dates}")
    append_longtable(
        lines,
        r">{\raggedright\arraybackslash}p{0.16\linewidth} >{\raggedleft\arraybackslash}p{0.10\linewidth} >{\raggedright\arraybackslash}p{0.62\linewidth}",
        ["Start Day", "Certificates", "Dominant Driver"],
        [
            [
                row.start_day,
                str(row.certificate_count),
                driver_summary(row.top_subjects, row.top_issuers),
            ]
            for row in assessment.day_rows
        ],
        font="footnotesize",
        tabcolsep="3.0pt",
    )
    lines.append(r"\subsection{Historic Step Weeks}")
    if assessment.week_rows:
        append_longtable(
            lines,
            r">{\raggedright\arraybackslash}p{0.16\linewidth} >{\raggedleft\arraybackslash}p{0.09\linewidth} >{\raggedleft\arraybackslash}p{0.13\linewidth} >{\raggedright\arraybackslash}p{0.52\linewidth}",
            ["Week Start", "Certs", "Prior 8-Week Avg", "Dominant Driver"],
            [
                [
                    row.week_start,
                    str(row.certificate_count),
                    row.prior_eight_week_avg,
                    driver_summary(row.top_subjects, row.top_issuers),
                ]
                for row in assessment.week_rows
            ],
            font="footnotesize",
            tabcolsep="3.0pt",
        )
    else:
        lines.append(r"No step weeks met the threshold.")

    lines.extend(
        [
            r"\section{CAA Policy Detail}",
            r"This appendix keeps the issuance-policy evidence inside the monograph. It answers a narrower question than the DNS appendix: not where a name lands, but which public CA families DNS currently authorizes to issue for that name.",
            r"\subsection{CAA Discovery Paths}",
        ]
    )
    append_longtable(
        lines,
        r">{\raggedright\arraybackslash}p{0.23\linewidth} >{\raggedleft\arraybackslash}p{0.10\linewidth} >{\raggedright\arraybackslash}p{0.55\linewidth}",
        ["CAA Discovery Result", "Names", "Meaning"],
        caa_source_rows(caa_analysis),
        font="footnotesize",
        tabcolsep="3.0pt",
    )
    lines.append(r"\subsection{Policy Regimes By Configured Zone}")
    for zone in caa_analysis.configured_domains:
        lines.append(rf"\subsubsection{{{latex_escape(zone)}}}")
        append_longtable(
            lines,
            r">{\raggedright\arraybackslash}p{0.24\linewidth} >{\raggedleft\arraybackslash}p{0.10\linewidth} >{\raggedright\arraybackslash}p{0.56\linewidth}",
            ["Policy Regime", "Names", "Plain-Language Meaning"],
            caa_zone_rows[zone],
            font="footnotesize",
            tabcolsep="3.0pt",
        )
    lines.append(r"\subsection{Current Multi-Family Overlap}")
    if caa_analysis.multi_family_overlap_names:
        lines.extend(
            [
                r"\begin{longtable}{>{\raggedright\arraybackslash}p{0.29\linewidth} >{\raggedright\arraybackslash}p{0.14\linewidth} >{\raggedright\arraybackslash}p{0.17\linewidth} >{\raggedright\arraybackslash}p{0.28\linewidth}}",
                r"\toprule",
                r"DNS Name & Zone & Live CA Families & Covering Subject CNs \\",
                r"\midrule",
            ]
        )
        for name, zone, families, subjects in top_caa_overlap_rows(caa_analysis, 40):
            lines.append(rf"{latex_escape(name)} & {latex_escape(zone)} & {latex_escape(families)} & {latex_escape(subjects)} \\")
        lines.extend([r"\bottomrule", r"\end{longtable}"])
    else:
        lines.append(r"No current multi-family overlap names were found.")
    lines.append(r"\subsection{Current Policy Mismatch}")
    if caa_analysis.policy_mismatch_names:
        lines.extend(
            [
                r"\begin{longtable}{>{\raggedright\arraybackslash}p{0.27\linewidth} >{\raggedright\arraybackslash}p{0.12\linewidth} >{\raggedright\arraybackslash}p{0.16\linewidth} >{\raggedright\arraybackslash}p{0.18\linewidth} >{\raggedright\arraybackslash}p{0.17\linewidth}}",
                r"\toprule",
                r"DNS Name & Zone & Live CA Families & CAA-Allowed Families & CAA Discovery Result \\",
                r"\midrule",
            ]
        )
        for name, zone, families, allowed, result in top_caa_mismatch_rows(caa_analysis, 40):
            lines.append(rf"{latex_escape(name)} & {latex_escape(zone)} & {latex_escape(families)} & {latex_escape(allowed)} & {latex_escape(result)} \\")
        lines.extend([r"\bottomrule", r"\end{longtable}"])
    else:
        lines.append(r"No current policy-mismatch names were found.")

    if focus_analysis:
        lines.extend(
            [
                r"\section{Focused Subject-CN Detail}",
                r"This appendix keeps the complete focused-cohort table inside the monograph, but it now follows the three-bucket taxonomy from Chapter 8. That makes it easier to read the cohort as a set of related naming traditions instead of as one flat mixed list.",
            ]
        )
        appendix_buckets = [
            ("direct_front_door", r"\subsection{Front-Door Direct Names}"),
            ("platform_matrix_anchor", r"\subsection{Platform-Anchor Matrix Names}"),
            ("ambiguous_legacy", r"\subsection{Ambiguous Or Legacy Residue}"),
        ]
        for bucket, heading in appendix_buckets:
            lines.append(heading)
            lines.append(
                rf"{latex_escape(ct_focus_subjects.taxonomy_bucket_label(bucket))} count: {focus_analysis.bucket_counts.get(bucket, 0)}."
            )
            rows = focus_appendix_rows(focus_analysis, bucket)
            if rows:
                lines.extend(
                    [
                        r"\begin{longtable}{>{\raggedright\arraybackslash}p{0.16\linewidth} >{\raggedright\arraybackslash}p{0.18\linewidth} >{\raggedright\arraybackslash}p{0.12\linewidth} >{\raggedright\arraybackslash}p{0.15\linewidth} >{\raggedright\arraybackslash}p{0.06\linewidth} >{\raggedright\arraybackslash}p{0.07\linewidth} >{\raggedright\arraybackslash}p{0.07\linewidth} >{\raggedright\arraybackslash}p{0.10\linewidth} >{\raggedright\arraybackslash}p{0.10\linewidth} >{\raggedright\arraybackslash}p{0.07\linewidth} >{\raggedright\arraybackslash}p{0.07\linewidth}}",
                        r"\toprule",
                        r"Subject CN & Bucket Rationale & Analyst Note & Observed Role & Direct C/H & Carried C/H & SANs C/H & Current DNS Outcome & Current Revocation Mix & Current Flags & Past Flags \\",
                        r"\midrule",
                    ]
                )
                for row in rows:
                    lines.append(
                        rf"{latex_escape(row[0])} & {latex_escape(row[1])} & {latex_escape(row[2])} & {latex_escape(row[3])} & {latex_escape(row[4])} & {latex_escape(row[5])} & {latex_escape(row[6])} & {latex_escape(row[7])} & {latex_escape(row[8])} & {latex_escape(row[9])} & {latex_escape(row[10])} \\"
                    )
                lines.extend([r"\bottomrule", r"\end{longtable}"])
            else:
                lines.append(r"No subjects fell into this bucket.")

    lines.extend(
        [
            r"\section{Detailed Inventory Appendix}",
            r"This appendix reproduces the full issuer-first family inventory so that the publication remains complete rather than merely interpretive.",
            rf"\includepdf[pages=-,pagecommand={{}}]{{{latex_escape(appendix_pdf_path)}}}",
            r"\end{document}",
        ]
    )
    def soften_heading(line: str) -> str:
        if line.startswith(r"\subsection{"):
            return line.replace(r"\subsection{", r"\SoftSubsection{", 1)
        if line.startswith(r"\subsubsection{"):
            return line.replace(r"\subsubsection{", r"\SoftSubsubsection{", 1)
        return line

    args.latex_output.write_text(
        "\n".join(soften_heading(line) for line in lines) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    args = parse_args()
    report = ct_master_report.summarize_for_report(args)
    assessment = ct_lineage_report.build_assessment(build_history_args(args))
    caa_analysis = ct_caa_analysis.build_analysis(
        report["hits"],
        report["domains"],
        args.caa_cache_dir,
        args.caa_cache_ttl_seconds,
    )
    focus_subjects = ct_focus_subjects.load_focus_subjects(args.focus_subjects_file)
    focus_analysis = ct_focus_subjects.build_analysis(
        focus_subjects,
        report,
        assessment,
        args.dns_cache_dir,
        args.dns_cache_ttl_seconds,
    )
    render_appendix_inventory(args, report)
    render_markdown(args, report, assessment, caa_analysis, focus_analysis)
    render_latex(args, report, assessment, caa_analysis, focus_analysis)
    if not args.skip_pdf:
        ct_scan.compile_latex_to_pdf(args.latex_output, args.pdf_output, args.pdf_engine)
    if not args.quiet:
        print(
            f"[report] markdown={args.markdown_output} latex={args.latex_output}"
            + ("" if args.skip_pdf else f" pdf={args.pdf_output}"),
            file=__import__("sys").stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
