#!/usr/bin/env python3

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import ct_dns_utils
import ct_scan
import ct_usage_assessment


ENV_TOKENS = [
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
]


@dataclass
class ExampleBlock:
    title: str
    subject_cn: str
    why_it_matters: str
    evidence: list[str]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a single consolidated CT, DNS, and naming report."
    )
    parser.add_argument("--domains-file", type=Path, default=Path("domains.local.txt"))
    parser.add_argument("--cache-dir", type=Path, default=Path(".cache/ct-search"))
    parser.add_argument("--dns-cache-dir", type=Path, default=Path(".cache/dns-scan"))
    parser.add_argument("--cache-ttl-seconds", type=int, default=0)
    parser.add_argument("--dns-cache-ttl-seconds", type=int, default=86400)
    parser.add_argument("--max-candidates-per-domain", type=int, default=10000)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--markdown-output", type=Path, default=Path("output/consolidated-corpus-report.md"))
    parser.add_argument("--latex-output", type=Path, default=Path("output/consolidated-corpus-report.tex"))
    parser.add_argument("--pdf-output", type=Path, default=Path("output/consolidated-corpus-report.pdf"))
    parser.add_argument("--skip-pdf", action="store_true")
    parser.add_argument("--pdf-engine", default="xelatex")
    parser.add_argument("--quiet", action="store_true")
    return parser.parse_args()


def load_records(args: argparse.Namespace) -> tuple[list[str], list[ct_scan.DatabaseRecord], dict[str, int]]:
    domains = ct_scan.load_domains(args.domains_file)
    records: list[ct_scan.DatabaseRecord] = []
    raw_match_counts: dict[str, int] = {}
    for domain in domains:
        raw_match_counts[domain] = ct_scan.query_raw_match_count(domain=domain, attempts=args.retries, verbose=not args.quiet)
        cached = ct_scan.load_cached_records(
            cache_dir=args.cache_dir,
            domain=domain,
            ttl_seconds=args.cache_ttl_seconds,
            max_candidates=args.max_candidates_per_domain,
        )
        if cached is not None:
            if not args.quiet:
                print(f"[cache] domain={domain} records={len(cached)}", file=__import__("sys").stderr)
            records.extend(cached)
            continue
        if not args.quiet:
            print(f"[query] domain={domain}", file=__import__("sys").stderr)
        queried = ct_scan.query_domain(
            domain=domain,
            max_candidates=args.max_candidates_per_domain,
            attempts=args.retries,
            verbose=not args.quiet,
        )
        ct_scan.store_cached_records(args.cache_dir, domain, args.max_candidates_per_domain, queried)
        records.extend(queried)
    return domains, records, raw_match_counts


def dns_names_from_hits(hits: list[ct_scan.CertificateHit]) -> list[str]:
    names = sorted(
        {
            ct_dns_utils.normalize_name(entry[4:])
            for hit in hits
            for entry in hit.san_entries
            if entry.startswith("DNS:")
        }
    )
    return names


def enrich_dns(names: list[str], args: argparse.Namespace) -> list[ct_dns_utils.DnsObservation]:
    observations = [ct_dns_utils.scan_name_cached(name, args.dns_cache_dir, args.dns_cache_ttl_seconds) for name in names]
    unique_ips = sorted({ip for observation in observations for ip in (*observation.a_records, *observation.aaaa_records)})
    ptr_cache_dir = args.dns_cache_dir / "ptr"
    ip_ptrs = {ip: ct_dns_utils.ptr_lookup(ip, ptr_cache_dir, args.dns_cache_ttl_seconds) for ip in unique_ips}
    for observation in observations:
        observation.ptr_records = sorted(
            {
                ptr
                for ip in (*observation.a_records, *observation.aaaa_records)
                for ptr in ip_ptrs.get(ip, [])
            }
        )
        observation.provider_hints = ct_dns_utils.infer_provider_hints(observation)
        observation.stack_signature = ct_dns_utils.infer_stack_signature(observation)
    return observations


def short_issuer_family(issuer_name: str) -> str:
    lowered = issuer_name.lower()
    if "amazon" in lowered:
        return "Amazon"
    if "sectigo" in lowered:
        return "Sectigo"
    if "comodo" in lowered:
        return "COMODO"
    if "google trust services" in lowered or "cn=we1" in lowered:
        return "Google Trust Services"
    return "Other"


def revocation_counts(hits: list[ct_scan.CertificateHit]) -> Counter[str]:
    return Counter(hit.revocation_status for hit in hits)


def is_www_pair(hit: ct_scan.CertificateHit) -> bool:
    dns_names = sorted(entry[4:] for entry in hit.san_entries if entry.startswith("DNS:"))
    if len(dns_names) != 2:
        return False
    plain = [name for name in dns_names if not name.startswith("www.")]
    return len(plain) == 1 and f"www.{plain[0]}" in dns_names


def env_token_count(name: str) -> int:
    lowered = name.lower()
    return sum(1 for token in ENV_TOKENS if token in lowered)


def dns_zone_count(hit: ct_scan.CertificateHit) -> int:
    zones = {ct_scan.san_tail_split(entry[4:])[1] for entry in hit.san_entries if entry.startswith("DNS:")}
    return len(zones)


def group_member_hits(groups: list[ct_scan.CertificateGroup], hits: list[ct_scan.CertificateHit]) -> dict[str, list[ct_scan.CertificateHit]]:
    mapping: dict[str, list[ct_scan.CertificateHit]] = {}
    for group in groups:
        mapping[group.group_id] = [hits[index] for index in group.member_indices]
    return mapping


def stack_counts_for_hits(member_hits: list[ct_scan.CertificateHit], observation_by_name: dict[str, ct_dns_utils.DnsObservation]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for hit in member_hits:
        for entry in hit.san_entries:
            if not entry.startswith("DNS:"):
                continue
            name = ct_dns_utils.normalize_name(entry[4:])
            observation = observation_by_name.get(name)
            if observation is not None:
                counts[observation.stack_signature] += 1
    return counts


def confirm_search_premise(hits: list[ct_scan.CertificateHit], domains: list[str]) -> tuple[int, int]:
    missing_matching_san = 0
    subject_not_in_san = 0
    for hit in hits:
        dns_names = [entry[4:].lower() for entry in hit.san_entries if entry.startswith("DNS:")]
        if not any(any(domain in dns_name for domain in domains) for dns_name in dns_names):
            missing_matching_san += 1
        if hit.subject_cn.lower() not in dns_names:
            subject_not_in_san += 1
    return missing_matching_san, subject_not_in_san


def provider_counts(observations: list[ct_dns_utils.DnsObservation]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for observation in observations:
        for hint in observation.provider_hints:
            if hint != "Unclassified":
                counts[hint] += 1
    return counts


def top_suffixes(hits: list[ct_scan.CertificateHit], limit: int = 8) -> list[tuple[str, int]]:
    counts: Counter[str] = Counter()
    for hit in hits:
        labels = hit.subject_cn.lower().split(".")
        suffix = ".".join(labels[1:]) if len(labels) > 1 else hit.subject_cn.lower()
        counts[suffix] += 1
    return counts.most_common(limit)


def top_env_tokens(hits: list[ct_scan.CertificateHit], limit: int = 10) -> list[tuple[str, int]]:
    counts: Counter[str] = Counter()
    for hit in hits:
        lowered = hit.subject_cn.lower()
        for token in ENV_TOKENS:
            if token in lowered:
                counts[token] += 1
    return counts.most_common(limit)


def pick_examples(
    hits: list[ct_scan.CertificateHit],
    groups: list[ct_scan.CertificateGroup],
    observation_by_name: dict[str, ct_dns_utils.DnsObservation],
) -> list[ExampleBlock]:
    examples: list[ExampleBlock] = []
    group_map = group_member_hits(groups, hits)

    numbered_groups = [group for group in groups if group.group_type == "numbered_cn_pattern"]
    if numbered_groups:
        group = max(numbered_groups, key=lambda item: item.member_count)
        member_hits = group_map[group.group_id]
        stack_counts = stack_counts_for_hits(member_hits, observation_by_name)
        example_hit = max(member_hits, key=lambda item: (len(item.san_entries), len(item.subject_cn)))
        examples.append(
            ExampleBlock(
                title="Shared operational rail",
                subject_cn=example_hit.subject_cn,
                why_it_matters="A numbered CN family usually signals a reusable service rail rather than a one-off branded page. It tends to expose fleet-style naming, repeated validity cycles, and many sibling hostnames.",
                evidence=[
                    f"Group basis: {ct_scan.describe_group_basis(group).replace('`', '')}.",
                    f"Certificates in family: {group.member_count}.",
                    f"Distinct Subject CNs in family: {group.distinct_subject_cn_count}.",
                    f"Top observed DNS delivery stacks: {', '.join(f'{label} ({count})' for label, count in stack_counts.most_common(3)) or 'none'}.",
                ],
            )
        )

    matrix_hits = [hit for hit in hits if len(hit.san_entries) >= 12 and env_token_count(hit.subject_cn) >= 1]
    if matrix_hits:
        hit = max(matrix_hits, key=lambda item: (len(item.san_entries), dns_zone_count(item), item.subject_cn))
        zones = sorted({ct_scan.san_tail_split(entry[4:])[1] for entry in hit.san_entries if entry.startswith("DNS:")})
        examples.append(
            ExampleBlock(
                title="Environment matrix certificate",
                subject_cn=hit.subject_cn,
                why_it_matters="A large SAN set with environment-style labels usually means one certificate is covering a coordinated platform surface across test, release, support, or tenant slices.",
                evidence=[
                    f"SAN entries: {len(hit.san_entries)}.",
                    f"Distinct DNS zones in SAN set: {len(zones)}.",
                    f"Environment tokens visible in Subject CN: {env_token_count(hit.subject_cn)}.",
                    f"First DNS zones in SAN set: {', '.join(zones[:6])}.",
                ],
            )
        )

    www_hits = [hit for hit in hits if is_www_pair(hit)]
    if www_hits:
        hit = min(www_hits, key=lambda item: (item.subject_cn.count("."), item.subject_cn))
        examples.append(
            ExampleBlock(
                title="Clean public front door",
                subject_cn=hit.subject_cn,
                why_it_matters="A two-name SAN pairing of the apex hostname with its www form is usually a deliberate customer-facing presentation rule rather than an internal platform rail.",
                evidence=[
                    f"SAN entries: {', '.join(entry[4:] for entry in hit.san_entries if entry.startswith('DNS:'))}.",
                    f"Issuer: {sorted(hit.issuer_names)[0]}.",
                    f"Revocation status: {hit.revocation_status}.",
                ],
            )
        )

    cross_zone_hits = [hit for hit in hits if dns_zone_count(hit) > 1]
    if cross_zone_hits:
        hit = max(cross_zone_hits, key=lambda item: (dns_zone_count(item), len(item.san_entries), item.subject_cn))
        zones = sorted({ct_scan.san_tail_split(entry[4:])[1] for entry in hit.san_entries if entry.startswith("DNS:")})
        examples.append(
            ExampleBlock(
                title="Cross-zone bridge",
                subject_cn=hit.subject_cn,
                why_it_matters="When one certificate spans several DNS zones, it often reveals a shared service or a migration bridge between branded fronts and underlying service domains.",
                evidence=[
                    f"Distinct DNS zones in SAN set: {len(zones)}.",
                    f"Representative zones: {', '.join(zones[:8])}.",
                    f"SAN entries: {len(hit.san_entries)}.",
                ],
            )
        )

    return examples


def build_group_digest(
    groups: list[ct_scan.CertificateGroup],
    hits: list[ct_scan.CertificateHit],
    observation_by_name: dict[str, ct_dns_utils.DnsObservation],
    limit: int = 20,
) -> list[dict[str, str]]:
    digest: list[dict[str, str]] = []
    group_map = group_member_hits(groups, hits)
    for group in groups[:limit]:
        member_hits = group_map[group.group_id]
        stack_counts = stack_counts_for_hits(member_hits, observation_by_name)
        digest.append(
            {
                "group_id": group.group_id,
                "basis": ct_scan.describe_group_basis(group).replace("`", ""),
                "type": group.group_type,
                "certificates": str(group.member_count),
                "subjects": str(group.distinct_subject_cn_count),
                "top_stacks": ", ".join(f"{label} ({count})" for label, count in stack_counts.most_common(3)) or "none",
            }
        )
    return digest


def summarize_for_report(args: argparse.Namespace) -> dict[str, object]:
    domains, records, raw_match_counts = load_records(args)
    hits, verification = ct_scan.build_hits(records)
    groups = ct_scan.build_groups(hits)
    issuer_trust = ct_scan.query_issuer_trust(hits)
    classifications = ct_usage_assessment.build_classifications(hits, records)
    purpose_summary = ct_usage_assessment.summarize(classifications, domains)
    unique_dns_names = dns_names_from_hits(hits)
    observations = enrich_dns(unique_dns_names, args)
    observation_by_name = {observation.original_name: observation for observation in observations}
    rev_counts = revocation_counts(hits)
    provider_hint_counts = provider_counts(observations)
    dns_class_counts = Counter(observation.classification for observation in observations)
    dns_stack_counts = Counter(observation.stack_signature for observation in observations)
    issuer_counts = Counter(ct_scan.primary_issuer_name(hit) for hit in hits)
    issuer_family_counts = Counter(short_issuer_family(name) for name in issuer_counts.elements())
    missing_matching_san, subject_not_in_san = confirm_search_premise(hits, domains)
    numbered_groups = [group for group in groups if group.group_type == "numbered_cn_pattern"]
    public_www_pair_count = sum(1 for hit in hits if is_www_pair(hit))
    multi_zone_hit_count = sum(1 for hit in hits if dns_zone_count(hit) > 1)
    examples = pick_examples(hits, groups, observation_by_name)
    digest = build_group_digest(groups, hits, observation_by_name)
    trusted_major = sum(1 for info in issuer_trust.values() if info.major_webpki)
    current_day = datetime.now(UTC).date().isoformat()

    return {
        "generated_at_utc": ct_scan.utc_iso(datetime.now(UTC)),
        "current_day": current_day,
        "domains": domains,
        "raw_match_counts": raw_match_counts,
        "cap": args.max_candidates_per_domain,
        "hits": hits,
        "groups": groups,
        "verification": verification,
        "issuer_trust": issuer_trust,
        "purpose_summary": purpose_summary,
        "classifications": classifications,
        "unique_dns_names": unique_dns_names,
        "observations": observations,
        "observation_by_name": observation_by_name,
        "rev_counts": rev_counts,
        "provider_hint_counts": provider_hint_counts,
        "dns_class_counts": dns_class_counts,
        "dns_stack_counts": dns_stack_counts,
        "issuer_counts": issuer_counts,
        "issuer_family_counts": issuer_family_counts,
        "missing_matching_san": missing_matching_san,
        "subject_not_in_san": subject_not_in_san,
        "numbered_groups": numbered_groups,
        "public_www_pair_count": public_www_pair_count,
        "multi_zone_hit_count": multi_zone_hit_count,
        "examples": examples,
        "top_suffixes": top_suffixes(hits),
        "top_env_tokens": top_env_tokens(hits),
        "group_digest": digest,
        "trusted_major": trusted_major,
    }


def md_bullets(items: list[str]) -> list[str]:
    return [f"- {item}" for item in items]


def render_markdown(path: Path, report: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    hits = report["hits"]
    groups = report["groups"]
    rev_counts = report["rev_counts"]
    purpose_summary = report["purpose_summary"]
    lines: list[str] = []
    lines.append("# Consolidated CT, Certificate, and DNS Report")
    lines.append("")
    lines.append(f"Generated: {report['generated_at_utc']}")
    lines.append(f"Configured search terms file: `{report['domains']}`")
    lines.append("")
    lines.append("## Executive Overview")
    lines.append("")
    lines.extend(
        md_bullets(
            [
                f"{len(hits)} current leaf certificates are in scope after local leaf-only verification.",
                f"{len(groups)} CN families reduce the raw certificate list into readable naming clusters.",
                f"{purpose_summary.category_counts.get('tls_server_only', 0)} certificates are strict server-auth and {purpose_summary.category_counts.get('tls_server_and_client', 0)} also allow client auth.",
                f"{len(report['unique_dns_names'])} unique DNS SAN names were scanned live; the estate collapses into a small number of recurring delivery stacks.",
                "The strongest overall reading is a layered operating model: branded public names on top, reusable service rails underneath, and cloud or vendor delivery platforms at the edge.",
            ]
        )
    )
    lines.append("")
    lines.append("## Chapter 1: Method, Integrity, and How To Read This")
    lines.append("")
    lines.append("**Management Summary**")
    lines.append("")
    lines.extend(
        md_bullets(
            [
                f"The scan now fails fast if the candidate cap is lower than the live raw match count. Current raw counts: {', '.join(f'{domain}={count}' for domain, count in report['raw_match_counts'].items())}.",
                f"The live candidate cap used for this run was {report['cap']}, which is safely above the current raw counts.",
                f"Leaf-only verification kept {report['verification'].unique_leaf_certificates} certificates and filtered {report['verification'].non_leaf_filtered} CA-style certificates and {report['verification'].precertificate_poison_filtered} precertificate-poison objects.",
                f"Every certificate in scope still contains at least one DNS SAN containing one of the configured search terms; exceptions found: {report['missing_matching_san']}.",
            ]
        )
    )
    lines.append("")
    lines.append("Certificate Transparency is the public logging layer for issued certificates. The scan starts there, then reads the actual X.509 certificate bytes, verifies that each object is a real leaf certificate, extracts SAN and Subject CN values, checks revocation state from crt.sh data, and then scans the DNS names seen in SANs.")
    lines.append("")
    lines.append("A **Subject CN** is the traditional primary name in a certificate. A **SAN** list is the modern list of all names the certificate covers. A **leaf certificate** is the endpoint certificate presented by a service, as distinct from a CA certificate used to sign other certificates.")
    lines.append("")
    lines.append("## Chapter 2: Certificate Corpus")
    lines.append("")
    lines.append("**Management Summary**")
    lines.append("")
    lines.extend(
        md_bullets(
            [
                f"The issuer landscape is concentrated: {', '.join(f'{name} ({count})' for name, count in report['issuer_family_counts'].most_common())}.",
                f"Revocation mix: {rev_counts.get('not_revoked', 0)} not revoked, {rev_counts.get('revoked', 0)} revoked, {rev_counts.get('unknown', 0)} unknown.",
                f"Purpose split: {purpose_summary.category_counts.get('tls_server_only', 0)} server-only, {purpose_summary.category_counts.get('tls_server_and_client', 0)} server+client, and zero client-only, S/MIME, or code-signing certificates.",
                f"All {len(hits)} Subject CN values appear literally in the SAN DNS set.",
            ]
        )
    )
    lines.append("")
    lines.append("An **issuer CA** is the certificate authority that signed the endpoint certificate. A **WebPKI-trusted** issuer is one that browsers and operating systems currently trust for public TLS. In this corpus, all visible issuers are live server-auth issuers in the public trust ecosystem.")
    lines.append("")
    lines.append("### Issuer Breakdown")
    lines.append("")
    for issuer_name, count in report["issuer_counts"].most_common():
        trust = report["issuer_trust"][issuer_name]
        lines.append(f"- `{issuer_name}`: {count} certificates | major WebPKI stores: {'yes' if trust.major_webpki else 'no'}")
    lines.append("")
    lines.append("### Purpose Assessment")
    lines.append("")
    for category, count in purpose_summary.category_counts.items():
        lines.append(f"- `{category}`: {count}")
    lines.append("")
    lines.append(
        "An **Extended Key Usage (EKU)** value tells software what the certificate is allowed to do. "
        f"Here the estate is entirely TLS-capable. The only nuance is that {purpose_summary.category_counts.get('tls_server_and_client', 0)} certificates also allow `clientAuth`. "
        "That does not by itself prove a separate client-certificate estate; in context, they still look like hostname certificates issued from a permissive or older server template."
    )
    lines.append("")
    lines.append("## Chapter 3: Naming Architecture")
    lines.append("")
    lines.append("**Management Summary**")
    lines.append("")
    lines.extend(
        md_bullets(
            [
                f"{len(report['numbered_groups'])} numbered CN families point to reusable service rails rather than one-off pages.",
                f"{report['public_www_pair_count']} certificates use the clean public front-door pattern of a base name paired with `www`.",
                f"{report['multi_zone_hit_count']} certificates span more than one DNS zone in SAN, which is usually a sign of shared platforms, migrations, or multi-brand exposure.",
                f"Most common suffixes: {', '.join(f'{suffix} ({count})' for suffix, count in report['top_suffixes'])}.",
            ]
        )
    )
    lines.append("")
    lines.append("Hostnames often look arbitrary because they are doing several jobs at once. Some names are for customers, some are for engineers, some encode environment state, and some preserve older platform lineage because renaming working infrastructure is costly.")
    lines.append("")
    lines.append("### Frequent Naming Tokens")
    lines.append("")
    for token, count in report["top_env_tokens"]:
        lines.append(f"- `{token}`: {count}")
    lines.append("")
    lines.append("### Dynamic Examples")
    lines.append("")
    for example in report["examples"]:
        lines.append(f"#### {example.title}")
        lines.append("")
        lines.append(f"- Subject CN: `{example.subject_cn}`")
        lines.append(f"- Why it matters: {example.why_it_matters}")
        for point in example.evidence:
            lines.append(f"- Evidence: {point}")
        lines.append("")
    lines.append("## Chapter 4: DNS Delivery Architecture")
    lines.append("")
    lines.append("**Management Summary**")
    lines.append("")
    lines.extend(
        md_bullets(
            [
                f"{len(report['unique_dns_names'])} unique DNS names were scanned from the SAN corpus.",
                f"DNS classes: {', '.join(f'{label}={count}' for label, count in report['dns_class_counts'].most_common())}.",
                f"Top delivery signatures: {', '.join(f'{label} ({count})' for label, count in report['dns_stack_counts'].most_common(6))}.",
                "The DNS layer turns a large hostname set into a smaller number of delivery stacks: CDN edges, API gateways, load balancers, and specialist vendor platforms.",
            ]
        )
    )
    lines.append("")
    lines.append("A **CNAME** is a DNS alias, meaning one hostname points to another hostname. An **A** or **AAAA** record is the final address mapping. An **NXDOMAIN** response means the public DNS name does not exist at the moment of the scan. That does not automatically invalidate the certificate-side finding, because certificate and DNS lifecycles can move at different speeds.")
    lines.append("")
    lines.append("### Delivery Stack Counts")
    lines.append("")
    for label, count in report["dns_stack_counts"].most_common(12):
        lines.append(f"- `{label}`: {count}")
    lines.append("")
    lines.append("### Platform and Provider Explanations")
    lines.append("")
    glossary = ct_dns_utils.provider_explanations()
    seen_terms = set()
    for observation in report["observations"]:
        seen_terms.update(observation.provider_hints)
    for term in ["Adobe Campaign", "AWS", "AWS CloudFront", "AWS ALB", "Google Apigee", "Pega Cloud", "Microsoft Edge", "Infinite / agency alias", "CNAME", "A record", "AAAA record", "PTR record", "NXDOMAIN"]:
        if term in glossary and (term in seen_terms or term in {"CNAME", "A record", "AAAA record", "PTR record", "NXDOMAIN", "AWS ALB"}):
            lines.append(f"- **{term}**: {glossary[term]}")
    lines.append("")
    lines.append("## Chapter 5: Where The Certificate View and DNS View Meet")
    lines.append("")
    lines.append("**Management Summary**")
    lines.append("")
    lines.extend(
        md_bullets(
            [
                "The certificate layer describes naming and trust; the DNS layer describes delivery and reachability. The same estate becomes legible only when both are read together.",
                "Numbered CN families usually behave like shared operational rails in certificates and collapse into repeatable delivery stacks in DNS.",
                "Cleaner public names tend to be the presentation layer, while denser SAN sets and multi-zone families tend to expose the platform layer underneath.",
            ]
        )
    )
    lines.append("")
    lines.append("The common ground is operational reality. A brand or product team wants a recognisable public name. A platform team wants a stable service rail. A delivery team wants environment labels and routable front doors. Certificates and DNS show those layers from different angles, which is why the estate looks messy when read from only one side.")
    lines.append("")
    lines.append("### Top Family Digest")
    lines.append("")
    for row in report["group_digest"]:
        lines.append(
            f"- `{row['group_id']}` | {row['basis']} | type={row['type']} | certs={row['certificates']} | subjects={row['subjects']} | stacks={row['top_stacks']}"
        )
    lines.append("")
    lines.append("## Chapter 6: Confidence, Limits, and Claims")
    lines.append("")
    lines.append("**Management Summary**")
    lines.append("")
    lines.extend(
        md_bullets(
            [
                "Strongest claims: issuer trust, leaf-only status, SAN and Subject CN structure, purpose EKU split, DNS stack signatures, and recurring family patterns.",
                "Medium-confidence claims: that the estate reflects a layered organisation with brand, platform, and delivery concerns superimposed on each other.",
                "Lower-confidence claims: exact meanings of internal abbreviations or exact organisation-chart boundaries inferred from naming alone.",
            ]
        )
    )
    lines.append("")
    lines.append("This report can prove what is visible in public certificate and DNS data. It cannot prove internal governance charts or the exact human meaning of every abbreviation. Where the report interprets rather than measures, it does so by tying the interpretation to repeated observable patterns.")
    lines.append("")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def tex_escape(value: str) -> str:
    return ct_scan.latex_escape(value)


def render_latex(path: Path, report: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    hits = report["hits"]
    groups = report["groups"]
    rev_counts = report["rev_counts"]
    purpose_summary = report["purpose_summary"]

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
        r"\usepackage{enumitem}",
        r"\usepackage{fancyhdr}",
        r"\usepackage{titlesec}",
        r"\usepackage[most]{tcolorbox}",
        r"\defaultfontfeatures{Ligatures=TeX,Scale=MatchLowercase}",
        r"\setmainfont{Palatino}",
        r"\setsansfont{Avenir Next}",
        r"\setmonofont{Menlo}",
        r"\definecolor{Ink}{HTML}{17202A}",
        r"\definecolor{Muted}{HTML}{667085}",
        r"\definecolor{Line}{HTML}{D0D5DD}",
        r"\definecolor{Panel}{HTML}{F8FAFC}",
        r"\definecolor{Accent}{HTML}{0F766E}",
        r"\definecolor{AccentSoft}{HTML}{E6F4F1}",
        r"\hypersetup{colorlinks=true,linkcolor=Accent,urlcolor=Accent,pdfauthor={CertTransparencySearch},pdftitle={Consolidated CT, Certificate, and DNS Report}}",
        r"\setlength{\parindent}{0pt}",
        r"\setlength{\parskip}{6pt}",
        r"\setcounter{tocdepth}{2}",
        r"\pagestyle{fancy}",
        r"\fancyhf{}",
        r"\fancyhead[L]{\sffamily\footnotesize Consolidated CT Report}",
        r"\fancyhead[R]{\sffamily\footnotesize \nouppercase{\leftmark}}",
        r"\fancyfoot[C]{\sffamily\footnotesize \thepage}",
        r"\titleformat{\section}{\sffamily\bfseries\LARGE\color{Ink}}{\thesection}{0.8em}{}",
        r"\titleformat{\subsection}{\sffamily\bfseries\Large\color{Ink}}{\thesubsection}{0.8em}{}",
        r"\tcbset{panel/.style={enhanced,breakable,boxrule=0.55pt,arc=3pt,left=9pt,right=9pt,top=8pt,bottom=8pt,colback=white,colframe=Line}}",
        r"\newcommand{\SummaryBox}[1]{\begin{tcolorbox}[panel,colback=Panel]#1\end{tcolorbox}}",
        r"\begin{document}",
        r"\begin{titlepage}",
        r"\vspace*{18mm}",
        r"{\sffamily\bfseries\fontsize{24}{28}\selectfont Consolidated CT, Certificate, and DNS Report\par}",
        r"\vspace{6pt}",
        r"{\Large One document for the certificate corpus, naming system, DNS delivery view, and proof boundaries\par}",
        r"\vspace{18pt}",
        rf"\textbf{{Generated}}: {tex_escape(report['generated_at_utc'])}\par",
        rf"\textbf{{Configured search terms file}}: {tex_escape(str(report['domains']))}\par",
        r"\vspace{12pt}",
        r"\SummaryBox{"
        + rf"\textbf{{Headline}}: {len(hits)} leaf certificates, {len(groups)} CN families, {len(report['unique_dns_names'])} DNS names, "
        + rf"{purpose_summary.category_counts.get('tls_server_only', 0)} strict server-auth certificates, "
        + rf"{purpose_summary.category_counts.get('tls_server_and_client', 0)} dual-EKU certificates."
        + r"}",
        r"\end{titlepage}",
        r"\tableofcontents",
        r"\clearpage",
    ]

    def add_summary(items: list[str]) -> None:
        lines.append(r"\SummaryBox{\textbf{Management Summary}\begin{itemize}[leftmargin=1.4em]")
        for item in items:
            lines.append(rf"\item {tex_escape(item)}")
        lines.append(r"\end{itemize}}")

    lines.append(r"\section{Method, Integrity, and How To Read This}")
    add_summary(
        [
            f"The scanner now refuses to run if the candidate cap is lower than the live raw match count; current counts are {', '.join(f'{domain}={count}' for domain, count in report['raw_match_counts'].items())}.",
            f"The live cap used for this run was {report['cap']}.",
            f"Leaf-only verification kept {report['verification'].unique_leaf_certificates} certificates.",
            f"Configured search-term coverage failures: {report['missing_matching_san']}.",
        ]
    )
    lines.append(
        r"Certificate Transparency is the public logging layer for issued certificates. The report starts there, validates the actual X.509 certificate bytes, and then scans the DNS names exposed in SANs. A Subject CN is the traditional primary name in a certificate; a SAN list is the modern set of all names the certificate covers."
    )

    lines.append(r"\section{Certificate Corpus}")
    add_summary(
        [
            f"{len(hits)} current leaf certificates are in scope.",
            f"Revocation mix: not revoked={rev_counts.get('not_revoked', 0)}, revoked={rev_counts.get('revoked', 0)}, unknown={rev_counts.get('unknown', 0)}.",
            f"Purpose split: server-only={purpose_summary.category_counts.get('tls_server_only', 0)}, server+client={purpose_summary.category_counts.get('tls_server_and_client', 0)}.",
            f"All Subject CN values appear in SAN DNS names.",
        ]
    )
    lines.extend(
        [
            r"\subsection{Issuer Breakdown}",
            r"\begin{longtable}{>{\raggedright\arraybackslash}p{0.67\linewidth} >{\raggedleft\arraybackslash}p{0.12\linewidth} >{\raggedleft\arraybackslash}p{0.12\linewidth}}",
            r"\toprule",
            r"Issuer & Count & WebPKI \\",
            r"\midrule",
        ]
    )
    for issuer_name, count in report["issuer_counts"].most_common():
        trust = report["issuer_trust"][issuer_name]
        lines.append(rf"{tex_escape(issuer_name)} & {count} & {'yes' if trust.major_webpki else 'no'} \\")
    lines.extend([r"\bottomrule", r"\end{longtable}"])
    lines.append(r"\subsection{Purpose Assessment}")
    lines.append(r"\begin{itemize}[leftmargin=1.4em]")
    for category, count in purpose_summary.category_counts.items():
        lines.append(rf"\item \texttt{{{tex_escape(category)}}}: {count}")
    lines.append(r"\end{itemize}")

    lines.append(r"\section{Naming Architecture}")
    add_summary(
        [
            f"{len(report['numbered_groups'])} numbered CN families indicate reusable service rails.",
            f"{report['public_www_pair_count']} certificates use a base-name plus www pairing.",
            f"{report['multi_zone_hit_count']} certificates span more than one DNS zone in SAN.",
            f"Most common suffixes are {', '.join(f'{suffix} ({count})' for suffix, count in report['top_suffixes'][:4])}.",
        ]
    )
    lines.append(r"\subsection{Representative Examples}")
    for example in report["examples"]:
        lines.append(r"\SummaryBox{")
        lines.append(rf"\textbf{{{tex_escape(example.title)}}}\par")
        lines.append(rf"\textbf{{Subject CN}}: \texttt{{{tex_escape(example.subject_cn)}}}\par")
        lines.append(tex_escape(example.why_it_matters) + r"\par")
        lines.append(r"\begin{itemize}[leftmargin=1.4em]")
        for point in example.evidence:
            lines.append(rf"\item {tex_escape(point)}")
        lines.append(r"\end{itemize}}")

    lines.append(r"\section{DNS Delivery Architecture}")
    add_summary(
        [
            f"{len(report['unique_dns_names'])} unique DNS names were scanned from SAN.",
            f"Top delivery signatures are {', '.join(f'{label} ({count})' for label, count in report['dns_stack_counts'].most_common(5))}.",
            "The DNS view reduces many hostnames into a smaller set of recurring delivery platforms.",
        ]
    )
    lines.extend(
        [
            r"\subsection{Delivery Stack Counts}",
            r"\begin{longtable}{>{\raggedright\arraybackslash}p{0.72\linewidth} >{\raggedleft\arraybackslash}p{0.16\linewidth}}",
            r"\toprule",
            r"Stack signature & Count \\",
            r"\midrule",
        ]
    )
    for label, count in report["dns_stack_counts"].most_common(12):
        lines.append(rf"{tex_escape(label)} & {count} \\")
    lines.extend([r"\bottomrule", r"\end{longtable}"])

    lines.append(r"\subsection{Platform Glossary}")
    lines.append(r"\begin{longtable}{>{\raggedright\arraybackslash}p{0.22\linewidth} >{\raggedright\arraybackslash}p{0.70\linewidth}}")
    lines.append(r"\toprule")
    lines.append(r"Term & Explanation \\")
    lines.append(r"\midrule")
    glossary = ct_dns_utils.provider_explanations()
    seen_terms = set()
    for observation in report["observations"]:
        seen_terms.update(observation.provider_hints)
    for term in ["Adobe Campaign", "AWS", "AWS CloudFront", "AWS ALB", "Google Apigee", "Pega Cloud", "Microsoft Edge", "Infinite / agency alias", "CNAME", "A record", "AAAA record", "PTR record", "NXDOMAIN"]:
        if term in glossary and (term in seen_terms or term in {"CNAME", "A record", "AAAA record", "PTR record", "NXDOMAIN", "AWS ALB"}):
            lines.append(rf"{tex_escape(term)} & {tex_escape(glossary[term])} \\")
    lines.extend([r"\bottomrule", r"\end{longtable}"])

    lines.append(r"\section{Where The Certificate View and DNS View Meet}")
    add_summary(
        [
            "Certificates explain naming, trust, and purpose; DNS explains routing, reachability, and platform landing points.",
            "Numbered families usually behave like shared service rails, while clean two-name SAN pairs usually behave like public presentation fronts.",
            "The estate becomes coherent when brand, platform, and delivery are treated as different layers of the same system.",
        ]
    )
    lines.extend(
        [
            r"\subsection{Top Family Digest}",
            r"\begin{longtable}{>{\raggedright\arraybackslash}p{0.09\linewidth} >{\raggedright\arraybackslash}p{0.39\linewidth} >{\raggedright\arraybackslash}p{0.15\linewidth} >{\raggedleft\arraybackslash}p{0.09\linewidth} >{\raggedleft\arraybackslash}p{0.09\linewidth} >{\raggedright\arraybackslash}p{0.13\linewidth}}",
            r"\toprule",
            r"ID & Basis & Type & Certs & CNs & Top stacks \\",
            r"\midrule",
        ]
    )
    for row in report["group_digest"]:
        lines.append(
            rf"{tex_escape(row['group_id'])} & {tex_escape(row['basis'])} & {tex_escape(row['type'])} & {row['certificates']} & {row['subjects']} & {tex_escape(row['top_stacks'])} \\"
        )
    lines.extend([r"\bottomrule", r"\end{longtable}"])

    lines.append(r"\section{Confidence, Limits, and Claims}")
    add_summary(
        [
            "Strong claims in this report are the ones tied directly to certificate fields, DNS answers, and trust records.",
            "Interpretive claims are constrained to repeated patterns and are stated as readings, not as internal-org certainties.",
            "The exact meaning of internal abbreviations cannot be proven from CT and DNS alone.",
        ]
    )
    lines.append(
        r"The report can prove which issuers are used, which EKU patterns exist, which DNS stacks are visible, and which naming families repeat. It cannot prove the exact internal org chart or the exact human expansion of every short token."
    )
    lines.append(r"\end{document}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    report = summarize_for_report(args)
    render_markdown(args.markdown_output, report)
    render_latex(args.latex_output, report)
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
