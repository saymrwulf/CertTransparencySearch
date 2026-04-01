# ct_usage_assessment.py

Source file: [`ct_usage_assessment.py`](../ct_usage_assessment.py)

Certificate-purpose analyzer. This file looks at EKU and KeyUsage to decide what each certificate is technically allowed to do.

Main flow in one line: `certificate bytes -> EKU and KeyUsage -> purpose label -> summary counts`

How to read this page:

- left side: the actual source code block
- right side: a plain-English explanation for a beginner
- read from top to bottom because later blocks depend on earlier ones

## Module setup

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">#!/usr/bin/env python3

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


SERVER_AUTH_OID = &quot;1.3.6.1.5.5.7.3.1&quot;
CLIENT_AUTH_OID = &quot;1.3.6.1.5.5.7.3.2&quot;
CODE_SIGNING_OID = &quot;1.3.6.1.5.5.7.3.3&quot;
EMAIL_PROTECTION_OID = &quot;1.3.6.1.5.5.7.3.4&quot;
TIME_STAMPING_OID = &quot;1.3.6.1.5.5.7.3.8&quot;
OCSP_SIGNING_OID = &quot;1.3.6.1.5.5.7.3.9&quot;
ANY_EXTENDED_KEY_USAGE_OID = &quot;2.5.29.37.0&quot;

EKU_LABELS = {
    SERVER_AUTH_OID: &quot;serverAuth&quot;,
    CLIENT_AUTH_OID: &quot;clientAuth&quot;,
    CODE_SIGNING_OID: &quot;codeSigning&quot;,
    EMAIL_PROTECTION_OID: &quot;emailProtection&quot;,
    TIME_STAMPING_OID: &quot;timeStamping&quot;,
    OCSP_SIGNING_OID: &quot;OCSPSigning&quot;,
    ANY_EXTENDED_KEY_USAGE_OID: &quot;anyExtendedKeyUsage&quot;,
}</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Purpose-analysis constants and small data shapes for EKU and KeyUsage classification.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>Module setup</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## PurposeClassification

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">@dataclass
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
    san_dns_names: list[str]</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>One certificate plus the usage label assigned to it.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>PurposeClassification</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## AssessmentSummary

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">@dataclass
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
    dual_eku_subject_cns_without_server_only_sibling: list[str]</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>The roll-up numbers that power the purpose chapter.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>AssessmentSummary</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## utc_now_iso

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def utc_now_iso() -&gt; str:
    return datetime.now(UTC).isoformat(timespec=&quot;seconds&quot;).replace(&quot;+00:00&quot;, &quot;Z&quot;)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_usage_assessment.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>utc_now_iso</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## parse_args

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def parse_args() -&gt; argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=&quot;Assess certificate intended usage from EKU and KeyUsage.&quot;
    )
    parser.add_argument(
        &quot;--domains-file&quot;,
        type=Path,
        default=Path(&quot;domains.local.txt&quot;),
        help=&quot;Configurable list of search domains, one per line.&quot;,
    )
    parser.add_argument(
        &quot;--cache-dir&quot;,
        type=Path,
        default=Path(&quot;.cache/ct-search&quot;),
        help=&quot;Directory used by ct_scan.py for cached CT results.&quot;,
    )
    parser.add_argument(
        &quot;--cache-ttl-seconds&quot;,
        type=int,
        default=86400,
        help=&quot;Reuse cached CT results up to this age before refreshing from crt.sh.&quot;,
    )
    parser.add_argument(
        &quot;--max-candidates&quot;,
        type=int,
        default=10000,
        help=&quot;Maximum raw crt.sh identity rows to inspect per configured domain.&quot;,
    )
    parser.add_argument(
        &quot;--attempts&quot;,
        type=int,
        default=3,
        help=&quot;Retry attempts for live crt.sh database queries.&quot;,
    )
    parser.add_argument(
        &quot;--markdown-output&quot;,
        type=Path,
        default=Path(&quot;output/certificate-purpose-assessment.md&quot;),
        help=&quot;Human-readable assessment output.&quot;,
    )
    parser.add_argument(
        &quot;--json-output&quot;,
        type=Path,
        default=Path(&quot;output/certificate-purpose-assessment.json&quot;),
        help=&quot;Machine-readable assessment output.&quot;,
    )
    parser.add_argument(
        &quot;--verbose&quot;,
        action=&quot;store_true&quot;,
        help=&quot;Print refresh activity to stderr.&quot;,
    )
    return parser.parse_args()</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This block defines the command-line knobs for the file: input paths, cache settings, output paths, and other runtime switches.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>parse_args</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## load_records

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def load_records(
    domains: list[str],
    cache_dir: Path,
    cache_ttl_seconds: int,
    max_candidates: int,
    attempts: int,
    verbose: bool,
) -&gt; list[ct_scan.DatabaseRecord]:
    all_records: list[ct_scan.DatabaseRecord] = []
    for domain in domains:
        records = ct_scan.load_cached_records(cache_dir, domain, cache_ttl_seconds, max_candidates)
        if records is None:
            records = ct_scan.query_domain(domain, max_candidates=max_candidates, attempts=attempts, verbose=verbose)
            ct_scan.store_cached_records(cache_dir, domain, max_candidates=max_candidates, records=records)
        all_records.extend(records)
    return all_records</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This block loads data from disk, cache, or an earlier stage so later code can work with it.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>load_records</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## extract_eku_oids

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def extract_eku_oids(cert: x509.Certificate) -&gt; list[str]:
    try:
        extension = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
    except x509.ExtensionNotFound:
        return []
    return sorted(oid.dotted_string for oid in extension.value)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This block pulls one specific piece of information out of a larger object.</p>
<p><strong>Flow arrows</strong></p><p>One certificate object. &#8594; <strong>extract_eku_oids</strong> &#8594; `classify_purpose` uses these OIDs to decide the category.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## extract_key_usage_flags

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def extract_key_usage_flags(cert: x509.Certificate) -&gt; list[str]:
    try:
        key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    except x509.ExtensionNotFound:
        return []
    flags: list[str] = []
    for attribute in (
        &quot;digital_signature&quot;,
        &quot;content_commitment&quot;,
        &quot;key_encipherment&quot;,
        &quot;data_encipherment&quot;,
        &quot;key_agreement&quot;,
        &quot;key_cert_sign&quot;,
        &quot;crl_sign&quot;,
    ):
        if getattr(key_usage, attribute):
            flags.append(attribute)
    if key_usage.key_agreement:
        if key_usage.encipher_only:
            flags.append(&quot;encipher_only&quot;)
        if key_usage.decipher_only:
            flags.append(&quot;decipher_only&quot;)
    return flags</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This block pulls one specific piece of information out of a larger object.</p>
<p><strong>Flow arrows</strong></p><p>One certificate object. &#8594; <strong>extract_key_usage_flags</strong> &#8594; `build_classifications` stores these flags as supporting evidence.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## classify_purpose

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def classify_purpose(eku_oids: list[str]) -&gt; str:
    eku_set = set(eku_oids)
    has_server = SERVER_AUTH_OID in eku_set or ANY_EXTENDED_KEY_USAGE_OID in eku_set
    has_client = CLIENT_AUTH_OID in eku_set or ANY_EXTENDED_KEY_USAGE_OID in eku_set
    has_code_signing = CODE_SIGNING_OID in eku_set
    has_email = EMAIL_PROTECTION_OID in eku_set

    if not eku_oids:
        return &quot;no_eku&quot;
    if has_server and not has_client and not has_code_signing and not has_email:
        return &quot;tls_server_only&quot;
    if has_server and has_client and not has_code_signing and not has_email:
        return &quot;tls_server_and_client&quot;
    if has_client and not has_server and not has_code_signing and not has_email:
        return &quot;client_auth_only&quot;
    if has_email and not has_server and not has_client and not has_code_signing:
        return &quot;smime_only&quot;
    if has_code_signing and not has_server and not has_client and not has_email:
        return &quot;code_signing_only&quot;
    return &quot;mixed_or_other&quot;</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This block applies rules and chooses a category label.</p>
<p><strong>Flow arrows</strong></p><p>The EKU OID list from one certificate. &#8594; <strong>classify_purpose</strong> &#8594; `build_classifications` turns that decision into a per-certificate record.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## format_eku_template

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def format_eku_template(eku_oids: list[str]) -&gt; str:
    if not eku_oids:
        return &quot;(none)&quot;
    return &quot;, &quot;.join(EKU_LABELS.get(oid, oid) for oid in eku_oids)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_usage_assessment.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>format_eku_template</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## format_key_usage_template

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def format_key_usage_template(flags: list[str]) -&gt; str:
    if not flags:
        return &quot;(missing)&quot;
    return &quot;, &quot;.join(flags)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_usage_assessment.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>format_key_usage_template</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## build_classifications

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def build_classifications(
    hits: list[ct_scan.CertificateHit],
    records: list[ct_scan.DatabaseRecord],
) -&gt; list[PurposeClassification]:
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
        san_dns_names = sorted(entry[4:] for entry in hit.san_entries if entry.startswith(&quot;DNS:&quot;))
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
    return results</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Walks through all current certificates and labels them by intended usage.</p>
<p><strong>Flow arrows</strong></p><p>The cleaned current hits plus raw records. &#8594; <strong>build_classifications</strong> &#8594; `summarize` compresses these rows into report-level counts.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## summarize

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def summarize(classifications: list[PurposeClassification], domains: list[str]) -&gt; AssessmentSummary:
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
        san_type_counts[&quot;DNSName&quot;] += len(item.san_dns_names)
        if item.subject_cn in set(item.san_dns_names):
            subject_cn_in_dns_san_count += 1
        else:
            subject_cn_not_in_dns_san_count += 1
        categories_by_canonical_cn[ct_scan.canonicalize_subject_cn(item.subject_cn)].add(item.category)

    dual_with_server_only = sorted(
        canonical_cn
        for canonical_cn, values in categories_by_canonical_cn.items()
        if &quot;tls_server_and_client&quot; in values and &quot;tls_server_only&quot; in values
    )
    dual_without_server_only = sorted(
        canonical_cn
        for canonical_cn, values in categories_by_canonical_cn.items()
        if values == {&quot;tls_server_and_client&quot;}
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
    )</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Compresses the per-certificate labels into counts, templates, and issuer breakdowns.</p>
<p><strong>Flow arrows</strong></p><p>The per-certificate purpose labels. &#8594; <strong>summarize</strong> &#8594; Current-state and monograph chapters use the summary counts and templates.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## render_markdown

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def render_markdown(summary: AssessmentSummary, classifications: list[PurposeClassification]) -&gt; str:
    lines: list[str] = []
    lines.append(&quot;# Certificate Purpose Assessment&quot;)
    lines.append(&quot;&quot;)
    lines.append(f&quot;Generated at: `{summary.generated_at_utc}`&quot;)
    lines.append(f&quot;Configured domains: `{&#x27;, &#x27;.join(summary.source_cache_domains)}`&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;## Headline Verdict&quot;)
    lines.append(&quot;&quot;)
    lines.append(f&quot;- Unique current leaf certificates assessed: **{summary.unique_leaf_certificates}**&quot;)
    lines.append(f&quot;- TLS server only: **{summary.category_counts.get(&#x27;tls_server_only&#x27;, 0)}**&quot;)
    lines.append(f&quot;- TLS server and client auth: **{summary.category_counts.get(&#x27;tls_server_and_client&#x27;, 0)}**&quot;)
    lines.append(f&quot;- Client auth only: **{summary.category_counts.get(&#x27;client_auth_only&#x27;, 0)}**&quot;)
    lines.append(f&quot;- S/MIME only: **{summary.category_counts.get(&#x27;smime_only&#x27;, 0)}**&quot;)
    lines.append(f&quot;- Code signing only: **{summary.category_counts.get(&#x27;code_signing_only&#x27;, 0)}**&quot;)
    lines.append(f&quot;- Mixed or other: **{summary.category_counts.get(&#x27;mixed_or_other&#x27;, 0)}**&quot;)
    lines.append(f&quot;- No EKU: **{summary.category_counts.get(&#x27;no_eku&#x27;, 0)}**&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;## What This Means&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;- The corpus contains **only TLS-capable certificates**. There are no client-only, S/MIME, or code-signing certificates.&quot;)
    lines.append(&quot;- All SAN entries seen in this corpus are DNS names.&quot;)
    lines.append(f&quot;- Subject CN appears literally in a DNS SAN for **{summary.subject_cn_in_dns_san_count} of {summary.unique_leaf_certificates}** certificates.&quot;)
    lines.append(&quot;- The only ambiguity is whether to keep or set aside the certificates whose EKU allows both `serverAuth` and `clientAuth`.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;## Rework Options&quot;)
    lines.append(&quot;&quot;)
    lines.append(f&quot;- Keep the full operational server corpus: **{summary.unique_leaf_certificates}** certificates.&quot;)
    lines.append(f&quot;- Keep only strict server-auth certificates: **{summary.category_counts.get(&#x27;tls_server_only&#x27;, 0)}** certificates.&quot;)
    lines.append(f&quot;- Create a review bucket for dual-EKU certificates: **{summary.category_counts.get(&#x27;tls_server_and_client&#x27;, 0)}** certificates.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;## EKU Templates&quot;)
    lines.append(&quot;&quot;)
    for template, count in summary.eku_templates.items():
        lines.append(f&quot;- `{template}`: {count}&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;## KeyUsage Templates&quot;)
    lines.append(&quot;&quot;)
    for template, count in summary.key_usage_templates.items():
        lines.append(f&quot;- `{template}`: {count}&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;## Issuer Breakdown&quot;)
    lines.append(&quot;&quot;)
    for category in sorted(summary.issuer_breakdown):
        lines.append(f&quot;### `{category}`&quot;)
        lines.append(&quot;&quot;)
        for issuer_name, count in summary.issuer_breakdown[category].items():
            lines.append(f&quot;- `{issuer_name}`: {count}&quot;)
        lines.append(&quot;&quot;)
    lines.append(&quot;## Time Pattern&quot;)
    lines.append(&quot;&quot;)
    dual_years = set(summary.validity_start_years.get(&quot;tls_server_and_client&quot;, {}))
    server_years = set(summary.validity_start_years.get(&quot;tls_server_only&quot;, {}))
    if dual_years and len(dual_years) == 1:
        lines.append(
            f&quot;- The dual-EKU bucket is entirely composed of certificates whose current validity starts in **{next(iter(sorted(dual_years)))}**.&quot;
        )
    if dual_years and server_years and dual_years != server_years:
        lines.append(&quot;- The year split suggests at least some change in issuance policy over time.&quot;)
    else:
        lines.append(&quot;- Time alone does not prove a migration. The stronger signal is the template split by issuer and EKU.&quot;)
    lines.append(&quot;&quot;)
    for category in sorted(summary.validity_start_years):
        year_counts = &quot;, &quot;.join(f&quot;{year}: {count}&quot; for year, count in summary.validity_start_years[category].items())
        lines.append(f&quot;- `{category}`: {year_counts}&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;## Interpretation&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;- The `tls_server_and_client` certificates still look like hostname certificates, not user or robot identity certificates.&quot;)
    lines.append(&quot;- Evidence: public DNS-style Subject CNs, DNS-only SANs, public WebPKI server-auth issuers, and no email or personal-name SAN material.&quot;)
    lines.append(&quot;- The most plausible reading is **legacy or permissive server certificate templates** that also included `clientAuth`, not a separate client-certificate estate.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;## Dual-EKU Hostname Overlap&quot;)
    lines.append(&quot;&quot;)
    lines.append(
        f&quot;- Dual-EKU subject CN families that also have a strict server-only sibling: **{len(summary.dual_eku_subject_cns_with_server_only_sibling)}**&quot;
    )
    lines.append(
        f&quot;- Dual-EKU subject CN families that currently appear only in the dual-EKU bucket: **{len(summary.dual_eku_subject_cns_without_server_only_sibling)}**&quot;
    )
    lines.append(&quot;&quot;)
    if summary.dual_eku_subject_cns_with_server_only_sibling:
        lines.append(&quot;### Dual-EKU Families With Server-Only Siblings&quot;)
        lines.append(&quot;&quot;)
        for subject_cn in summary.dual_eku_subject_cns_with_server_only_sibling:
            lines.append(f&quot;- `{subject_cn}`&quot;)
        lines.append(&quot;&quot;)
    if summary.dual_eku_subject_cns_without_server_only_sibling:
        lines.append(&quot;### Dual-EKU Families Without Server-Only Siblings&quot;)
        lines.append(&quot;&quot;)
        for subject_cn in summary.dual_eku_subject_cns_without_server_only_sibling:
            lines.append(f&quot;- `{subject_cn}`&quot;)
        lines.append(&quot;&quot;)
    lines.append(&quot;## Detailed Dual-EKU Certificates&quot;)
    lines.append(&quot;&quot;)
    dual_items = [item for item in classifications if item.category == &quot;tls_server_and_client&quot;]
    if not dual_items:
        lines.append(&quot;- None&quot;)
        lines.append(&quot;&quot;)
    else:
        for item in dual_items:
            dns_sample = &quot;, &quot;.join(item.san_dns_names[:8])
            if len(item.san_dns_names) &gt; 8:
                dns_sample += &quot;, ...&quot;
            lines.append(f&quot;### `{item.subject_cn}`&quot;)
            lines.append(&quot;&quot;)
            lines.append(f&quot;- Issuer: `{item.issuer_name}`&quot;)
            lines.append(f&quot;- Validity: `{item.valid_from_utc}` to `{item.valid_to_utc}`&quot;)
            lines.append(f&quot;- Matched search domains: `{&#x27;, &#x27;.join(item.matched_domains)}`&quot;)
            lines.append(f&quot;- EKU: `{format_eku_template(item.eku_oids)}`&quot;)
            lines.append(f&quot;- KeyUsage: `{format_key_usage_template(item.key_usage_flags)}`&quot;)
            lines.append(f&quot;- DNS SAN count: `{len(item.san_dns_names)}`&quot;)
            lines.append(f&quot;- DNS SAN sample: `{dns_sample}`&quot;)
            lines.append(&quot;&quot;)
    return &quot;\n&quot;.join(lines) + &quot;\n&quot;</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Writes the standalone purpose report.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>render_markdown</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## main

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def main() -&gt; int:
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
        &quot;summary&quot;: asdict(summary),
        &quot;verification&quot;: asdict(verification),
        &quot;classifications&quot;: [asdict(item) for item in classifications],
    }

    args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.markdown_output.write_text(markdown_payload, encoding=&quot;utf-8&quot;)
    args.json_output.write_text(json.dumps(json_payload, indent=2, sort_keys=True), encoding=&quot;utf-8&quot;)
    return 0</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>The standalone command-line entrypoint for the purpose analyzer.</p>
<p><strong>Flow arrows</strong></p><p>CLI arguments from the operator. &#8594; <strong>main</strong> &#8594; Runs the standalone purpose analysis end to end.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

