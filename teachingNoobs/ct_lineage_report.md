# ct_lineage_report.py

Source file: [`ct_lineage_report.py`](../ct_lineage_report.py)

Historical analyzer. This file studies expired plus current certificates to find renewals, overlap, drift, and issuance bursts over time.

Main flow in one line: `historical CT rows -> historical certificates -> grouped by Subject CN -> overlap and drift checks -> red flags`

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
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.x509.oid import NameOID
from psycopg.rows import dict_row

import ct_scan


HISTORICAL_QUERY_SQL = &quot;&quot;&quot;
WITH ci AS (
    SELECT
        min(sub.certificate_id) AS id,
        min(sub.issuer_ca_id) AS issuer_ca_id,
        x509_commonName(sub.certificate) AS common_name,
        x509_subjectName(sub.certificate) AS subject_dn,
        x509_notBefore(sub.certificate) AS not_before,
        x509_notAfter(sub.certificate) AS not_after,
        encode(x509_serialNumber(sub.certificate), &#x27;hex&#x27;) AS serial_number,
        sub.certificate AS certificate
    FROM (
        SELECT cai.*
        FROM certificate_and_identities cai
        WHERE plainto_tsquery(&#x27;certwatch&#x27;, %(domain)s) @@ identities(cai.certificate)
          AND cai.name_value ILIKE %(name_pattern)s ESCAPE &#x27;\\&#x27;
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
      AND cr.serial_number = decode(ci.serial_number, &#x27;hex&#x27;)
    ORDER BY cr.last_seen_check_date DESC NULLS LAST
    LIMIT 1
) rev ON TRUE
LEFT JOIN LATERAL (
    SELECT
        count(*) FILTER (
            WHERE crl.error_message IS NULL
              AND crl.next_update &gt; now() AT TIME ZONE &#x27;UTC&#x27;
        ) AS active_crl_count,
        max(crl.last_checked) AS last_checked
    FROM crl
    WHERE crl.ca_id = ci.issuer_ca_id
) crl_state ON TRUE
WHERE cl.certificate_type = &#x27;Certificate&#x27;
ORDER BY ci.not_before ASC, cl.first_seen ASC NULLS LAST, ci.id ASC;
&quot;&quot;&quot;


ENV_TOKENS = {
    &quot;api&quot;,
    &quot;auth&quot;,
    &quot;developer&quot;,
    &quot;webbanking&quot;,
    &quot;sandbox&quot;,
    &quot;dev&quot;,
    &quot;test&quot;,
    &quot;qa&quot;,
    &quot;uat&quot;,
    &quot;preprod&quot;,
    &quot;prod&quot;,
    &quot;stage&quot;,
    &quot;stg&quot;,
    &quot;release&quot;,
    &quot;replica&quot;,
    &quot;support&quot;,
    &quot;hotfix&quot;,
    &quot;monitoring&quot;,
    &quot;mail&quot;,
    &quot;statement&quot;,
    &quot;update&quot;,
    &quot;secure&quot;,
}</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Historical query logic, data structures, and red-flag rules for certificate lifecycle analysis.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>Module setup</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## HistoricalCertificate

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">@dataclass
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
    serial_numbers: set[str] = field(default_factory=set)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>One certificate in the full time-based dataset, including expired ones.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>HistoricalCertificate</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## CnCollisionRow

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">@dataclass
class CnCollisionRow:
    subject_cn: str
    certificate_count: int
    current_certificate_count: int
    distinct_value_count: int
    issuer_families: str
    details: str</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>A table row for Subject-DN drift or issuer drift under the same Subject CN.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>CnCollisionRow</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## SanChangeRow

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">@dataclass
class SanChangeRow:
    subject_cn: str
    certificate_count: int
    current_certificate_count: int
    distinct_san_profiles: int
    stable_entries: int
    variable_entries: int
    delta_pattern: str
    representative_delta: str</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>A table row that describes SAN-profile change for one Subject CN.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>SanChangeRow</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## StartDayRow

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">@dataclass
class StartDayRow:
    start_day: str
    certificate_count: int
    top_subjects: str
    top_issuers: str</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This class is a structured container for one piece of data that later code passes around instead of juggling many loose variables.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>StartDayRow</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## StepWeekRow

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">@dataclass
class StepWeekRow:
    week_start: str
    certificate_count: int
    prior_eight_week_avg: str
    top_subjects: str
    top_issuers: str</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This class is a structured container for one piece of data that later code passes around instead of juggling many loose variables.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>StepWeekRow</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## OverlapRow

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">@dataclass
class OverlapRow:
    subject_cn: str
    asset_variant_count: int
    current_certificate_count: int
    lineage: str
    max_concurrent: int
    max_overlap_days: int
    overlap_class: str
    details: str</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>A table row describing long predecessor/successor overlap.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>OverlapRow</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## RedFlagRow

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">@dataclass
class RedFlagRow:
    subject_cn: str
    score: int
    certificate_count: int
    current_certificate_count: int
    flags: str
    notes: str</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>A compact summary row for names worth attention.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>RedFlagRow</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## HistoricalAssessment

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">@dataclass
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
    week_rows: list[StepWeekRow]</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>The full historical analysis bundle used by the monograph.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>HistoricalAssessment</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
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
        description=&quot;Analyse historical certificate lineage, CN reuse, issuer drift, SAN drift, and issuance bursts.&quot;
    )
    parser.add_argument(&quot;--domains-file&quot;, type=Path, default=Path(&quot;domains.local.txt&quot;))
    parser.add_argument(&quot;--cache-dir&quot;, type=Path, default=Path(&quot;.cache/ct-history-v2&quot;))
    parser.add_argument(&quot;--cache-ttl-seconds&quot;, type=int, default=0)
    parser.add_argument(&quot;--max-candidates-per-domain&quot;, type=int, default=10000)
    parser.add_argument(&quot;--retries&quot;, type=int, default=3)
    parser.add_argument(
        &quot;--markdown-output&quot;,
        type=Path,
        default=Path(&quot;output/corpus/certificate-lineage-report.md&quot;),
    )
    parser.add_argument(
        &quot;--latex-output&quot;,
        type=Path,
        default=Path(&quot;output/corpus/certificate-lineage-report.tex&quot;),
    )
    parser.add_argument(
        &quot;--pdf-output&quot;,
        type=Path,
        default=Path(&quot;output/corpus/certificate-lineage-report.pdf&quot;),
    )
    parser.add_argument(&quot;--skip-pdf&quot;, action=&quot;store_true&quot;)
    parser.add_argument(&quot;--pdf-engine&quot;, default=&quot;xelatex&quot;)
    parser.add_argument(&quot;--quiet&quot;, action=&quot;store_true&quot;)
    return parser.parse_args()</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This block defines the command-line knobs for the file: input paths, cache settings, output paths, and other runtime switches.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>parse_args</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## short_issuer

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def short_issuer(issuer_name: str) -&gt; str:
    lowered = issuer_name.lower()
    if &quot;amazon&quot; in lowered:
        return &quot;Amazon&quot;
    if &quot;sectigo&quot; in lowered or &quot;comodo&quot; in lowered:
        return &quot;Sectigo/COMODO&quot;
    if &quot;digicert&quot; in lowered:
        return &quot;DigiCert&quot;
    if &quot;symantec&quot; in lowered:
        return &quot;Symantec&quot;
    if &quot;verisign&quot; in lowered:
        return &quot;VeriSign&quot;
    if &quot;cloudflare&quot; in lowered:
        return &quot;Cloudflare&quot;
    if &quot;google trust services&quot; in lowered or &quot;cn=we1&quot; in lowered:
        return &quot;Google Trust Services&quot;
    return issuer_name</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_lineage_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>short_issuer</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## pct

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def pct(count: int, total: int) -&gt; str:
    if total &lt;= 0:
        return &quot;0.0%&quot;
    return f&quot;{(count / total) * 100:.1f}%&quot;</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This is a small helper that keeps the larger analytical code cleaner and easier to reuse.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>pct</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## md_table

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def md_table(headers: list[str], rows: list[list[str]]) -&gt; list[str]:
    lines = [
        &quot;| &quot; + &quot; | &quot;.join(headers) + &quot; |&quot;,
        &quot;| &quot; + &quot; | &quot;.join([&quot;---&quot;] * len(headers)) + &quot; |&quot;,
    ]
    for row in rows:
        lines.append(&quot;| &quot; + &quot; | &quot;.join(row) + &quot; |&quot;)
    return lines</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_lineage_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>md_table</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## extract_common_name

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def extract_common_name(cert: x509.Certificate) -&gt; str | None:
    attributes = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attributes:
        return None
    return attributes[0].value</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This block pulls one specific piece of information out of a larger object.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>extract_common_name</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## query_historical_domain

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def query_historical_domain(domain: str, max_candidates: int, attempts: int, quiet: bool) -&gt; list[ct_scan.DatabaseRecord]:
    raw_match_count = ct_scan.query_raw_match_count(domain=domain, attempts=attempts, verbose=not quiet)
    if raw_match_count &gt; max_candidates:
        raise ValueError(
            f&quot;domain={domain} raw identity matches={raw_match_count} exceed max_candidates={max_candidates}; &quot;
            f&quot;increase --max-candidates-per-domain to at least {raw_match_count} for a complete result set&quot;
        )
    params = {
        &quot;domain&quot;: domain,
        &quot;name_pattern&quot;: f&quot;%{ct_scan.escape_like(domain)}%&quot;,
        &quot;max_candidates&quot;: max_candidates,
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
                    f&quot;[warn] historical domain={domain} attempt={attempt}/{attempts} failed: {exc}&quot;,
                    file=__import__(&quot;sys&quot;).stderr,
                )
            __import__(&quot;time&quot;).sleep(min(2 ** attempt, 10))
    assert last_error is not None
    raise last_error</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Fetches the wider historical corpus for one search term.</p>
<p><strong>Flow arrows</strong></p><p>A configured search domain. &#8594; <strong>query_historical_domain</strong> &#8594; `load_records` uses it to build the wider historical corpus.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## load_records

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def load_records(args: argparse.Namespace) -&gt; tuple[list[str], list[ct_scan.DatabaseRecord]]:
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
                print(f&quot;[cache] historical domain={domain} records={len(cached)}&quot;, file=__import__(&quot;sys&quot;).stderr)
            all_records.extend(cached)
            continue
        if not args.quiet:
            print(f&quot;[query] historical domain={domain}&quot;, file=__import__(&quot;sys&quot;).stderr)
        queried = query_historical_domain(
            domain=domain,
            max_candidates=args.max_candidates_per_domain,
            attempts=args.retries,
            quiet=args.quiet,
        )
        ct_scan.store_cached_records(args.cache_dir, domain, args.max_candidates_per_domain, queried)
        all_records.extend(queried)
    return domains, all_records</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This block loads data from disk, cache, or an earlier stage so later code can work with it.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>load_records</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## build_certificates

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def build_certificates(records: list[ct_scan.DatabaseRecord]) -&gt; list[HistoricalCertificate]:
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
            subject_cn = record.common_name or extract_common_name(cert) or &quot;-&quot;
            revocation_status, revocation_date, _revocation_reason, _crtsh_crl_timestamp, _revocation_note = ct_scan.revocation_fields(record)
            effective_not_after = record.not_after
            if revocation_status == &quot;revoked&quot; and revocation_date is not None and revocation_date &lt; effective_not_after:
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
                current=record.not_before &lt;= now &lt;= record.not_after,
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
        if hit.first_seen is None or (record.first_seen is not None and record.first_seen &lt; hit.first_seen):
            hit.first_seen = record.first_seen
    return sorted(
        by_fingerprint.values(),
        key=lambda item: (
            item.subject_cn.casefold(),
            item.validity_not_before,
            item.fingerprint_sha256,
        ),
    )</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Converts raw DB rows into historical working objects.</p>
<p><strong>Flow arrows</strong></p><p>Historical `DatabaseRecord` rows. &#8594; <strong>build_certificates</strong> &#8594; `group_by_subject_cn` and all drift checks consume these normalized historical certificates.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## group_by_subject_cn

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def group_by_subject_cn(certificates: list[HistoricalCertificate]) -&gt; dict[str, list[HistoricalCertificate]]:
    groups: dict[str, list[HistoricalCertificate]] = defaultdict(list)
    for certificate in certificates:
        groups[certificate.subject_cn.lower()].append(certificate)
    return groups</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This block clusters related items together so later code can analyze them as families instead of as isolated rows.</p>
<p><strong>Flow arrows</strong></p><p>Historical certificates. &#8594; <strong>group_by_subject_cn</strong> &#8594; `dn_change_rows`, `issuer_change_rows`, `san_change_rows`, and `overlap_rows` all work off this grouping.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## summarize_name_list

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def summarize_name_list(values: set[str], limit: int = 3) -&gt; str:
    ordered = sorted(values, key=str.casefold)
    if len(ordered) &lt;= limit:
        return &quot;, &quot;.join(ordered)
    return &quot;, &quot;.join(ordered[:limit]) + f&quot;, ... (+{len(ordered) - limit} more)&quot;</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This block compresses many detailed rows into a smaller, easier-to-read summary.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>summarize_name_list</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## family_counter

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def family_counter(values: list[HistoricalCertificate]) -&gt; Counter[str]:
    return Counter(item.issuer_family for item in values)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_lineage_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>family_counter</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## dn_change_rows

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def dn_change_rows(cn_groups: dict[str, list[HistoricalCertificate]]) -&gt; list[CnCollisionRow]:
    rows: list[CnCollisionRow] = []
    for certificates in cn_groups.values():
        dns = {item.subject_dn for item in certificates}
        if len(dns) &lt;= 1:
            continue
        subject_cn = min({item.subject_cn for item in certificates}, key=str.casefold)
        rows.append(
            CnCollisionRow(
                subject_cn=subject_cn,
                certificate_count=len(certificates),
                current_certificate_count=sum(1 for item in certificates if item.current),
                distinct_value_count=len(dns),
                issuer_families=&quot;, &quot;.join(
                    f&quot;{name} ({count})&quot; for name, count in family_counter(certificates).most_common()
                ),
                details=summarize_name_list(dns, limit=2),
            )
        )
    return sorted(
        rows,
        key=lambda item: (-item.distinct_value_count, -item.certificate_count, item.subject_cn.casefold()),
    )</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Finds names whose formal Subject DN changed over time.</p>
<p><strong>Flow arrows</strong></p><p>CN-grouped historical certificates. &#8594; <strong>dn_change_rows</strong> &#8594; `build_assessment` uses these rows for Subject-DN drift sections.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## issuer_change_rows

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def issuer_change_rows(
    cn_groups: dict[str, list[HistoricalCertificate]],
) -&gt; tuple[list[CnCollisionRow], list[CnCollisionRow]]:
    exact_rows: list[CnCollisionRow] = []
    vendor_rows: list[CnCollisionRow] = []
    for certificates in cn_groups.values():
        issuer_names = {item.issuer_name for item in certificates}
        issuer_families = {item.issuer_family for item in certificates}
        subject_cn = min({item.subject_cn for item in certificates}, key=str.casefold)
        if len(issuer_names) &gt; 1:
            exact_rows.append(
                CnCollisionRow(
                    subject_cn=subject_cn,
                    certificate_count=len(certificates),
                    current_certificate_count=sum(1 for item in certificates if item.current),
                    distinct_value_count=len(issuer_names),
                    issuer_families=&quot;, &quot;.join(
                        f&quot;{name} ({count})&quot; for name, count in family_counter(certificates).most_common()
                    ),
                    details=summarize_name_list(issuer_names, limit=3),
                )
            )
        if len(issuer_families) &gt; 1:
            vendor_rows.append(
                CnCollisionRow(
                    subject_cn=subject_cn,
                    certificate_count=len(certificates),
                    current_certificate_count=sum(1 for item in certificates if item.current),
                    distinct_value_count=len(issuer_families),
                    issuer_families=&quot;, &quot;.join(
                        f&quot;{name} ({count})&quot; for name, count in family_counter(certificates).most_common()
                    ),
                    details=summarize_name_list(issuer_families, limit=4),
                )
            )
    ordering = lambda item: (-item.distinct_value_count, -item.certificate_count, item.subject_cn.casefold())
    return (sorted(exact_rows, key=ordering), sorted(vendor_rows, key=ordering))</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Finds names whose issuing CA family changed over time.</p>
<p><strong>Flow arrows</strong></p><p>CN-grouped historical certificates. &#8594; <strong>issuer_change_rows</strong> &#8594; `build_assessment` uses these rows for CA-family drift sections.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## classify_san_delta

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def classify_san_delta(delta_entries: set[str]) -&gt; str:
    dns_names = [entry[4:] for entry in delta_entries if entry.startswith(&quot;DNS:&quot;)]
    if not dns_names:
        return &quot;non-DNS SAN drift&quot;
    if all(name.startswith(&quot;www.&quot;) or f&quot;www.{name}&quot; in dns_names for name in dns_names):
        return &quot;www toggle&quot;
    zones = {ct_scan.san_tail_split(name)[1] for name in dns_names}
    if len(zones) &gt; 1:
        return &quot;cross-zone bridge change&quot;
    lowered = &quot; &quot;.join(dns_names).lower()
    if any(token in lowered for token in ENV_TOKENS) or any(char.isdigit() for char in lowered):
        return &quot;environment or fleet change&quot;
    if len(dns_names) &lt;= 3:
        return &quot;small alias change&quot;
    return &quot;broad SAN redesign&quot;</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This block applies rules and chooses a category label.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>classify_san_delta</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## representative_delta

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def representative_delta(delta_entries: set[str]) -&gt; str:
    values = sorted(delta_entries, key=str.casefold)
    if not values:
        return &quot;-&quot;
    if len(values) &lt;= 4:
        return &quot;, &quot;.join(values)
    return &quot;, &quot;.join(values[:4]) + f&quot;, ... (+{len(values) - 4} more)&quot;</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_lineage_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>representative_delta</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## san_change_rows

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def san_change_rows(cn_groups: dict[str, list[HistoricalCertificate]]) -&gt; tuple[list[SanChangeRow], Counter[str]]:
    rows: list[SanChangeRow] = []
    pattern_counts: Counter[str] = Counter()
    for certificates in cn_groups.values():
        profiles = {tuple(item.san_entries) for item in certificates}
        if len(profiles) &lt;= 1:
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
    return rows, pattern_counts</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Finds names whose SAN bundle changed over time.</p>
<p><strong>Flow arrows</strong></p><p>CN-grouped historical certificates. &#8594; <strong>san_change_rows</strong> &#8594; `build_assessment` uses these rows for SAN-drift sections.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## overlap_days

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def overlap_days(left: HistoricalCertificate, right: HistoricalCertificate) -&gt; int:
    start = max(left.validity_not_before, right.validity_not_before)
    end = min(left.effective_not_after, right.effective_not_after)
    if end &lt;= start:
        return 0
    return max(1, (end - start).days)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_lineage_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>overlap_days</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## overlap_class

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def overlap_class(days: int) -&gt; str:
    if days &lt;= 0:
        return &quot;no overlap&quot;
    if days &lt; 50:
        return &quot;normal rollover&quot;
    return &quot;red flag (&gt;=50 days)&quot;</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_lineage_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>overlap_class</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## build_asset_key

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def build_asset_key(certificate: HistoricalCertificate) -&gt; tuple[str, str, tuple[str, ...], str]:
    return (
        certificate.subject_cn.lower(),
        certificate.subject_dn,
        tuple(certificate.san_entries),
        certificate.issuer_family,
    )</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This block constructs a richer higher-level result from simpler inputs.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>build_asset_key</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## overlap_metrics

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def overlap_metrics(certificates: list[HistoricalCertificate]) -&gt; tuple[int, int]:
    if len(certificates) &lt; 2:
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
        active = [item for item in active if item.effective_not_after &gt; certificate.validity_not_before]
        for other in active:
            max_overlap = max(max_overlap, overlap_days(other, certificate))
        active.append(certificate)
        max_concurrent = max(max_concurrent, len(active))
    return (max_overlap, max_concurrent)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_lineage_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>overlap_metrics</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## overlap_row_from_asset

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def overlap_row_from_asset(
    asset_certificates: list[HistoricalCertificate],
    overlap_days_value: int,
    max_concurrent: int,
    details_prefix: str,
) -&gt; OverlapRow:
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
            f&quot;{details_prefix}; &quot;
            f&quot;DN={representative.subject_dn}; &quot;
            f&quot;SANs={len(representative.san_entries)}; &quot;
            f&quot;windows={&#x27;, &#x27;.join(f&#x27;{item.validity_not_before.date().isoformat()}-&gt;{item.effective_not_after.date().isoformat()}&#x27; for item in ordered[:4])}&quot;
            + (&quot;&quot; if len(ordered) &lt;= 4 else f&quot;, ... (+{len(ordered) - 4} more)&quot;)
        ),
    )</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_lineage_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>overlap_row_from_asset</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## overlap_rows

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def overlap_rows(cn_groups: dict[str, list[HistoricalCertificate]]) -&gt; tuple[list[OverlapRow], list[OverlapRow], int, int]:
    normal_reissuance = 0
    repeated_asset_count = 0
    current_red_flags: list[OverlapRow] = []
    past_red_flags: list[OverlapRow] = []
    for certificates in cn_groups.values():
        by_asset: dict[tuple[str, str, tuple[str, ...], str], list[HistoricalCertificate]] = defaultdict(list)
        for certificate in certificates:
            by_asset[build_asset_key(certificate)].append(certificate)
        for asset_certificates in by_asset.values():
            if len(asset_certificates) &lt; 2:
                continue
            repeated_asset_count += 1
            max_overlap, max_concurrent = overlap_metrics(asset_certificates)
            current_certificates = [item for item in asset_certificates if item.current]
            current_overlap, current_concurrent = overlap_metrics(current_certificates)
            if max_overlap &lt; 50:
                normal_reissuance += 1
                continue
            if current_overlap &gt;= 50:
                current_red_flags.append(
                    overlap_row_from_asset(
                        current_certificates,
                        current_overlap,
                        current_concurrent,
                        f&quot;current overlap persists; historical max overlap={max_overlap} days&quot;,
                    )
                )
                continue
            past_red_flags.append(
                overlap_row_from_asset(
                    asset_certificates,
                    max_overlap,
                    max_concurrent,
                    &quot;historical overlap reached red-flag territory, but no currently valid pair still does&quot;,
                )
            )
    ordering = lambda item: (-item.max_overlap_days, -item.max_concurrent, -item.asset_variant_count, item.subject_cn.casefold())
    return (
        sorted(current_red_flags, key=ordering),
        sorted(past_red_flags, key=ordering),
        normal_reissuance,
        repeated_asset_count,
    )</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Finds predecessor/successor pairs that overlap too long.</p>
<p><strong>Flow arrows</strong></p><p>CN-grouped historical certificates. &#8594; <strong>overlap_rows</strong> &#8594; `build_assessment` turns these into current and past overlap red flags.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## build_red_flag_rows

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def build_red_flag_rows(
    cn_groups: dict[str, list[HistoricalCertificate]],
    dn_rows: list[CnCollisionRow],
    vendor_rows: list[CnCollisionRow],
    san_rows: list[SanChangeRow],
    overlap_rows_: list[OverlapRow],
) -&gt; list[RedFlagRow]:
    dn_set = {row.subject_cn.lower() for row in dn_rows}
    vendor_set = {row.subject_cn.lower() for row in vendor_rows}
    san_set = {row.subject_cn.lower() for row in san_rows}
    overlap_set = {row.subject_cn.lower() for row in overlap_rows_}
    rows: list[RedFlagRow] = []
    for key, certificates in cn_groups.items():
        flags: list[str] = []
        if key in overlap_set:
            flags.append(&quot;overlap &gt;=50 days&quot;)
        if key in dn_set:
            flags.append(&quot;Subject DN drift&quot;)
        if key in vendor_set:
            flags.append(&quot;CA lineage drift&quot;)
        if key in san_set:
            flags.append(&quot;SAN drift&quot;)
        if not flags:
            continue
        issuer_mix = Counter(item.issuer_family for item in certificates)
        notes = &quot;, &quot;.join(f&quot;{name} ({count})&quot; for name, count in issuer_mix.most_common())
        rows.append(
            RedFlagRow(
                subject_cn=min({item.subject_cn for item in certificates}, key=str.casefold),
                score=len(flags),
                certificate_count=len(certificates),
                current_certificate_count=sum(1 for item in certificates if item.current),
                flags=&quot;, &quot;.join(flags),
                notes=notes,
            )
        )
    rows.sort(key=lambda item: (-item.score, -item.certificate_count, item.subject_cn.casefold()))
    return rows</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This block constructs a richer higher-level result from simpler inputs.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>build_red_flag_rows</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## top_start_days

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def top_start_days(certificates: list[HistoricalCertificate], limit: int = 12) -&gt; list[StartDayRow]:
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
                top_subjects=&quot;, &quot;.join(f&quot;{name} ({count})&quot; for name, count in subject_counts.most_common(4)),
                top_issuers=&quot;, &quot;.join(f&quot;{name} ({count})&quot; for name, count in issuer_counts.most_common()),
            )
        )
    return rows[:limit]</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_lineage_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>top_start_days</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## spike_weeks

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def spike_weeks(certificates: list[HistoricalCertificate], min_count: int = 8) -&gt; list[StepWeekRow]:
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
        if len(prior) &lt; 4:
            continue
        prior_avg = sum(prior) / len(prior)
        if current_count &lt; min_count:
            continue
        if current_count &lt; prior_avg * 2 and current_count &lt; prior_avg + 8:
            continue
        week_items = by_week[week]
        subject_counts = Counter(item.subject_cn for item in week_items)
        issuer_counts = Counter(item.issuer_family for item in week_items)
        rows.append(
            StepWeekRow(
                week_start=week.isoformat(),
                certificate_count=current_count,
                prior_eight_week_avg=f&quot;{prior_avg:.1f}&quot;,
                top_subjects=&quot;, &quot;.join(f&quot;{name} ({count})&quot; for name, count in subject_counts.most_common(4)),
                top_issuers=&quot;, &quot;.join(f&quot;{name} ({count})&quot; for name, count in issuer_counts.most_common()),
            )
        )
    return rows</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_lineage_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>spike_weeks</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## partition_collision_rows

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def partition_collision_rows(
    rows: list[CnCollisionRow],
    cn_groups: dict[str, list[HistoricalCertificate]],
    value_getter,
) -&gt; tuple[list[CnCollisionRow], list[CnCollisionRow]]:
    current_rows: list[CnCollisionRow] = []
    past_rows: list[CnCollisionRow] = []
    for row in rows:
        certificates = cn_groups[row.subject_cn.lower()]
        current_values = {value_getter(item) for item in certificates if item.current}
        if len(current_values) &gt; 1:
            current_rows.append(row)
        else:
            past_rows.append(row)
    return current_rows, past_rows</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_lineage_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>partition_collision_rows</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## partition_san_rows

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def partition_san_rows(
    rows: list[SanChangeRow],
    cn_groups: dict[str, list[HistoricalCertificate]],
) -&gt; tuple[list[SanChangeRow], list[SanChangeRow]]:
    current_rows: list[SanChangeRow] = []
    past_rows: list[SanChangeRow] = []
    for row in rows:
        certificates = cn_groups[row.subject_cn.lower()]
        current_profiles = {tuple(item.san_entries) for item in certificates if item.current}
        if len(current_profiles) &gt; 1:
            current_rows.append(row)
        else:
            past_rows.append(row)
    return current_rows, past_rows</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_lineage_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>partition_san_rows</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## build_assessment

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def build_assessment(args: argparse.Namespace) -&gt; HistoricalAssessment:
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
    )</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Runs the full historical workflow and returns the finished analytical bundle.</p>
<p><strong>Flow arrows</strong></p><p>Historical records from all configured domains. &#8594; <strong>build_assessment</strong> &#8594; The monograph and standalone historical reports consume this one big bundle.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## render_markdown

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def render_markdown(args: argparse.Namespace, assessment: HistoricalAssessment) -&gt; None:
    args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
    certificates = assessment.certificates
    current_count = sum(1 for item in certificates if item.current)
    cn_groups = assessment.cn_groups
    repeated_cn_count = sum(1 for values in cn_groups.values() if len(values) &gt; 1)
    same_cn_same_dn = sum(1 for values in cn_groups.values() if len(values) &gt; 1 and len({item.subject_dn for item in values}) == 1)

    lines: list[str] = []
    lines.append(&quot;# Historical Certificate Lineage Analysis&quot;)
    lines.append(&quot;&quot;)
    lines.append(f&quot;Generated: {ct_scan.utc_iso(datetime.now(UTC))}&quot;)
    lines.append(f&quot;Configured search terms file: `{args.domains_file.name}`&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;## Executive Summary&quot;)
    lines.append(&quot;&quot;)
    lines.extend(
        [
            f&quot;- Historical unique leaf certificates in scope: **{len(certificates)}**.&quot;,
            f&quot;- Currently valid subset inside that historical corpus: **{current_count}**.&quot;,
            f&quot;- Distinct Subject CN values: **{len(cn_groups)}**.&quot;,
            f&quot;- Subject CNs with more than one certificate over time: **{repeated_cn_count}**.&quot;,
            f&quot;- Renewal asset lineages with only normal rollover overlap (`&lt;50 days`): **{assessment.normal_reissuance_assets}**.&quot;,
            f&quot;- Renewal asset lineages with a current overlap red flag (`&gt;=50 days`): **{len(assessment.overlap_current_rows)}**.&quot;,
            f&quot;- Renewal asset lineages with a past-only overlap red flag now fixed: **{len(assessment.overlap_past_rows)}**.&quot;,
            f&quot;- Subject CN values with current red flags: **{len(assessment.current_red_flag_rows)}**.&quot;,
            f&quot;- Subject CN values with past-only red flags now fixed: **{len(assessment.past_red_flag_rows)}**.&quot;,
        ]
    )
    lines.append(&quot;&quot;)
    lines.append(&quot;This report treats Subject CN as a hostname label, not as a unique asset key. The point is to follow certificate lineage through renewals, issuer changes, SAN changes, and issuance bursts across both current and expired certificates, while separating normal rollover from red-flag behavior.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;## Reading Notes&quot;)
    lines.append(&quot;&quot;)
    lines.extend(
        [
            &quot;- **Subject CN** is the hostname placed in the certificate&#x27;s Common Name field.&quot;,
            &quot;- **Subject DN** is the full subject identity string, not just the hostname.&quot;,
            &quot;- **SAN profile** means the complete set of SAN entries carried by a certificate.&quot;,
            &quot;- **CA lineage** collapses exact issuer names into vendor-level families. In this report, legacy COMODO and Sectigo are treated as one lineage: `Sectigo/COMODO`.&quot;,
            &quot;- A **renewal asset lineage** means the same Subject CN, same Subject DN, same SAN profile, and same CA lineage reissued over time.&quot;,
            &quot;- Overlap threshold used here: anything `&lt;50 days` is treated as normal rollover; anything `&gt;=50 days` is treated as a red flag.&quot;,
            &quot;- A **past-only** red flag means the issue is visible historically, but no currently valid certificate still carries that same red-flag condition.&quot;,
            &quot;- A **current** red flag means at least one currently valid certificate still participates in that same red-flag condition.&quot;,
        ]
    )
    lines.append(&quot;&quot;)
    lines.append(&quot;## Chapter 1: Renewal Baseline Versus Overlap Red Flags&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;**Management Summary**&quot;)
    lines.append(&quot;&quot;)
    lines.extend(
        [
            f&quot;- {repeated_cn_count} of {len(cn_groups)} Subject CN values have more than one certificate across the historical corpus.&quot;,
            f&quot;- {assessment.repeated_asset_count} renewal asset lineages contain more than one certificate.&quot;,
            f&quot;- {assessment.normal_reissuance_assets} of those renewal asset lineages stay below the 50-day overlap threshold and fit the normal renewal model.&quot;,
            f&quot;- {len(assessment.overlap_current_rows)} renewal asset lineages still have a current overlap red flag.&quot;,
            f&quot;- {len(assessment.overlap_past_rows)} renewal asset lineages had an overlap red flag historically, but that issue is not current anymore.&quot;,
            f&quot;- {same_cn_same_dn} repeated Subject CN values keep the same Subject DN while rotating serial number, validity span, or SAN profile.&quot;,
        ]
    )
    lines.append(&quot;&quot;)
    lines.append(&quot;This is the baseline that matters before any anomaly analysis. Most service names are not single certificates frozen in time. They are lineages of certificates issued, renewed, and sometimes restructured under the same public hostname. The key distinction is whether successor and predecessor overlap only briefly, which is normal, or coexist for fifty days or longer, which is the threshold treated here as a red flag.&quot;)
    lines.append(&quot;&quot;)
    if assessment.overlap_current_rows:
        lines.append(&quot;### Current Overlap Red Flags&quot;)
        lines.append(&quot;&quot;)
        lines.extend(
            md_table(
                [&quot;Subject CN&quot;, &quot;Lineage&quot;, &quot;Asset Certs&quot;, &quot;Current&quot;, &quot;Max Concurrent&quot;, &quot;Max Overlap Days&quot;, &quot;Class&quot;, &quot;Asset Details&quot;],
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
        lines.append(&quot;&quot;)
    if assessment.overlap_past_rows:
        lines.append(&quot;### Past Overlap Red Flags Now Fixed&quot;)
        lines.append(&quot;&quot;)
        lines.extend(
            md_table(
                [&quot;Subject CN&quot;, &quot;Lineage&quot;, &quot;Asset Certs&quot;, &quot;Current&quot;, &quot;Max Concurrent&quot;, &quot;Max Overlap Days&quot;, &quot;Class&quot;, &quot;Asset Details&quot;],
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
        lines.append(&quot;&quot;)
    lines.append(&quot;## Chapter 2: Current Red Flags&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;**Management Summary**&quot;)
    lines.append(&quot;&quot;)
    lines.extend(
        [
            f&quot;- Current overlap red flags: {len(assessment.overlap_current_rows)} Subject-CN asset lineages.&quot;,
            f&quot;- Current Subject DN drift: {len(assessment.dn_current_rows)} Subject CN values.&quot;,
            f&quot;- Current CA lineage drift: {len(assessment.vendor_current_rows)} Subject CN values.&quot;,
            f&quot;- Current SAN drift: {len(assessment.san_current_rows)} Subject CN values.&quot;,
            &quot;- This chapter is the shortest route to the names that deserve present-tense manual review.&quot;,
        ]
    )
    lines.append(&quot;&quot;)
    if assessment.current_red_flag_rows:
        lines.extend(
            md_table(
                [&quot;Subject CN&quot;, &quot;Score&quot;, &quot;Certs&quot;, &quot;Current&quot;, &quot;Flags&quot;, &quot;Issuer Mix&quot;],
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
        lines.append(&quot;&quot;)
    else:
        lines.append(&quot;No current red flags were found under the configured rules.&quot;)
        lines.append(&quot;&quot;)
    lines.append(&quot;## Chapter 3: Past Red Flags Now Fixed&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;**Management Summary**&quot;)
    lines.append(&quot;&quot;)
    lines.extend(
        [
            f&quot;- Past-only overlap red flags now fixed: {len(assessment.overlap_past_rows)} Subject-CN asset lineages.&quot;,
            f&quot;- Past-only Subject DN drift now fixed: {len(assessment.dn_past_rows)} Subject CN values.&quot;,
            f&quot;- Past-only CA lineage drift now fixed: {len(assessment.vendor_past_rows)} Subject CN values.&quot;,
            f&quot;- Past-only SAN drift now fixed: {len(assessment.san_past_rows)} Subject CN values.&quot;,
            &quot;- These are not present-tense problems, but they matter because they show how the estate used to behave.&quot;,
        ]
    )
    lines.append(&quot;&quot;)
    if assessment.past_red_flag_rows:
        lines.extend(
            md_table(
                [&quot;Subject CN&quot;, &quot;Score&quot;, &quot;Certs&quot;, &quot;Current&quot;, &quot;Flags&quot;, &quot;Issuer Mix&quot;],
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
        lines.append(&quot;&quot;)
    else:
        lines.append(&quot;No historical red flags were found under the configured rules.&quot;)
        lines.append(&quot;&quot;)
    lines.append(&quot;## Chapter 4: Subject DN Drift&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;**Management Summary**&quot;)
    lines.append(&quot;&quot;)
    lines.extend(
        [
            f&quot;- Current Subject DN drift: {len(assessment.dn_current_rows)}.&quot;,
            f&quot;- Past-only Subject DN drift now fixed: {len(assessment.dn_past_rows)}.&quot;,
            f&quot;- Total Subject CN values with more than one Subject DN across history: {len(assessment.dn_rows)}.&quot;,
            &quot;- This is relevant because it means the hostname stayed the same while the full subject identity string changed.&quot;,
            &quot;- That does not automatically imply a security problem, but it is exactly the kind of drift that deserves review when you care about ownership, issuance policy, or certificate governance.&quot;,
        ]
    )
    lines.append(&quot;&quot;)
    if assessment.dn_current_rows:
        lines.append(&quot;### Current Subject DN Drift&quot;)
        lines.append(&quot;&quot;)
        lines.extend(
            md_table(
                [&quot;Subject CN&quot;, &quot;Certs&quot;, &quot;Current&quot;, &quot;Distinct Subject DNs&quot;, &quot;Issuer Families&quot;, &quot;Subject DN Samples&quot;],
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
        lines.append(&quot;&quot;)
    if assessment.dn_past_rows:
        lines.append(&quot;### Past Subject DN Drift Now Fixed&quot;)
        lines.append(&quot;&quot;)
        lines.extend(
            md_table(
                [&quot;Subject CN&quot;, &quot;Certs&quot;, &quot;Current&quot;, &quot;Distinct Subject DNs&quot;, &quot;Issuer Families&quot;, &quot;Subject DN Samples&quot;],
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
        lines.append(&quot;&quot;)
    if not assessment.dn_rows:
        lines.append(&quot;No cases were found.&quot;)
        lines.append(&quot;&quot;)
    lines.append(&quot;## Chapter 5: CA Lineage Drift&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;**Management Summary**&quot;)
    lines.append(&quot;&quot;)
    lines.extend(
        [
            f&quot;- Exact issuer-name changes across history: {len(assessment.issuer_rows)} Subject CN values.&quot;,
            f&quot;- Current CA lineage drift: {len(assessment.vendor_current_rows)} Subject CN values.&quot;,
            f&quot;- Past-only CA lineage drift now fixed: {len(assessment.vendor_past_rows)} Subject CN values.&quot;,
            &quot;- Exact issuer changes inside one lineage can be operationally normal. The stronger red flag is a drift between different CA lineages, with COMODO and Sectigo deliberately collapsed into one lineage here.&quot;,
        ]
    )
    lines.append(&quot;&quot;)
    if assessment.vendor_current_rows:
        lines.append(&quot;### Current CA Lineage Drift&quot;)
        lines.append(&quot;&quot;)
        lines.extend(
            md_table(
                [&quot;Subject CN&quot;, &quot;Certs&quot;, &quot;Current&quot;, &quot;Distinct Lineages&quot;, &quot;Lineage Mix&quot;, &quot;Lineages Seen&quot;],
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
        lines.append(&quot;&quot;)
    if assessment.vendor_past_rows:
        lines.append(&quot;### Past CA Lineage Drift Now Fixed&quot;)
        lines.append(&quot;&quot;)
        lines.extend(
            md_table(
                [&quot;Subject CN&quot;, &quot;Certs&quot;, &quot;Current&quot;, &quot;Distinct Lineages&quot;, &quot;Lineage Mix&quot;, &quot;Lineages Seen&quot;],
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
        lines.append(&quot;&quot;)
    if assessment.issuer_rows:
        lines.append(&quot;### Exact Issuer Changes Inside The Same Or Different Lineages&quot;)
        lines.append(&quot;&quot;)
        lines.extend(
            md_table(
                [&quot;Subject CN&quot;, &quot;Certs&quot;, &quot;Current&quot;, &quot;Distinct Issuers&quot;, &quot;Lineage Mix&quot;, &quot;Issuer Samples&quot;],
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
        lines.append(&quot;&quot;)
    lines.append(&quot;## Chapter 6: SAN Profile Drift&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;**Management Summary**&quot;)
    lines.append(&quot;&quot;)
    lines.extend(
        [
            f&quot;- Current SAN drift: {len(assessment.san_current_rows)} Subject CN values.&quot;,
            f&quot;- Past-only SAN drift now fixed: {len(assessment.san_past_rows)} Subject CN values.&quot;,
            f&quot;- Total Subject CN values with more than one distinct SAN profile across history: {len(assessment.san_rows)}.&quot;,
            f&quot;- Top SAN-delta pattern classes: {&#x27;, &#x27;.join(f&#x27;{name} ({count})&#x27; for name, count in assessment.san_pattern_counts.most_common()) or &#x27;none&#x27;}.&quot;,
            &quot;- This shows whether the service name stayed stable while the covered endpoint set expanded, contracted, or shifted shape.&quot;,
        ]
    )
    lines.append(&quot;&quot;)
    if assessment.san_current_rows:
        lines.append(&quot;### Current SAN Drift&quot;)
        lines.append(&quot;&quot;)
        lines.extend(
            md_table(
                [
                    &quot;Subject CN&quot;,
                    &quot;Certs&quot;,
                    &quot;Current&quot;,
                    &quot;SAN Profiles&quot;,
                    &quot;Stable SANs&quot;,
                    &quot;Variable SANs&quot;,
                    &quot;Delta Pattern&quot;,
                    &quot;Representative Delta&quot;,
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
        lines.append(&quot;&quot;)
    if assessment.san_past_rows:
        lines.append(&quot;### Past SAN Drift Now Fixed&quot;)
        lines.append(&quot;&quot;)
        lines.extend(
            md_table(
                [
                    &quot;Subject CN&quot;,
                    &quot;Certs&quot;,
                    &quot;Current&quot;,
                    &quot;SAN Profiles&quot;,
                    &quot;Stable SANs&quot;,
                    &quot;Variable SANs&quot;,
                    &quot;Delta Pattern&quot;,
                    &quot;Representative Delta&quot;,
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
        lines.append(&quot;&quot;)
    lines.append(&quot;## Chapter 7: Historic Issuance Bursts And Step Changes&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;**Management Summary**&quot;)
    lines.append(&quot;&quot;)
    lines.extend(
        [
            &quot;- This chapter includes expired certificates on purpose, because step changes are historical phenomena rather than current-only phenomena.&quot;,
            &quot;- Strong same-day or same-week issuance bursts usually signal planned renewal waves, platform migrations, or bulk onboarding of service families.&quot;,
            f&quot;- Top issuance start dates: {&#x27;, &#x27;.join(f&#x27;{row.start_day} ({row.certificate_count})&#x27; for row in assessment.day_rows[:6])}.&quot;,
        ]
    )
    lines.append(&quot;&quot;)
    lines.append(&quot;### Top Start Dates&quot;)
    lines.append(&quot;&quot;)
    lines.extend(
        md_table(
            [&quot;Start Day&quot;, &quot;Certificates&quot;, &quot;Top Subject CNs&quot;, &quot;Top Issuer Families&quot;],
            [[row.start_day, str(row.certificate_count), row.top_subjects, row.top_issuers] for row in assessment.day_rows],
        )
    )
    lines.append(&quot;&quot;)
    lines.append(&quot;### Step Weeks&quot;)
    lines.append(&quot;&quot;)
    if assessment.week_rows:
        lines.extend(
            md_table(
                [&quot;Week Start&quot;, &quot;Certificates&quot;, &quot;Prior 8-Week Avg&quot;, &quot;Top Subject CNs&quot;, &quot;Top Issuer Families&quot;],
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
        lines.append(&quot;&quot;)
    else:
        lines.append(&quot;No step weeks met the configured threshold.&quot;)
        lines.append(&quot;&quot;)
    lines.append(&quot;## Chapter 8: Interpretation&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;The main operational picture is not one of single certificates mapped one-to-one to service names. It is a layered certificate lineage model. The normal case is rollover inside a stable renewal asset lineage with less than fifty days of overlap. The red flags are the exceptions layered on top of that baseline: overlap that persists for fifty days or more, Subject DN drift, CA lineage drift, and SAN drift. The current-versus-past split matters because it distinguishes live governance concerns from issues that appear to have been corrected already.&quot;)
    lines.append(&quot;&quot;)
    args.markdown_output.write_text(&quot;\n&quot;.join(lines) + &quot;\n&quot;, encoding=&quot;utf-8&quot;)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Writes the standalone historical report in Markdown.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>render_markdown</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## render_latex

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def render_latex(args: argparse.Namespace, assessment: HistoricalAssessment) -&gt; None:
    args.latex_output.parent.mkdir(parents=True, exist_ok=True)
    certificates = assessment.certificates
    current_count = sum(1 for item in certificates if item.current)
    cn_groups = assessment.cn_groups
    repeated_cn_count = sum(1 for values in cn_groups.values() if len(values) &gt; 1)
    same_cn_same_dn = sum(1 for values in cn_groups.values() if len(values) &gt; 1 and len({item.subject_dn for item in values}) == 1)

    lines: list[str] = [
        r&quot;\documentclass[11pt]{article}&quot;,
        r&quot;\usepackage[a4paper,margin=18mm]{geometry}&quot;,
        r&quot;\usepackage{fontspec}&quot;,
        r&quot;\usepackage[table]{xcolor}&quot;,
        r&quot;\usepackage{microtype}&quot;,
        r&quot;\usepackage{hyperref}&quot;,
        r&quot;\usepackage{xurl}&quot;,
        r&quot;\usepackage{array}&quot;,
        r&quot;\usepackage{booktabs}&quot;,
        r&quot;\usepackage{longtable}&quot;,
        r&quot;\usepackage{enumitem}&quot;,
        r&quot;\usepackage{fancyhdr}&quot;,
        r&quot;\usepackage{titlesec}&quot;,
        r&quot;\usepackage[most]{tcolorbox}&quot;,
        r&quot;\usepackage{pdflscape}&quot;,
        r&quot;\defaultfontfeatures{Ligatures=TeX,Scale=MatchLowercase}&quot;,
        r&quot;\setmainfont{Palatino}&quot;,
        r&quot;\setsansfont{Avenir Next}&quot;,
        r&quot;\setmonofont{Menlo}&quot;,
        r&quot;\definecolor{Ink}{HTML}{17202A}&quot;,
        r&quot;\definecolor{Line}{HTML}{D0D5DD}&quot;,
        r&quot;\definecolor{Panel}{HTML}{F8FAFC}&quot;,
        r&quot;\definecolor{Accent}{HTML}{0F766E}&quot;,
        r&quot;\hypersetup{colorlinks=true,linkcolor=Accent,urlcolor=Accent,pdfauthor={CertTransparencySearch},pdftitle={Historical Certificate Lineage Analysis}}&quot;,
        r&quot;\setlength{\parindent}{0pt}&quot;,
        r&quot;\setlength{\parskip}{6pt}&quot;,
        r&quot;\setlength{\emergencystretch}{4em}&quot;,
        r&quot;\setlength{\headheight}{16pt}&quot;,
        r&quot;\setlength{\tabcolsep}{4.2pt}&quot;,
        r&quot;\renewcommand{\arraystretch}{1.12}&quot;,
        r&quot;\raggedbottom&quot;,
        r&quot;\setcounter{tocdepth}{2}&quot;,
        r&quot;\pagestyle{fancy}&quot;,
        r&quot;\fancyhf{}&quot;,
        r&quot;\renewcommand{\headrulewidth}{0pt}&quot;,
        r&quot;\fancyfoot[C]{\sffamily\footnotesize \thepage}&quot;,
        r&quot;\titleformat{\section}{\sffamily\bfseries\LARGE\color{Ink}\raggedright}{\thesection}{0.8em}{}&quot;,
        r&quot;\titleformat{\subsection}{\sffamily\bfseries\Large\color{Ink}\raggedright}{\thesubsection}{0.8em}{}&quot;,
        r&quot;\tcbset{panel/.style={enhanced,breakable,boxrule=0.55pt,arc=3pt,left=9pt,right=9pt,top=8pt,bottom=8pt,colback=white,colframe=Line}}&quot;,
        r&quot;\newcommand{\SummaryBox}[1]{\begin{tcolorbox}[panel,colback=Panel]#1\end{tcolorbox}}&quot;,
        r&quot;\begin{document}&quot;,
        r&quot;\begin{titlepage}&quot;,
        r&quot;\vspace*{18mm}&quot;,
        r&quot;{\sffamily\bfseries\fontsize{24}{28}\selectfont Historical Certificate Lineage Analysis\par}&quot;,
        r&quot;\vspace{8pt}&quot;,
        r&quot;{\Large A historical study of Subject CN reuse, subject drift, issuer drift, SAN drift, and issuance bursts\par}&quot;,
        r&quot;\vspace{18pt}&quot;,
        rf&quot;\textbf{{Generated}}: {ct_scan.latex_escape(ct_scan.utc_iso(datetime.now(UTC)))}\par&quot;,
        rf&quot;\textbf{{Configured search terms file}}: {ct_scan.latex_escape(args.domains_file.name)}\par&quot;,
        r&quot;\vspace{12pt}&quot;,
        r&quot;\SummaryBox{&quot;
        + rf&quot;\textbf{{Headline}}: {len(certificates)} historical leaf certificates, {current_count} currently valid, {len(cn_groups)} Subject CN values, {repeated_cn_count} multi-certificate CN lineages.&quot;
        + r&quot;}&quot;,
        r&quot;\end{titlepage}&quot;,
        r&quot;\tableofcontents&quot;,
        r&quot;\clearpage&quot;,
    ]

    def add_summary(items: list[str]) -&gt; None:
        lines.append(r&quot;\SummaryBox{\textbf{Management Summary}\begin{itemize}[leftmargin=1.4em]&quot;)
        for item in items:
            lines.append(rf&quot;\item {ct_scan.latex_escape(item)}&quot;)
        lines.append(r&quot;\end{itemize}}&quot;)

    lines.append(r&quot;\section{Executive Summary}&quot;)
    add_summary(
        [
            f&quot;Historical unique leaf certificates in scope: {len(certificates)}.&quot;,
            f&quot;Currently valid subset inside that historical corpus: {current_count}.&quot;,
            f&quot;Distinct Subject CN values: {len(cn_groups)}.&quot;,
            f&quot;Subject CN values with more than one certificate over time: {repeated_cn_count}.&quot;,
            f&quot;Normal renewal asset lineages with overlap below 50 days: {assessment.normal_reissuance_assets}.&quot;,
            f&quot;Current overlap red flags: {len(assessment.overlap_current_rows)}.&quot;,
            f&quot;Past-only overlap red flags now fixed: {len(assessment.overlap_past_rows)}.&quot;,
        ]
    )
    lines.append(
        r&quot;This report treats Subject CN as a hostname label, not as a unique asset key. The goal is to observe how certificate lineages evolve over time across renewals, issuer changes, SAN changes, and issuance bursts, while separating normal rollover from genuine red flags.&quot;
    )

    lines.append(r&quot;\section{Reading Notes}&quot;)
    lines.append(r&quot;\begin{itemize}[leftmargin=1.4em]&quot;)
    for item in [
        &quot;Subject CN is the hostname placed in the certificate&#x27;s Common Name field.&quot;,
        &quot;Subject DN is the full subject identity string, not just the hostname.&quot;,
        &quot;SAN profile means the complete set of SAN entries carried by a certificate.&quot;,
        &quot;CA lineage collapses exact issuer names into vendor-level families. Legacy COMODO and Sectigo are treated as one lineage here: Sectigo/COMODO.&quot;,
        &quot;A renewal asset lineage means the same Subject CN, same Subject DN, same SAN profile, and same CA lineage reissued over time.&quot;,
        &quot;The overlap threshold used here is simple: less than 50 days is normal rollover, 50 days or more is a red flag.&quot;,
        &quot;A past-only red flag means it appears historically but no currently valid certificate still carries that same condition.&quot;,
    ]:
        lines.append(rf&quot;\item {ct_scan.latex_escape(item)}&quot;)
    lines.append(r&quot;\end{itemize}&quot;)

    lines.append(r&quot;\section{Renewal Baseline Versus Overlap Red Flags}&quot;)
    add_summary(
        [
            f&quot;{repeated_cn_count} of {len(cn_groups)} Subject CN values have more than one certificate across the historical corpus.&quot;,
            f&quot;{assessment.repeated_asset_count} renewal asset lineages contain more than one certificate.&quot;,
            f&quot;{assessment.normal_reissuance_assets} of those renewal asset lineages stay below the 50-day overlap threshold and fit the normal renewal model.&quot;,
            f&quot;{len(assessment.overlap_current_rows)} still have a current overlap red flag.&quot;,
            f&quot;{len(assessment.overlap_past_rows)} had an overlap red flag historically, but that issue is not current anymore.&quot;,
            f&quot;{same_cn_same_dn} repeated Subject CN values keep the same Subject DN while rotating serial number, validity span, or SAN profile.&quot;,
        ]
    )
    lines.append(
        r&quot;The baseline is ordinary certificate rollover: successor and predecessor overlap briefly while deployment is switched over. The red flag is not reissuance itself, but overlap that persists for fifty days or longer for what otherwise looks like the same renewal asset lineage.&quot;
    )
    if assessment.overlap_current_rows:
        lines.append(r&quot;\subsection{Current Overlap Red Flags}&quot;)
        lines.extend(
            [
                r&quot;\begin{longtable}{&gt;{\raggedright\arraybackslash}p{0.14\linewidth} &gt;{\raggedright\arraybackslash}p{0.12\linewidth} &gt;{\raggedleft\arraybackslash}p{0.07\linewidth} &gt;{\raggedleft\arraybackslash}p{0.06\linewidth} &gt;{\raggedleft\arraybackslash}p{0.08\linewidth} &gt;{\raggedleft\arraybackslash}p{0.08\linewidth} &gt;{\raggedright\arraybackslash}p{0.13\linewidth} &gt;{\raggedright\arraybackslash}p{0.24\linewidth}}&quot;,
                r&quot;\toprule&quot;,
                r&quot;Subject CN &amp; Lineage &amp; Asset Certs &amp; Current &amp; Max Concurrent &amp; Max Overlap Days &amp; Class &amp; Asset Details \\&quot;,
                r&quot;\midrule&quot;,
            ]
        )
        for row in assessment.overlap_current_rows[:20]:
            lines.append(
                rf&quot;{ct_scan.latex_escape(row.subject_cn)} &amp; {ct_scan.latex_escape(row.lineage)} &amp; {row.asset_variant_count} &amp; {row.current_certificate_count} &amp; {row.max_concurrent} &amp; {row.max_overlap_days} &amp; {ct_scan.latex_escape(row.overlap_class)} &amp; {ct_scan.latex_escape(row.details)} \\&quot;
            )
        lines.extend([r&quot;\bottomrule&quot;, r&quot;\end{longtable}&quot;])
    if assessment.overlap_past_rows:
        lines.append(r&quot;\subsection{Past Overlap Red Flags Now Fixed}&quot;)
        lines.extend(
            [
                r&quot;\begin{longtable}{&gt;{\raggedright\arraybackslash}p{0.14\linewidth} &gt;{\raggedright\arraybackslash}p{0.12\linewidth} &gt;{\raggedleft\arraybackslash}p{0.07\linewidth} &gt;{\raggedleft\arraybackslash}p{0.06\linewidth} &gt;{\raggedleft\arraybackslash}p{0.08\linewidth} &gt;{\raggedleft\arraybackslash}p{0.08\linewidth} &gt;{\raggedright\arraybackslash}p{0.13\linewidth} &gt;{\raggedright\arraybackslash}p{0.24\linewidth}}&quot;,
                r&quot;\toprule&quot;,
                r&quot;Subject CN &amp; Lineage &amp; Asset Certs &amp; Current &amp; Max Concurrent &amp; Max Overlap Days &amp; Class &amp; Asset Details \\&quot;,
                r&quot;\midrule&quot;,
            ]
        )
        for row in assessment.overlap_past_rows[:20]:
            lines.append(
                rf&quot;{ct_scan.latex_escape(row.subject_cn)} &amp; {ct_scan.latex_escape(row.lineage)} &amp; {row.asset_variant_count} &amp; {row.current_certificate_count} &amp; {row.max_concurrent} &amp; {row.max_overlap_days} &amp; {ct_scan.latex_escape(row.overlap_class)} &amp; {ct_scan.latex_escape(row.details)} \\&quot;
            )
        lines.extend([r&quot;\bottomrule&quot;, r&quot;\end{longtable}&quot;])

    lines.append(r&quot;\section{Current Red Flags}&quot;)
    add_summary(
        [
            f&quot;Current overlap red flags: {len(assessment.overlap_current_rows)} Subject-CN asset lineages.&quot;,
            f&quot;Current Subject DN drift: {len(assessment.dn_current_rows)} Subject CN values.&quot;,
            f&quot;Current CA lineage drift: {len(assessment.vendor_current_rows)} Subject CN values.&quot;,
            f&quot;Current SAN drift: {len(assessment.san_current_rows)} Subject CN values.&quot;,
        ]
    )
    if assessment.current_red_flag_rows:
        lines.extend(
            [
                r&quot;\begin{longtable}{&gt;{\raggedright\arraybackslash}p{0.18\linewidth} &gt;{\raggedleft\arraybackslash}p{0.06\linewidth} &gt;{\raggedleft\arraybackslash}p{0.06\linewidth} &gt;{\raggedleft\arraybackslash}p{0.06\linewidth} &gt;{\raggedright\arraybackslash}p{0.30\linewidth} &gt;{\raggedright\arraybackslash}p{0.26\linewidth}}&quot;,
                r&quot;\toprule&quot;,
                r&quot;Subject CN &amp; Score &amp; Certs &amp; Current &amp; Flags &amp; Issuer Mix \\&quot;,
                r&quot;\midrule&quot;,
            ]
        )
        for row in assessment.current_red_flag_rows[:30]:
            lines.append(
                rf&quot;{ct_scan.latex_escape(row.subject_cn)} &amp; {row.score} &amp; {row.certificate_count} &amp; {row.current_certificate_count} &amp; {ct_scan.latex_escape(row.flags)} &amp; {ct_scan.latex_escape(row.notes)} \\&quot;
            )
        lines.extend([r&quot;\bottomrule&quot;, r&quot;\end{longtable}&quot;])
    else:
        lines.append(r&quot;No current red flags were found under the configured rules.&quot;)

    lines.append(r&quot;\section{Past Red Flags Now Fixed}&quot;)
    add_summary(
        [
            f&quot;Past-only overlap red flags now fixed: {len(assessment.overlap_past_rows)} Subject-CN asset lineages.&quot;,
            f&quot;Past-only Subject DN drift now fixed: {len(assessment.dn_past_rows)} Subject CN values.&quot;,
            f&quot;Past-only CA lineage drift now fixed: {len(assessment.vendor_past_rows)} Subject CN values.&quot;,
            f&quot;Past-only SAN drift now fixed: {len(assessment.san_past_rows)} Subject CN values.&quot;,
        ]
    )
    if assessment.past_red_flag_rows:
        lines.extend(
            [
                r&quot;\begin{longtable}{&gt;{\raggedright\arraybackslash}p{0.18\linewidth} &gt;{\raggedleft\arraybackslash}p{0.06\linewidth} &gt;{\raggedleft\arraybackslash}p{0.06\linewidth} &gt;{\raggedleft\arraybackslash}p{0.06\linewidth} &gt;{\raggedright\arraybackslash}p{0.30\linewidth} &gt;{\raggedright\arraybackslash}p{0.26\linewidth}}&quot;,
                r&quot;\toprule&quot;,
                r&quot;Subject CN &amp; Score &amp; Certs &amp; Current &amp; Flags &amp; Issuer Mix \\&quot;,
                r&quot;\midrule&quot;,
            ]
        )
        for row in assessment.past_red_flag_rows[:30]:
            lines.append(
                rf&quot;{ct_scan.latex_escape(row.subject_cn)} &amp; {row.score} &amp; {row.certificate_count} &amp; {row.current_certificate_count} &amp; {ct_scan.latex_escape(row.flags)} &amp; {ct_scan.latex_escape(row.notes)} \\&quot;
            )
        lines.extend([r&quot;\bottomrule&quot;, r&quot;\end{longtable}&quot;])
    else:
        lines.append(r&quot;No historical red flags were found under the configured rules.&quot;)

    lines.append(r&quot;\section{Subject DN Drift}&quot;)
    add_summary(
        [
            f&quot;Current Subject DN drift: {len(assessment.dn_current_rows)}.&quot;,
            f&quot;Past-only Subject DN drift now fixed: {len(assessment.dn_past_rows)}.&quot;,
            f&quot;Total Subject CN values with more than one Subject DN across history: {len(assessment.dn_rows)}.&quot;,
            &quot;This matters because the hostname stayed the same while the full subject identity string changed.&quot;,
            &quot;That is not automatically a security problem, but it is relevant governance drift.&quot;,
        ]
    )
    if assessment.dn_current_rows:
        lines.append(r&quot;\subsection{Current Subject DN Drift}&quot;)
        lines.extend(
            [
                r&quot;\begin{longtable}{&gt;{\raggedright\arraybackslash}p{0.20\linewidth} &gt;{\raggedleft\arraybackslash}p{0.07\linewidth} &gt;{\raggedleft\arraybackslash}p{0.07\linewidth} &gt;{\raggedleft\arraybackslash}p{0.09\linewidth} &gt;{\raggedright\arraybackslash}p{0.20\linewidth} &gt;{\raggedright\arraybackslash}p{0.29\linewidth}}&quot;,
                r&quot;\toprule&quot;,
                r&quot;Subject CN &amp; Certs &amp; Current &amp; Distinct Subject DNs &amp; Issuer Families &amp; Subject DN Samples \\&quot;,
                r&quot;\midrule&quot;,
            ]
        )
        for row in assessment.dn_current_rows[:20]:
            lines.append(
                rf&quot;{ct_scan.latex_escape(row.subject_cn)} &amp; {row.certificate_count} &amp; {row.current_certificate_count} &amp; {row.distinct_value_count} &amp; {ct_scan.latex_escape(row.issuer_families)} &amp; {ct_scan.latex_escape(row.details)} \\&quot;
            )
        lines.extend([r&quot;\bottomrule&quot;, r&quot;\end{longtable}&quot;])
    if assessment.dn_past_rows:
        lines.append(r&quot;\subsection{Past Subject DN Drift Now Fixed}&quot;)
        lines.extend(
            [
                r&quot;\begin{longtable}{&gt;{\raggedright\arraybackslash}p{0.20\linewidth} &gt;{\raggedleft\arraybackslash}p{0.07\linewidth} &gt;{\raggedleft\arraybackslash}p{0.07\linewidth} &gt;{\raggedleft\arraybackslash}p{0.09\linewidth} &gt;{\raggedright\arraybackslash}p{0.20\linewidth} &gt;{\raggedright\arraybackslash}p{0.29\linewidth}}&quot;,
                r&quot;\toprule&quot;,
                r&quot;Subject CN &amp; Certs &amp; Current &amp; Distinct Subject DNs &amp; Issuer Families &amp; Subject DN Samples \\&quot;,
                r&quot;\midrule&quot;,
            ]
        )
        for row in assessment.dn_past_rows[:20]:
            lines.append(
                rf&quot;{ct_scan.latex_escape(row.subject_cn)} &amp; {row.certificate_count} &amp; {row.current_certificate_count} &amp; {row.distinct_value_count} &amp; {ct_scan.latex_escape(row.issuer_families)} &amp; {ct_scan.latex_escape(row.details)} \\&quot;
            )
        lines.extend([r&quot;\bottomrule&quot;, r&quot;\end{longtable}&quot;])
    if not assessment.dn_rows:
        lines.append(r&quot;No cases were found.&quot;)

    lines.append(r&quot;\section{CA Lineage Drift}&quot;)
    add_summary(
        [
            f&quot;Exact issuer-name changes across history: {len(assessment.issuer_rows)} Subject CN values.&quot;,
            f&quot;Current CA lineage drift: {len(assessment.vendor_current_rows)} Subject CN values.&quot;,
            f&quot;Past-only CA lineage drift now fixed: {len(assessment.vendor_past_rows)} Subject CN values.&quot;,
            &quot;Exact issuer changes inside one lineage can be operationally normal. CA lineage drift is the stronger signal, with COMODO and Sectigo deliberately collapsed into one lineage.&quot;,
        ]
    )
    if assessment.vendor_current_rows:
        lines.append(r&quot;\subsection{Current CA Lineage Drift}&quot;)
        lines.extend(
            [
                r&quot;\begin{longtable}{&gt;{\raggedright\arraybackslash}p{0.20\linewidth} &gt;{\raggedleft\arraybackslash}p{0.07\linewidth} &gt;{\raggedleft\arraybackslash}p{0.07\linewidth} &gt;{\raggedleft\arraybackslash}p{0.08\linewidth} &gt;{\raggedright\arraybackslash}p{0.18\linewidth} &gt;{\raggedright\arraybackslash}p{0.32\linewidth}}&quot;,
                r&quot;\toprule&quot;,
                r&quot;Subject CN &amp; Certs &amp; Current &amp; Distinct Lineages &amp; Lineage Mix &amp; Lineages Seen \\&quot;,
                r&quot;\midrule&quot;,
            ]
        )
        for row in assessment.vendor_current_rows[:20]:
            lines.append(
                rf&quot;{ct_scan.latex_escape(row.subject_cn)} &amp; {row.certificate_count} &amp; {row.current_certificate_count} &amp; {row.distinct_value_count} &amp; {ct_scan.latex_escape(row.issuer_families)} &amp; {ct_scan.latex_escape(row.details)} \\&quot;
            )
        lines.extend([r&quot;\bottomrule&quot;, r&quot;\end{longtable}&quot;])
    if assessment.vendor_past_rows:
        lines.append(r&quot;\subsection{Past CA Lineage Drift Now Fixed}&quot;)
        lines.extend(
            [
                r&quot;\begin{longtable}{&gt;{\raggedright\arraybackslash}p{0.20\linewidth} &gt;{\raggedleft\arraybackslash}p{0.07\linewidth} &gt;{\raggedleft\arraybackslash}p{0.07\linewidth} &gt;{\raggedleft\arraybackslash}p{0.08\linewidth} &gt;{\raggedright\arraybackslash}p{0.18\linewidth} &gt;{\raggedright\arraybackslash}p{0.32\linewidth}}&quot;,
                r&quot;\toprule&quot;,
                r&quot;Subject CN &amp; Certs &amp; Current &amp; Distinct Lineages &amp; Lineage Mix &amp; Lineages Seen \\&quot;,
                r&quot;\midrule&quot;,
            ]
        )
        for row in assessment.vendor_past_rows[:20]:
            lines.append(
                rf&quot;{ct_scan.latex_escape(row.subject_cn)} &amp; {row.certificate_count} &amp; {row.current_certificate_count} &amp; {row.distinct_value_count} &amp; {ct_scan.latex_escape(row.issuer_families)} &amp; {ct_scan.latex_escape(row.details)} \\&quot;
            )
        lines.extend([r&quot;\bottomrule&quot;, r&quot;\end{longtable}&quot;])
    if assessment.issuer_rows:
        lines.append(r&quot;\subsection{Exact Issuer Changes Inside The Same Or Different Lineages}&quot;)
        lines.extend(
            [
                r&quot;\begin{longtable}{&gt;{\raggedright\arraybackslash}p{0.20\linewidth} &gt;{\raggedleft\arraybackslash}p{0.07\linewidth} &gt;{\raggedleft\arraybackslash}p{0.07\linewidth} &gt;{\raggedleft\arraybackslash}p{0.08\linewidth} &gt;{\raggedright\arraybackslash}p{0.18\linewidth} &gt;{\raggedright\arraybackslash}p{0.32\linewidth}}&quot;,
                r&quot;\toprule&quot;,
                r&quot;Subject CN &amp; Certs &amp; Current &amp; Distinct Issuers &amp; Lineage Mix &amp; Issuer Samples \\&quot;,
                r&quot;\midrule&quot;,
            ]
        )
        for row in assessment.issuer_rows[:20]:
            lines.append(
                rf&quot;{ct_scan.latex_escape(row.subject_cn)} &amp; {row.certificate_count} &amp; {row.current_certificate_count} &amp; {row.distinct_value_count} &amp; {ct_scan.latex_escape(row.issuer_families)} &amp; {ct_scan.latex_escape(row.details)} \\&quot;
            )
        lines.extend([r&quot;\bottomrule&quot;, r&quot;\end{longtable}&quot;])

    lines.append(r&quot;\section{SAN Profile Drift}&quot;)
    add_summary(
        [
            f&quot;Current SAN drift: {len(assessment.san_current_rows)} Subject CN values.&quot;,
            f&quot;Past-only SAN drift now fixed: {len(assessment.san_past_rows)} Subject CN values.&quot;,
            f&quot;Total Subject CN values with more than one SAN profile across history: {len(assessment.san_rows)}.&quot;,
            f&quot;Top SAN-delta pattern classes: {&#x27;, &#x27;.join(f&#x27;{name} ({count})&#x27; for name, count in assessment.san_pattern_counts.most_common()) or &#x27;none&#x27;}.&quot;,
            &quot;This reveals whether the endpoint surface under the same hostname stayed stable or changed shape over time.&quot;,
        ]
    )
    if assessment.san_current_rows:
        lines.append(r&quot;\subsection{Current SAN Drift}&quot;)
        lines.extend(
            [
                r&quot;\begin{longtable}{&gt;{\raggedright\arraybackslash}p{0.16\linewidth} &gt;{\raggedleft\arraybackslash}p{0.06\linewidth} &gt;{\raggedleft\arraybackslash}p{0.06\linewidth} &gt;{\raggedleft\arraybackslash}p{0.07\linewidth} &gt;{\raggedleft\arraybackslash}p{0.07\linewidth} &gt;{\raggedleft\arraybackslash}p{0.07\linewidth} &gt;{\raggedright\arraybackslash}p{0.18\linewidth} &gt;{\raggedright\arraybackslash}p{0.25\linewidth}}&quot;,
                r&quot;\toprule&quot;,
                r&quot;Subject CN &amp; Certs &amp; Current &amp; Profiles &amp; Stable &amp; Variable &amp; Delta Pattern &amp; Representative Delta \\&quot;,
                r&quot;\midrule&quot;,
            ]
        )
        for row in assessment.san_current_rows[:20]:
            lines.append(
                rf&quot;{ct_scan.latex_escape(row.subject_cn)} &amp; {row.certificate_count} &amp; {row.current_certificate_count} &amp; {row.distinct_san_profiles} &amp; {row.stable_entries} &amp; {row.variable_entries} &amp; {ct_scan.latex_escape(row.delta_pattern)} &amp; {ct_scan.latex_escape(row.representative_delta)} \\&quot;
            )
        lines.extend([r&quot;\bottomrule&quot;, r&quot;\end{longtable}&quot;])
    if assessment.san_past_rows:
        lines.append(r&quot;\subsection{Past SAN Drift Now Fixed}&quot;)
        lines.extend(
            [
                r&quot;\begin{longtable}{&gt;{\raggedright\arraybackslash}p{0.16\linewidth} &gt;{\raggedleft\arraybackslash}p{0.06\linewidth} &gt;{\raggedleft\arraybackslash}p{0.06\linewidth} &gt;{\raggedleft\arraybackslash}p{0.07\linewidth} &gt;{\raggedleft\arraybackslash}p{0.07\linewidth} &gt;{\raggedleft\arraybackslash}p{0.07\linewidth} &gt;{\raggedright\arraybackslash}p{0.18\linewidth} &gt;{\raggedright\arraybackslash}p{0.25\linewidth}}&quot;,
                r&quot;\toprule&quot;,
                r&quot;Subject CN &amp; Certs &amp; Current &amp; Profiles &amp; Stable &amp; Variable &amp; Delta Pattern &amp; Representative Delta \\&quot;,
                r&quot;\midrule&quot;,
            ]
        )
        for row in assessment.san_past_rows[:20]:
            lines.append(
                rf&quot;{ct_scan.latex_escape(row.subject_cn)} &amp; {row.certificate_count} &amp; {row.current_certificate_count} &amp; {row.distinct_san_profiles} &amp; {row.stable_entries} &amp; {row.variable_entries} &amp; {ct_scan.latex_escape(row.delta_pattern)} &amp; {ct_scan.latex_escape(row.representative_delta)} \\&quot;
            )
        lines.extend([r&quot;\bottomrule&quot;, r&quot;\end{longtable}&quot;])

    lines.append(r&quot;\section{Historic Issuance Bursts And Step Changes}&quot;)
    add_summary(
        [
            &quot;This chapter includes expired certificates on purpose, because issuance bursts are historical phenomena rather than current-only phenomena.&quot;,
            f&quot;Top issuance start dates are {&#x27;, &#x27;.join(f&#x27;{row.start_day} ({row.certificate_count})&#x27; for row in assessment.day_rows[:6])}.&quot;,
            &quot;Strong same-day or same-week bursts usually indicate planned renewal waves, platform migrations, or bulk onboarding of service families.&quot;,
        ]
    )
    lines.append(r&quot;\subsection{Top Start Dates}&quot;)
    lines.extend(
        [
            r&quot;\begin{longtable}{&gt;{\raggedright\arraybackslash}p{0.13\linewidth} &gt;{\raggedleft\arraybackslash}p{0.09\linewidth} &gt;{\raggedright\arraybackslash}p{0.43\linewidth} &gt;{\raggedright\arraybackslash}p{0.27\linewidth}}&quot;,
            r&quot;\toprule&quot;,
            r&quot;Start Day &amp; Certificates &amp; Top Subject CNs &amp; Top Issuer Families \\&quot;,
            r&quot;\midrule&quot;,
        ]
    )
    for row in assessment.day_rows:
        lines.append(
            rf&quot;{ct_scan.latex_escape(row.start_day)} &amp; {row.certificate_count} &amp; {ct_scan.latex_escape(row.top_subjects)} &amp; {ct_scan.latex_escape(row.top_issuers)} \\&quot;
        )
    lines.extend([r&quot;\bottomrule&quot;, r&quot;\end{longtable}&quot;])
    lines.append(r&quot;\subsection{Step Weeks}&quot;)
    if assessment.week_rows:
        lines.extend(
            [
                r&quot;\begin{longtable}{&gt;{\raggedright\arraybackslash}p{0.13\linewidth} &gt;{\raggedleft\arraybackslash}p{0.08\linewidth} &gt;{\raggedleft\arraybackslash}p{0.10\linewidth} &gt;{\raggedright\arraybackslash}p{0.35\linewidth} &gt;{\raggedright\arraybackslash}p{0.24\linewidth}}&quot;,
                r&quot;\toprule&quot;,
                r&quot;Week Start &amp; Certs &amp; Prior 8-Week Avg &amp; Top Subject CNs &amp; Top Issuer Families \\&quot;,
                r&quot;\midrule&quot;,
            ]
        )
        for row in assessment.week_rows[:20]:
            lines.append(
                rf&quot;{ct_scan.latex_escape(row.week_start)} &amp; {row.certificate_count} &amp; {ct_scan.latex_escape(row.prior_eight_week_avg)} &amp; {ct_scan.latex_escape(row.top_subjects)} &amp; {ct_scan.latex_escape(row.top_issuers)} \\&quot;
            )
        lines.extend([r&quot;\bottomrule&quot;, r&quot;\end{longtable}&quot;])
    else:
        lines.append(r&quot;No step weeks met the configured threshold.&quot;)

    lines.append(r&quot;\section{Interpretation}&quot;)
    lines.append(
        r&quot;The public certificate view is not just a static inventory. It is a change log. The normal case is rollover inside a stable renewal asset lineage with less than fifty days of overlap. The red flags are the exceptions layered on top of that baseline: overlap of fifty days or more, Subject DN drift, CA lineage drift, and SAN drift. The current-versus-past split matters because it separates live governance concerns from issues that appear to have been corrected already.&quot;
    )
    lines.extend([r&quot;\end{document}&quot;])
    args.latex_output.write_text(&quot;\n&quot;.join(lines) + &quot;\n&quot;, encoding=&quot;utf-8&quot;)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Writes the standalone historical report in LaTeX.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>render_latex</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
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
    assessment = build_assessment(args)
    render_markdown(args, assessment)
    render_latex(args, assessment)
    if not args.skip_pdf:
        ct_scan.compile_latex_to_pdf(args.latex_output, args.pdf_output, args.pdf_engine)
    if not args.quiet:
        print(
            f&quot;[report] historical_leaf={len(assessment.certificates)} markdown={args.markdown_output} latex={args.latex_output}&quot;
            + (&quot;&quot; if args.skip_pdf else f&quot; pdf={args.pdf_output}&quot;),
            file=__import__(&quot;sys&quot;).stderr,
        )
    return 0</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>The standalone command-line entrypoint for the historical analyzer.</p>
<p><strong>Flow arrows</strong></p><p>CLI arguments from the operator. &#8594; <strong>main</strong> &#8594; Runs the standalone historical analysis end to end.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

