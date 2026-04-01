# ct_focus_subjects.py

Source file: [`ct_focus_subjects.py`](../ct_focus_subjects.py)

Focused-cohort analyzer. This file takes your special hand-picked Subject CN list and compares it against the wider certificate and DNS estate.

Main flow in one line: `focus-subject file -> cohort entries -> compare against current and historical estate -> bucketed cohort explanation`

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

import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from statistics import median

import ct_dns_utils
import ct_lineage_report
import ct_master_report
import ct_scan


ENVIRONMENT_HINTS = {
    &quot;alpha&quot;,
    &quot;beta&quot;,
    &quot;dev&quot;,
    &quot;qa&quot;,
    &quot;uat&quot;,
    &quot;sit&quot;,
    &quot;stage&quot;,
    &quot;stg&quot;,
    &quot;preprod&quot;,
    &quot;prod&quot;,
    &quot;release&quot;,
    &quot;squads&quot;,
    &quot;sandbox&quot;,
}

VENDOR_HINTS = {
    &quot;vendor&quot;,
    &quot;external&quot;,
    &quot;hoster&quot;,
    &quot;product&quot;,
    &quot;mitek&quot;,
    &quot;scrive&quot;,
    &quot;pega&quot;,
}

IDENTITY_HINTS = {
    &quot;id&quot;,
    &quot;idp&quot;,
    &quot;identity&quot;,
    &quot;auth&quot;,
    &quot;sso&quot;,
    &quot;online&quot;,
    &quot;mail&quot;,
    &quot;email&quot;,
    &quot;secmail&quot;,
    &quot;chat&quot;,
    &quot;appointment&quot;,
    &quot;appointments&quot;,
}

CUSTOMER_HINTS = {
    &quot;brand&quot;,
    &quot;branding&quot;,
    &quot;campaign&quot;,
    &quot;experience&quot;,
    &quot;welcome&quot;,
    &quot;thankyou&quot;,
    &quot;gifts&quot;,
    &quot;investment&quot;,
    &quot;client&quot;,
    &quot;customers&quot;,
    &quot;information&quot;,
    &quot;club&quot;,
    &quot;risk&quot;,
}</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Rules and data shapes for analyzing the special hand-picked Subject-CN cohort.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>Module setup</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## FocusSubject

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">@dataclass
class FocusSubject:
    subject_cn: str
    analyst_note: str</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>One line from the local focus-subject file.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>FocusSubject</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## FocusSubjectDetail

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">@dataclass
class FocusSubjectDetail:
    subject_cn: str
    analyst_note: str
    analyst_theme: str
    taxonomy_bucket: str
    taxonomy_reason: str
    observed_role: str
    basket_status: str
    current_direct_certificates: int
    historical_direct_certificates: int
    current_non_focus_san_carriers: int
    historical_non_focus_san_carriers: int
    current_revoked_certificates: int
    current_not_revoked_certificates: int
    current_dns_outcome: str
    current_dns_classification: str
    current_issuer_families: str
    historical_issuer_families: str
    current_san_size_span: str
    historical_san_size_span: str
    max_direct_to_carrier_overlap_days: int
    carrier_subjects: str
    current_red_flags: str
    past_red_flags: str</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>One detailed analytical row for one focused Subject CN.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>FocusSubjectDetail</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## FocusCohortAnalysis

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">@dataclass
class FocusCohortAnalysis:
    focus_subjects: list[FocusSubject]
    details: list[FocusSubjectDetail]
    provided_subjects_count: int
    historically_seen_subjects_count: int
    current_direct_subjects_count: int
    current_carried_only_subjects_count: int
    historical_non_focus_carried_subjects_count: int
    unseen_subjects: list[str]
    current_focus_certificate_count: int
    current_rest_certificate_count: int
    focus_revoked_current_count: int
    focus_not_revoked_current_count: int
    rest_revoked_current_count: int
    rest_not_revoked_current_count: int
    focus_revoked_share: str
    rest_revoked_share: str
    focus_median_san_entries: int
    focus_average_san_entries: str
    rest_median_san_entries: int
    rest_average_san_entries: str
    focus_multi_zone_certificate_count: int
    rest_multi_zone_certificate_count: int
    focus_current_subject_dns_classes: Counter[str]
    rest_current_subject_dns_classes: Counter[str]
    focus_current_subject_dns_stacks: Counter[str]
    rest_current_subject_dns_stacks: Counter[str]
    focus_current_issuer_families: Counter[str]
    rest_current_issuer_families: Counter[str]
    focus_current_red_flag_subjects: int
    focus_past_red_flag_subjects: int
    focus_any_red_flag_subjects: int
    bucket_counts: Counter[str]
    notables: list[FocusSubjectDetail]
    transition_rows: list[FocusSubjectDetail]</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>The full cohort comparison bundle used in the monograph.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>FocusCohortAnalysis</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## load_focus_subjects

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def load_focus_subjects(path: Path) -&gt; list[FocusSubject]:
    if not path.exists():
        return []
    subjects: list[FocusSubject] = []
    seen: set[str] = set()
    for raw_line in path.read_text(encoding=&quot;utf-8&quot;).splitlines():
        line = raw_line.strip()
        if not line or line.startswith(&quot;#&quot;):
            continue
        match = re.match(r&quot;^(?P&lt;cn&gt;[^()]+?)(?:\s*\((?P&lt;meta&gt;.*)\))?$&quot;, line)
        if not match:
            continue
        subject_cn = match.group(&quot;cn&quot;).strip().lower()
        if subject_cn in seen:
            continue
        seen.add(subject_cn)
        subjects.append(
            FocusSubject(
                subject_cn=subject_cn,
                analyst_note=(match.group(&quot;meta&quot;) or &quot;&quot;).strip(),
            )
        )
    return subjects</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Reads the local focus-subject list and any analyst notes attached to it.</p>
<p><strong>Flow arrows</strong></p><p>The local focus-subject file. &#8594; <strong>load_focus_subjects</strong> &#8594; `build_analysis` uses these parsed cohort entries.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## dns_names

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def dns_names(san_entries: list[str]) -&gt; set[str]:
    return {entry[4:].lower() for entry in san_entries if entry.startswith(&quot;DNS:&quot;)}</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_focus_subjects.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>dns_names</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## overlap_days

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def overlap_days(
    left_start,
    left_end,
    right_start,
    right_end,
) -&gt; int:
    start = max(left_start, right_start)
    end = min(left_end, right_end)
    if end &lt;= start:
        return 0
    return max(1, (end - start).days)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_focus_subjects.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>overlap_days</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
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

## short_issuer_family

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def short_issuer_family(issuer_name: str) -&gt; str:
    lowered = issuer_name.lower()
    if &quot;amazon&quot; in lowered:
        return &quot;Amazon&quot;
    if &quot;sectigo&quot; in lowered or &quot;comodo&quot; in lowered:
        return &quot;Sectigo/COMODO&quot;
    if &quot;google trust services&quot; in lowered or &quot;cn=we1&quot; in lowered:
        return &quot;Google Trust Services&quot;
    return &quot;Other&quot;</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_focus_subjects.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>short_issuer_family</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## median_int

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def median_int(values: list[int]) -&gt; int:
    if not values:
        return 0
    return int(median(values))</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_focus_subjects.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>median_int</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## average_text

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def average_text(values: list[int]) -&gt; str:
    if not values:
        return &quot;0.0&quot;
    return f&quot;{(sum(values) / len(values)):.1f}&quot;</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_focus_subjects.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>average_text</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## san_size_span

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def san_size_span(current_hits: list[ct_scan.CertificateHit]) -&gt; str:
    sizes = sorted({len(hit.san_entries) for hit in current_hits})
    if not sizes:
        return &quot;-&quot;
    if len(sizes) == 1:
        return str(sizes[0])
    return &quot;, &quot;.join(str(value) for value in sizes[:4]) + (&quot;&quot; if len(sizes) &lt;= 4 else f&quot;, ... (+{len(sizes) - 4} more)&quot;)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_focus_subjects.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>san_size_span</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## historical_san_size_span

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def historical_san_size_span(certificates: list[ct_lineage_report.HistoricalCertificate]) -&gt; str:
    sizes = sorted({len(certificate.san_entries) for certificate in certificates})
    if not sizes:
        return &quot;-&quot;
    if len(sizes) == 1:
        return str(sizes[0])
    return &quot;, &quot;.join(str(value) for value in sizes[:4]) + (&quot;&quot; if len(sizes) &lt;= 4 else f&quot;, ... (+{len(sizes) - 4} more)&quot;)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_focus_subjects.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>historical_san_size_span</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## summarize_names

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def summarize_names(values: set[str], limit: int = 4) -&gt; str:
    if not values:
        return &quot;-&quot;
    ordered = sorted(values, key=str.casefold)
    if len(ordered) &lt;= limit:
        return &quot;, &quot;.join(ordered)
    return &quot;, &quot;.join(ordered[:limit]) + f&quot;, ... (+{len(ordered) - limit} more)&quot;</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This block compresses many detailed rows into a smaller, easier-to-read summary.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>summarize_names</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## zone_count_from_sans

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def zone_count_from_sans(san_entries: list[str]) -&gt; int:
    return len(
        {
            ct_scan.san_tail_split(entry[4:])[1]
            for entry in san_entries
            if entry.startswith(&quot;DNS:&quot;)
        }
    )</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_focus_subjects.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>zone_count_from_sans</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## max_san_count_current

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def max_san_count_current(hits: list[ct_scan.CertificateHit]) -&gt; int:
    return max((len(hit.san_entries) for hit in hits), default=0)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_focus_subjects.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>max_san_count_current</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## max_san_count_historical

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def max_san_count_historical(certificates: list[ct_lineage_report.HistoricalCertificate]) -&gt; int:
    return max((len(certificate.san_entries) for certificate in certificates), default=0)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_focus_subjects.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>max_san_count_historical</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## max_zone_count_current

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def max_zone_count_current(hits: list[ct_scan.CertificateHit]) -&gt; int:
    return max((zone_count_from_sans(hit.san_entries) for hit in hits), default=0)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_focus_subjects.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>max_zone_count_current</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## bucket_sort_key

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def bucket_sort_key(value: str) -&gt; tuple[int, str]:
    order = {
        &quot;direct_front_door&quot;: 0,
        &quot;platform_matrix_anchor&quot;: 1,
        &quot;ambiguous_legacy&quot;: 2,
    }
    return (order.get(value, 99), value)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_focus_subjects.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>bucket_sort_key</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## taxonomy_bucket_label

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def taxonomy_bucket_label(bucket: str) -&gt; str:
    return {
        &quot;direct_front_door&quot;: &quot;Front-door direct name&quot;,
        &quot;platform_matrix_anchor&quot;: &quot;Platform-anchor matrix name&quot;,
        &quot;ambiguous_legacy&quot;: &quot;Ambiguous or legacy residue&quot;,
    }.get(bucket, bucket)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_focus_subjects.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>taxonomy_bucket_label</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## analyst_theme

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def analyst_theme(subject: FocusSubject) -&gt; str:
    tokens = set(re.findall(r&quot;[a-z0-9]+&quot;, f&quot;{subject.subject_cn} {subject.analyst_note}&quot;.lower()))
    if ENVIRONMENT_HINTS &amp; tokens:
        return &quot;environment or platform anchor&quot;
    if VENDOR_HINTS &amp; tokens:
        return &quot;vendor or product integration&quot;
    if IDENTITY_HINTS &amp; tokens:
        return &quot;identity, messaging, or service front&quot;
    if CUSTOMER_HINTS &amp; tokens:
        return &quot;customer proposition or campaign front&quot;
    left_label = subject.subject_cn.split(&quot;.&quot;)[0].lower()
    if re.fullmatch(r&quot;\d+&quot;, left_label) or re.fullmatch(r&quot;[a-z]{2,6}\d{1,4}&quot;, left_label):
        return &quot;opaque or legacy label&quot;
    return &quot;human-named branded or service endpoint&quot;</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_focus_subjects.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>analyst_theme</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## classify_taxonomy_bucket

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def classify_taxonomy_bucket(
    subject: FocusSubject,
    current_hits: list[ct_scan.CertificateHit],
    historical_hits: list[ct_lineage_report.HistoricalCertificate],
    current_carriers: list[ct_scan.CertificateHit],
    historical_carriers: list[ct_lineage_report.HistoricalCertificate],
) -&gt; tuple[str, str]:
    tokens = set(re.findall(r&quot;[a-z0-9]+&quot;, f&quot;{subject.subject_cn} {subject.analyst_note}&quot;.lower()))
    left_label = subject.subject_cn.split(&quot;.&quot;)[0].lower()
    opaque_label = bool(
        re.fullmatch(r&quot;\d+&quot;, left_label)
        or re.fullmatch(r&quot;[a-z]{1,4}\d{1,4}&quot;, left_label)
    )
    current_direct_exists = bool(current_hits)
    historical_direct_exists = bool(historical_hits)
    max_current_sans = max_san_count_current(current_hits)
    max_historical_sans = max_san_count_historical(historical_hits)
    max_any_sans = max(max_current_sans, max_historical_sans)
    max_current_zones = max_zone_count_current(current_hits)
    carrier_only_today = not current_direct_exists and bool(current_carriers)
    carrier_only_history = (not current_direct_exists and not historical_direct_exists and bool(historical_carriers))
    environment_signal = bool(ENVIRONMENT_HINTS &amp; tokens)

    if max_any_sans &gt;= 20:
        return (
            &quot;platform_matrix_anchor&quot;,
            &quot;Large SAN matrix coverage indicates an umbrella certificate for a managed platform slice rather than one standalone public front door.&quot;,
        )
    if carrier_only_today or carrier_only_history:
        return (
            &quot;ambiguous_legacy&quot;,
            &quot;This name now appears mainly as a carried SAN passenger or as historical residue, so it no longer behaves like a stable standalone certificate front.&quot;,
        )
    if current_direct_exists and max_any_sans &lt;= 4 and max_current_zones &lt;= 1 and not opaque_label and not environment_signal:
        return (
            &quot;direct_front_door&quot;,
            &quot;Small direct certificates, single-zone scope, and a human-readable service label fit the pattern of a branded or service-facing public entry point.&quot;,
        )
    if historical_direct_exists and not current_direct_exists and max_any_sans &lt;= 4 and not opaque_label:
        return (
            &quot;ambiguous_legacy&quot;,
            &quot;The historical certificates look like a simple direct front, but there is no current direct certificate anymore, which makes this mostly migration residue rather than a live front-door pattern.&quot;,
        )
    if max_any_sans &lt;= 4 and opaque_label:
        return (
            &quot;ambiguous_legacy&quot;,
            &quot;The direct certificate shape is small and simple, but the left-most label is too opaque to treat as a clear branded or service-front naming pattern.&quot;,
        )
    if environment_signal and max_any_sans &lt;= 19:
        return (
            &quot;ambiguous_legacy&quot;,
            &quot;Environment-style wording is present, but the SAN coverage is not broad enough to prove a full platform-matrix certificate role.&quot;,
        )
    if max_any_sans &gt; 4:
        return (
            &quot;ambiguous_legacy&quot;,
            &quot;Direct issuance exists, but the SAN set is broader or more variable than a simple one-service front, which leaves the role mixed.&quot;,
        )
    return (
        &quot;ambiguous_legacy&quot;,
        &quot;The evidence is mixed or too thin to place this name cleanly in one of the stronger bucket patterns.&quot;,
    )</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Places a name into the direct-front, platform-anchor, or ambiguous bucket.</p>
<p><strong>Flow arrows</strong></p><p>One focused Subject CN plus surrounding evidence. &#8594; <strong>classify_taxonomy_bucket</strong> &#8594; `build_analysis` uses the bucket label in the focused-cohort chapter.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## observed_role

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def observed_role(
    subject: FocusSubject,
    current_hits: list[ct_scan.CertificateHit],
    current_carriers: list[ct_scan.CertificateHit],
    historical_carriers: list[ct_lineage_report.HistoricalCertificate],
    observation: ct_dns_utils.DnsObservation,
) -&gt; str:
    tokens = set(re.findall(r&quot;[a-z0-9]+&quot;, f&quot;{subject.subject_cn} {subject.analyst_note}&quot;.lower()))
    if not current_hits and current_carriers:
        return &quot;carried today inside another certificate&quot;
    if not current_hits and historical_carriers:
        return &quot;historical carried alias or retired passenger&quot;
    if not current_hits:
        return &quot;not seen in the CT corpus&quot;
    max_san_entries = max(len(hit.san_entries) for hit in current_hits)
    if max_san_entries &gt;= 20 or (ENVIRONMENT_HINTS &amp; tokens):
        return &quot;platform matrix or environment anchor&quot;
    revoked = sum(1 for hit in current_hits if hit.revocation_status == &quot;revoked&quot;)
    if revoked &gt;= 3:
        return &quot;high-churn direct service front&quot;
    if VENDOR_HINTS &amp; tokens:
        return &quot;direct vendor or product integration front&quot;
    if IDENTITY_HINTS &amp; tokens:
        return &quot;direct service or identity front&quot;
    if CUSTOMER_HINTS &amp; tokens:
        return &quot;direct branded or customer proposition front&quot;
    if observation.classification in {&quot;direct_address&quot;, &quot;cname_to_address&quot;}:
        return &quot;direct standalone service front&quot;
    return &quot;standalone branded or service endpoint&quot;</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Tries to describe what role the name appears to play in the public estate.</p>
<p><strong>Flow arrows</strong></p><p>One focused Subject CN plus public evidence. &#8594; <strong>observed_role</strong> &#8594; `build_analysis` stores the plain-English role description.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## basket_status

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def basket_status(
    current_hits: list[ct_scan.CertificateHit],
    current_carriers: list[ct_scan.CertificateHit],
    historical_hits: list[ct_lineage_report.HistoricalCertificate],
    historical_carriers: list[ct_lineage_report.HistoricalCertificate],
) -&gt; str:
    if current_hits and current_carriers:
        return &quot;current direct-and-carried overlap&quot;
    if current_hits:
        return &quot;current direct subject certificate&quot;
    if current_carriers:
        return &quot;current SAN passenger only&quot;
    if historical_hits and historical_carriers:
        return &quot;historical direct-and-carried only&quot;
    if historical_hits:
        return &quot;historical direct only&quot;
    if historical_carriers:
        return &quot;historical SAN passenger only&quot;
    return &quot;not seen&quot;</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_focus_subjects.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>basket_status</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## red_flag_text

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def red_flag_text(row_lookup: dict[str, str], subject_cn: str) -&gt; str:
    return row_lookup.get(subject_cn.lower(), &quot;-&quot;)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_focus_subjects.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>red_flag_text</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## build_analysis

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def build_analysis(
    subjects: list[FocusSubject],
    report: dict[str, object],
    assessment: ct_lineage_report.HistoricalAssessment,
    dns_cache_dir: Path,
    dns_cache_ttl_seconds: int,
) -&gt; FocusCohortAnalysis | None:
    if not subjects:
        return None
    focus_set = {subject.subject_cn for subject in subjects}

    current_hits = report[&quot;hits&quot;]
    current_by_cn: dict[str, list[ct_scan.CertificateHit]] = {}
    for hit in current_hits:
        current_by_cn.setdefault(hit.subject_cn.lower(), []).append(hit)

    historical_by_cn: dict[str, list[ct_lineage_report.HistoricalCertificate]] = {}
    for certificate in assessment.certificates:
        historical_by_cn.setdefault(certificate.subject_cn.lower(), []).append(certificate)

    non_focus_current = [hit for hit in current_hits if hit.subject_cn.lower() not in focus_set]
    non_focus_historical = [certificate for certificate in assessment.certificates if certificate.subject_cn.lower() not in focus_set]

    observation_by_name = report[&quot;observation_by_name&quot;]
    detail_rows: list[FocusSubjectDetail] = []
    transition_rows: list[FocusSubjectDetail] = []

    current_red_flag_lookup = {row.subject_cn.lower(): row.flags for row in assessment.current_red_flag_rows}
    past_red_flag_lookup = {row.subject_cn.lower(): row.flags for row in assessment.past_red_flag_rows}

    for subject in subjects:
        current_direct = current_by_cn.get(subject.subject_cn, [])
        historical_direct = historical_by_cn.get(subject.subject_cn, [])
        current_carriers = [hit for hit in non_focus_current if subject.subject_cn in dns_names(hit.san_entries)]
        historical_carriers = [
            certificate
            for certificate in non_focus_historical
            if subject.subject_cn in dns_names(certificate.san_entries)
        ]
        observation = observation_by_name.get(subject.subject_cn) or ct_dns_utils.scan_name_cached(
            subject.subject_cn,
            dns_cache_dir,
            dns_cache_ttl_seconds,
        )
        current_issuer_families = Counter(
            short_issuer_family(ct_scan.primary_issuer_name(hit))
            for hit in current_direct
        )
        historical_issuer_families = Counter(
            certificate.issuer_family
            for certificate in historical_direct
        )
        max_overlap = 0
        for direct_certificate in historical_direct:
            for carrier_certificate in historical_carriers:
                max_overlap = max(
                    max_overlap,
                    overlap_days(
                        direct_certificate.validity_not_before,
                        direct_certificate.effective_not_after,
                        carrier_certificate.validity_not_before,
                        carrier_certificate.effective_not_after,
                    ),
                )
        taxonomy_bucket, taxonomy_reason = classify_taxonomy_bucket(
            subject,
            current_direct,
            historical_direct,
            current_carriers,
            historical_carriers,
        )
        detail = FocusSubjectDetail(
            subject_cn=subject.subject_cn,
            analyst_note=subject.analyst_note or &quot;-&quot;,
            analyst_theme=analyst_theme(subject),
            taxonomy_bucket=taxonomy_bucket,
            taxonomy_reason=taxonomy_reason,
            observed_role=observed_role(subject, current_direct, current_carriers, historical_carriers, observation),
            basket_status=basket_status(current_direct, current_carriers, historical_direct, historical_carriers),
            current_direct_certificates=len(current_direct),
            historical_direct_certificates=len(historical_direct),
            current_non_focus_san_carriers=len(current_carriers),
            historical_non_focus_san_carriers=len(historical_carriers),
            current_revoked_certificates=sum(1 for hit in current_direct if hit.revocation_status == &quot;revoked&quot;),
            current_not_revoked_certificates=sum(1 for hit in current_direct if hit.revocation_status == &quot;not_revoked&quot;),
            current_dns_outcome=observation.stack_signature,
            current_dns_classification=observation.classification,
            current_issuer_families=&quot;, &quot;.join(
                f&quot;{name} ({count})&quot;
                for name, count in current_issuer_families.most_common()
            ) or &quot;-&quot;,
            historical_issuer_families=&quot;, &quot;.join(
                f&quot;{name} ({count})&quot;
                for name, count in historical_issuer_families.most_common()
            ) or &quot;-&quot;,
            current_san_size_span=san_size_span(current_direct),
            historical_san_size_span=historical_san_size_span(historical_direct),
            max_direct_to_carrier_overlap_days=max_overlap,
            carrier_subjects=summarize_names({hit.subject_cn for hit in current_carriers} | {certificate.subject_cn for certificate in historical_carriers}),
            current_red_flags=red_flag_text(current_red_flag_lookup, subject.subject_cn),
            past_red_flags=red_flag_text(past_red_flag_lookup, subject.subject_cn),
        )
        detail_rows.append(detail)
        if detail.current_non_focus_san_carriers or detail.historical_non_focus_san_carriers:
            transition_rows.append(detail)

    focus_current_hits = [hit for hit in current_hits if hit.subject_cn.lower() in focus_set]
    rest_current_hits = [hit for hit in current_hits if hit.subject_cn.lower() not in focus_set]

    def zone_count(hit: ct_scan.CertificateHit) -&gt; int:
        return len({ct_scan.san_tail_split(entry[4:])[1] for entry in hit.san_entries if entry.startswith(&quot;DNS:&quot;)})

    focus_current_subject_names = sorted({hit.subject_cn.lower() for hit in focus_current_hits})
    rest_current_subject_names = sorted({hit.subject_cn.lower() for hit in rest_current_hits})

    def observation_for_subject(name: str) -&gt; ct_dns_utils.DnsObservation:
        return observation_by_name.get(name) or ct_dns_utils.scan_name_cached(name, dns_cache_dir, dns_cache_ttl_seconds)

    focus_current_subject_observations = [observation_for_subject(name) for name in focus_current_subject_names]
    rest_current_subject_observations = [observation_for_subject(name) for name in rest_current_subject_names]

    focus_current_issuer_families = Counter(
        short_issuer_family(ct_scan.primary_issuer_name(hit))
        for hit in focus_current_hits
    )
    rest_current_issuer_families = Counter(
        short_issuer_family(ct_scan.primary_issuer_name(hit))
        for hit in rest_current_hits
    )

    current_red_flag_subjects = {row.subject_cn.lower() for row in assessment.current_red_flag_rows}
    past_red_flag_subjects = {row.subject_cn.lower() for row in assessment.past_red_flag_rows}

    notables = sorted(
        detail_rows,
        key=lambda item: (
            bucket_sort_key(item.taxonomy_bucket),
            -(
                (item.current_revoked_certificates &gt; 0)
                + (item.current_non_focus_san_carriers &gt; 0)
                + (item.historical_non_focus_san_carriers &gt; 0)
                + (item.current_red_flags != &quot;-&quot;)
                + (item.past_red_flags != &quot;-&quot;)
            ),
            -item.current_direct_certificates,
            item.subject_cn,
        ),
    )[:10]

    return FocusCohortAnalysis(
        focus_subjects=subjects,
        details=sorted(detail_rows, key=lambda item: (bucket_sort_key(item.taxonomy_bucket), item.subject_cn.casefold())),
        provided_subjects_count=len(subjects),
        historically_seen_subjects_count=sum(
            1
            for item in detail_rows
            if item.historical_direct_certificates &gt; 0 or item.historical_non_focus_san_carriers &gt; 0
        ),
        current_direct_subjects_count=sum(1 for item in detail_rows if item.current_direct_certificates &gt; 0),
        current_carried_only_subjects_count=sum(
            1
            for item in detail_rows
            if item.current_direct_certificates == 0 and item.current_non_focus_san_carriers &gt; 0
        ),
        historical_non_focus_carried_subjects_count=sum(
            1
            for item in detail_rows
            if item.historical_non_focus_san_carriers &gt; 0
        ),
        unseen_subjects=[item.subject_cn for item in detail_rows if item.basket_status == &quot;not seen&quot;],
        current_focus_certificate_count=len(focus_current_hits),
        current_rest_certificate_count=len(rest_current_hits),
        focus_revoked_current_count=sum(1 for hit in focus_current_hits if hit.revocation_status == &quot;revoked&quot;),
        focus_not_revoked_current_count=sum(1 for hit in focus_current_hits if hit.revocation_status == &quot;not_revoked&quot;),
        rest_revoked_current_count=sum(1 for hit in rest_current_hits if hit.revocation_status == &quot;revoked&quot;),
        rest_not_revoked_current_count=sum(1 for hit in rest_current_hits if hit.revocation_status == &quot;not_revoked&quot;),
        focus_revoked_share=pct(
            sum(1 for hit in focus_current_hits if hit.revocation_status == &quot;revoked&quot;),
            len(focus_current_hits),
        ),
        rest_revoked_share=pct(
            sum(1 for hit in rest_current_hits if hit.revocation_status == &quot;revoked&quot;),
            len(rest_current_hits),
        ),
        focus_median_san_entries=median_int([len(hit.san_entries) for hit in focus_current_hits]),
        focus_average_san_entries=average_text([len(hit.san_entries) for hit in focus_current_hits]),
        rest_median_san_entries=median_int([len(hit.san_entries) for hit in rest_current_hits]),
        rest_average_san_entries=average_text([len(hit.san_entries) for hit in rest_current_hits]),
        focus_multi_zone_certificate_count=sum(1 for hit in focus_current_hits if zone_count(hit) &gt; 1),
        rest_multi_zone_certificate_count=sum(1 for hit in rest_current_hits if zone_count(hit) &gt; 1),
        focus_current_subject_dns_classes=Counter(observation.classification for observation in focus_current_subject_observations),
        rest_current_subject_dns_classes=Counter(observation.classification for observation in rest_current_subject_observations),
        focus_current_subject_dns_stacks=Counter(observation.stack_signature for observation in focus_current_subject_observations),
        rest_current_subject_dns_stacks=Counter(observation.stack_signature for observation in rest_current_subject_observations),
        focus_current_issuer_families=focus_current_issuer_families,
        rest_current_issuer_families=rest_current_issuer_families,
        focus_current_red_flag_subjects=sum(1 for subject in subjects if subject.subject_cn in current_red_flag_subjects),
        focus_past_red_flag_subjects=sum(1 for subject in subjects if subject.subject_cn in past_red_flag_subjects),
        focus_any_red_flag_subjects=sum(
            1
            for subject in subjects
            if subject.subject_cn in current_red_flag_subjects or subject.subject_cn in past_red_flag_subjects
        ),
        bucket_counts=Counter(item.taxonomy_bucket for item in detail_rows),
        notables=notables,
        transition_rows=sorted(
            transition_rows,
            key=lambda item: (
                -(item.current_non_focus_san_carriers + item.historical_non_focus_san_carriers),
                -item.max_direct_to_carrier_overlap_days,
                item.subject_cn.casefold(),
            ),
        ),
    )</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Runs the full comparison between the focused cohort and the rest of the estate.</p>
<p><strong>Flow arrows</strong></p><p>The focus-subject list, current-state report, and historical assessment. &#8594; <strong>build_analysis</strong> &#8594; The monograph uses the resulting bundle for Chapter 8 and Appendix D.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

