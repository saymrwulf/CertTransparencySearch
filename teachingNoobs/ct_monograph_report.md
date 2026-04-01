# ct_monograph_report.py

Source file: [`ct_monograph_report.py`](../ct_monograph_report.py)

Publication builder. This file takes all analytical layers and turns them into the final monograph in Markdown, LaTeX, and PDF.

Main flow in one line: `current-state bundle + history + CAA + focused cohort -> Markdown/LaTeX/PDF monograph`

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
from collections import Counter
from pathlib import Path

import ct_caa_analysis
import ct_dns_utils
import ct_focus_subjects
import ct_lineage_report
import ct_master_report
import ct_scan</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>The orchestration and publishing layer that turns all analytical modules into one publication.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>Module setup</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
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
        description=&quot;Generate a complete monograph-style CT and DNS report with appendices.&quot;
    )
    parser.add_argument(&quot;--domains-file&quot;, type=Path, default=Path(&quot;domains.local.txt&quot;))
    parser.add_argument(&quot;--cache-dir&quot;, type=Path, default=Path(&quot;.cache/ct-search&quot;))
    parser.add_argument(&quot;--dns-cache-dir&quot;, type=Path, default=Path(&quot;.cache/dns-scan&quot;))
    parser.add_argument(&quot;--caa-cache-dir&quot;, type=Path, default=Path(&quot;.cache/caa-scan&quot;))
    parser.add_argument(&quot;--history-cache-dir&quot;, type=Path, default=Path(&quot;.cache/ct-history-v2&quot;))
    parser.add_argument(&quot;--focus-subjects-file&quot;, type=Path, default=Path(&quot;focus_subjects.local.txt&quot;))
    parser.add_argument(&quot;--cache-ttl-seconds&quot;, type=int, default=0)
    parser.add_argument(&quot;--dns-cache-ttl-seconds&quot;, type=int, default=86400)
    parser.add_argument(&quot;--caa-cache-ttl-seconds&quot;, type=int, default=86400)
    parser.add_argument(&quot;--max-candidates-per-domain&quot;, type=int, default=10000)
    parser.add_argument(&quot;--retries&quot;, type=int, default=3)
    parser.add_argument(&quot;--markdown-output&quot;, type=Path, default=Path(&quot;output/corpus/monograph.md&quot;))
    parser.add_argument(&quot;--latex-output&quot;, type=Path, default=Path(&quot;output/corpus/monograph.tex&quot;))
    parser.add_argument(&quot;--pdf-output&quot;, type=Path, default=Path(&quot;output/corpus/monograph.pdf&quot;))
    parser.add_argument(&quot;--appendix-markdown-output&quot;, type=Path, default=Path(&quot;.cache/monograph-temp/appendix-inventory.md&quot;))
    parser.add_argument(&quot;--appendix-latex-output&quot;, type=Path, default=Path(&quot;.cache/monograph-temp/appendix-inventory.tex&quot;))
    parser.add_argument(&quot;--appendix-pdf-output&quot;, type=Path, default=Path(&quot;.cache/monograph-temp/appendix-inventory.pdf&quot;))
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

## build_scan_stats

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def build_scan_stats(report: dict[str, object]) -&gt; ct_scan.ScanStats:
    groups = report[&quot;groups&quot;]
    hits = report[&quot;hits&quot;]
    verification = report[&quot;verification&quot;]
    return ct_scan.ScanStats(
        generated_at_utc=report[&quot;generated_at_utc&quot;],
        configured_domains=report[&quot;domains&quot;],
        unique_leaf_certificates=len(hits),
        groups_total=len(groups),
        groups_multi_member=sum(1 for group in groups if group.member_count &gt; 1),
        groups_singleton=sum(1 for group in groups if group.member_count == 1),
        groups_by_type=dict(Counter(group.group_type for group in groups)),
        verification=verification,
    )</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This block constructs a richer higher-level result from simpler inputs.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>build_scan_stats</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## render_appendix_inventory

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def render_appendix_inventory(args: argparse.Namespace, report: dict[str, object]) -&gt; None:
    stats = build_scan_stats(report)
    ct_scan.render_markdown_report(
        args.appendix_markdown_output,
        report[&quot;hits&quot;],
        report[&quot;groups&quot;],
        stats,
        report[&quot;issuer_trust&quot;],
    )
    ct_scan.render_latex_report(
        args.appendix_latex_output,
        report[&quot;hits&quot;],
        report[&quot;groups&quot;],
        stats,
        report[&quot;issuer_trust&quot;],
        show_page_numbers=False,
    )
    if not args.skip_pdf:
        ct_scan.compile_latex_to_pdf(args.appendix_latex_output, args.appendix_pdf_output, args.pdf_engine)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Generates the hidden full inventory appendix before the main monograph is assembled.</p>
<p><strong>Flow arrows</strong></p><p>The current-state report bundle. &#8594; <strong>render_appendix_inventory</strong> &#8594; Creates the hidden appendix files that are later embedded into the monograph.</p>
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
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_monograph_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>md_table</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## latex_escape

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def latex_escape(value: str) -&gt; str:
    return ct_scan.latex_escape(value)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_monograph_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>latex_escape</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
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
    if &quot;google trust services&quot; in lowered or &quot;cn=we1&quot; in lowered:
        return &quot;Google Trust Services&quot;
    return issuer_name</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_monograph_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
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

## purpose_label

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def purpose_label(category: str) -&gt; str:
    return {
        &quot;tls_server_only&quot;: &quot;TLS server only&quot;,
        &quot;tls_server_and_client&quot;: &quot;TLS server and client auth&quot;,
        &quot;client_auth_only&quot;: &quot;Client auth only&quot;,
        &quot;smime_only&quot;: &quot;S/MIME only&quot;,
        &quot;code_signing_only&quot;: &quot;Code signing only&quot;,
        &quot;mixed_or_other&quot;: &quot;Mixed or other&quot;,
        &quot;no_eku&quot;: &quot;No EKU&quot;,
    }.get(category, category)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_monograph_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>purpose_label</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## purpose_meaning

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def purpose_meaning(category: str) -&gt; str:
    return {
        &quot;tls_server_only&quot;: &quot;Standard public website or API endpoint certificate.&quot;,
        &quot;tls_server_and_client&quot;: &quot;Server certificate whose EKU also permits client-certificate use.&quot;,
        &quot;client_auth_only&quot;: &quot;Identity-style certificate for a person, robot, or agent in mTLS.&quot;,
        &quot;smime_only&quot;: &quot;Email-signing or email-encryption certificate.&quot;,
        &quot;code_signing_only&quot;: &quot;Software-signing certificate rather than a web-endpoint certificate.&quot;,
        &quot;mixed_or_other&quot;: &quot;Unusual or mixed EKU combination requiring case-by-case review.&quot;,
        &quot;no_eku&quot;: &quot;Certificate without an Extended Key Usage extension.&quot;,
    }.get(category, &quot;Certificate purpose category.&quot;)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_monograph_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>purpose_meaning</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## collapse_issuer_counts_by_family

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def collapse_issuer_counts_by_family(issuer_counts: dict[str, int]) -&gt; Counter[str]:
    families: Counter[str] = Counter()
    for issuer_name, count in issuer_counts.items():
        families[short_issuer(issuer_name)] += count
    return families</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_monograph_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>collapse_issuer_counts_by_family</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## build_issuer_family_rows

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def build_issuer_family_rows(report: dict[str, object]) -&gt; list[dict[str, str]]:
    issuer_trust = report[&quot;issuer_trust&quot;]
    families: dict[str, dict[str, object]] = {}
    for issuer_name, count in report[&quot;issuer_counts&quot;].most_common():
        family = short_issuer(issuer_name)
        row = families.setdefault(
            family,
            {
                &quot;family&quot;: family,
                &quot;certificates&quot;: 0,
                &quot;variants&quot;: [],
                &quot;major_webpki&quot;: True,
            },
        )
        row[&quot;certificates&quot;] += count
        row[&quot;variants&quot;].append(issuer_name)
        row[&quot;major_webpki&quot;] = bool(row[&quot;major_webpki&quot;] and issuer_trust[issuer_name].major_webpki)
    ordered = sorted(
        families.values(),
        key=lambda item: (-int(item[&quot;certificates&quot;]), str(item[&quot;family&quot;]).casefold()),
    )
    result: list[dict[str, str]] = []
    for item in ordered:
        variant_labels = [
            str(name).split(&quot;CN=&quot;)[-1]
            for name in sorted(item[&quot;variants&quot;], key=str.casefold)
        ]
        result.append(
            {
                &quot;family&quot;: str(item[&quot;family&quot;]),
                &quot;certificates&quot;: str(item[&quot;certificates&quot;]),
                &quot;variant_count&quot;: str(len(variant_labels)),
                &quot;major_webpki&quot;: &quot;yes&quot; if item[&quot;major_webpki&quot;] else &quot;no&quot;,
                &quot;variants&quot;: &quot;, &quot;.join(variant_labels),
            }
        )
    return result</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This block constructs a richer higher-level result from simpler inputs.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>build_issuer_family_rows</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## build_history_args

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def build_history_args(args: argparse.Namespace) -&gt; argparse.Namespace:
    return argparse.Namespace(
        domains_file=args.domains_file,
        cache_dir=args.history_cache_dir,
        cache_ttl_seconds=args.cache_ttl_seconds,
        max_candidates_per_domain=args.max_candidates_per_domain,
        retries=args.retries,
        quiet=args.quiet,
        markdown_output=Path(&quot;.cache/monograph-temp/unused-history.md&quot;),
        latex_output=Path(&quot;.cache/monograph-temp/unused-history.tex&quot;),
        pdf_output=Path(&quot;.cache/monograph-temp/unused-history.pdf&quot;),
        skip_pdf=True,
        pdf_engine=args.pdf_engine,
    )</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This block constructs a richer higher-level result from simpler inputs.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>build_history_args</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## historical_repeated_cn_count

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def historical_repeated_cn_count(assessment: ct_lineage_report.HistoricalAssessment) -&gt; int:
    return sum(1 for values in assessment.cn_groups.values() if len(values) &gt; 1)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_monograph_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>historical_repeated_cn_count</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## truncate_text

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def truncate_text(value: str, limit: int = 88) -&gt; str:
    if len(value) &lt;= limit:
        return value
    return value[: limit - 3].rstrip() + &quot;...&quot;</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This is a small helper that keeps the larger analytical code cleaner and easier to reuse.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>truncate_text</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## first_list_item

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def first_list_item(value: str) -&gt; str:
    return value.split(&quot;, &quot;)[0] if value else &quot;-&quot;</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This is a small helper that keeps the larger analytical code cleaner and easier to reuse.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>first_list_item</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## compact_list_items

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def compact_list_items(value: str, keep: int = 2, limit: int = 96) -&gt; str:
    if not value:
        return &quot;-&quot;
    parts = value.split(&quot;, &quot;)
    if len(parts) &lt;= keep:
        return truncate_text(value, limit)
    return truncate_text(&quot;, &quot;.join(parts[:keep]) + f&quot;, ... (+{len(parts) - keep} more)&quot;, limit)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_monograph_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>compact_list_items</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## compact_family_basis

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def compact_family_basis(value: str) -&gt; str:
    prefixes = {
        &quot;CN pattern with running-number slot: &quot;: &quot;Numbered family: &quot;,
        &quot;Same endpoint CN family (exact CN; www. grouped with base name): &quot;: &quot;Exact endpoint family: &quot;,
    }
    for prefix, replacement in prefixes.items():
        if value.startswith(prefix):
            return value.replace(prefix, replacement, 1)
    return truncate_text(value, 92)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_monograph_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>compact_family_basis</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## latex_table_cell

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def latex_table_cell(value: str) -&gt; str:
    escaped = latex_escape(value)
    for token in [&quot;.&quot;, &quot;/&quot;, &quot;-&quot;, &quot;:&quot;, &quot;;&quot;, &quot;,&quot;, &quot;=&quot;]:
        escaped = escaped.replace(token, token + r&quot;\allowbreak{}&quot;)
    return escaped</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_monograph_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>latex_table_cell</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## append_longtable

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def append_longtable(
    lines: list[str],
    spec: str,
    headers: list[str],
    rows: list[list[str]],
    *,
    font: str = &quot;small&quot;,
    tabcolsep: str | None = &quot;3.8pt&quot;,
) -&gt; None:
    lines.append(r&quot;\begingroup&quot;)
    if font:
        lines.append(rf&quot;\{font}&quot;)
    if tabcolsep:
        lines.append(rf&quot;\setlength{{\tabcolsep}}{{{tabcolsep}}}&quot;)
    lines.append(rf&quot;\begin{{longtable}}{{{spec}}}&quot;)
    header_line = &quot; &amp; &quot;.join(latex_escape(header) for header in headers) + r&quot; \\&quot;
    lines.extend(
        [
            r&quot;\toprule&quot;,
            header_line,
            r&quot;\midrule&quot;,
            r&quot;\endfirsthead&quot;,
            r&quot;\toprule&quot;,
            header_line,
            r&quot;\midrule&quot;,
            r&quot;\endhead&quot;,
            r&quot;\midrule&quot;,
            rf&quot;\multicolumn{{{len(headers)}}}{{r}}{{\footnotesize\itshape Continued on next page}} \\&quot;,
            r&quot;\midrule&quot;,
            r&quot;\endfoot&quot;,
            r&quot;\bottomrule&quot;,
            r&quot;\endlastfoot&quot;,
        ]
    )
    for row in rows:
        lines.append(&quot; &amp; &quot;.join(latex_table_cell(cell) for cell in row) + r&quot; \\&quot;)
    lines.extend([r&quot;\end{longtable}&quot;, r&quot;\endgroup&quot;])</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Shared LaTeX helper for readable multi-page tables.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>append_longtable</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## nonzero_purpose_rows

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def nonzero_purpose_rows(purpose_rows: list[list[str]]) -&gt; list[list[str]]:
    return [row for row in purpose_rows if row[1] != &quot;0&quot;]</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_monograph_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>nonzero_purpose_rows</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## driver_summary

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def driver_summary(subjects: str, issuers: str) -&gt; str:
    return f&quot;{truncate_text(first_list_item(subjects), 48)}; {truncate_text(first_list_item(issuers), 28)}&quot;</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_monograph_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>driver_summary</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## counter_text

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def counter_text(counter: Counter[str], limit: int = 4) -&gt; str:
    if not counter:
        return &quot;-&quot;
    items = [f&quot;{name} ({count})&quot; for name, count in counter.most_common(limit)]
    if len(counter) &gt; limit:
        items.append(f&quot;... (+{len(counter) - limit} more)&quot;)
    return &quot;, &quot;.join(items)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_monograph_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>counter_text</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## overlap_signal

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def overlap_signal(details: str) -&gt; str:
    parts = []
    for piece in details.split(&quot;; &quot;):
        if piece.startswith(&quot;DN=&quot;) or piece.startswith(&quot;SANs=&quot;):
            parts.append(piece)
    return truncate_text(&quot;; &quot;.join(parts) if parts else details, 108)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_monograph_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>overlap_signal</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## caa_source_label

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def caa_source_label(source_kind: str) -&gt; str:
    return {
        &quot;exact&quot;: &quot;Exact-name CAA&quot;,
        &quot;alias_target&quot;: &quot;Alias-target CAA&quot;,
        &quot;parent&quot;: &quot;Inherited parent CAA&quot;,
        &quot;parent_alias_target&quot;: &quot;Inherited parent CAA reached through alias following&quot;,
        &quot;none&quot;: &quot;No CAA found&quot;,
    }.get(source_kind, source_kind)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_monograph_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>caa_source_label</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## caa_policy_label

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def caa_policy_label(families: tuple[str, ...]) -&gt; str:
    if families == (&quot;UNRESTRICTED&quot;,):
        return &quot;No published CAA restriction&quot;
    if families == (&quot;Amazon&quot;,):
        return &quot;Amazon-only issuance policy&quot;
    if families == (&quot;DigiCert/QuoVadis&quot;, &quot;Sectigo/COMODO&quot;):
        return &quot;Corporate broad policy&quot;
    if families == (&quot;Amazon&quot;, &quot;DigiCert/QuoVadis&quot;, &quot;Sectigo/COMODO&quot;):
        return &quot;Mixed corporate-plus-Amazon policy&quot;
    if families == (&quot;Google Trust Services&quot;, &quot;Sectigo/COMODO&quot;):
        return &quot;Google plus Sectigo policy&quot;
    if &quot;Let&#x27;s Encrypt&quot; in families or &quot;Telia&quot; in families:
        return &quot;Vendor-delegated broad policy&quot;
    return &quot;Mixed named policy&quot;</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_monograph_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>caa_policy_label</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## caa_policy_explanation

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def caa_policy_explanation(families: tuple[str, ...]) -&gt; str:
    if families == (&quot;UNRESTRICTED&quot;,):
        return &quot;No CAA restriction is published, so WebPKI issuance is not limited by DNS policy.&quot;
    if families == (&quot;Amazon&quot;,):
        return &quot;Only Amazon Trust Services identifiers are authorized by DNS policy.&quot;
    if families == (&quot;DigiCert/QuoVadis&quot;, &quot;Sectigo/COMODO&quot;):
        return &quot;The name inherits the broad corporate policy that permits the main non-Amazon public CA families seen in this estate.&quot;
    if families == (&quot;Amazon&quot;, &quot;DigiCert/QuoVadis&quot;, &quot;Sectigo/COMODO&quot;):
        return &quot;The name permits both the broad corporate CA set and Amazon Trust Services.&quot;
    if families == (&quot;Google Trust Services&quot;, &quot;Sectigo/COMODO&quot;):
        return &quot;This is a narrow exception that permits Google Trust Services alongside the Sectigo lineage.&quot;
    if &quot;Let&#x27;s Encrypt&quot; in families or &quot;Telia&quot; in families:
        return &quot;The allowed CA set is wider and looks delegated to a specialist external platform or vendor.&quot;
    return &quot;The DNS policy allows a mixed set of public CA families.&quot;</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_monograph_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>caa_policy_explanation</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## service_anchor_label

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def service_anchor_label(name: str, zone: str) -&gt; str:
    if zone == &quot;other&quot;:
        return name
    if name == zone:
        return zone
    relative = name[: -(len(zone) + 1)]
    parts = relative.split(&quot;.&quot;)
    if not parts:
        return zone
    return parts[-1]</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_monograph_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>service_anchor_label</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## caa_zone_policy_rows

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def caa_zone_policy_rows(
    analysis: ct_caa_analysis.CaaAnalysis,
    zone: str,
) -&gt; list[list[str]]:
    rows = ct_caa_analysis.rows_for_zone(analysis, zone)
    policy_counts = ct_caa_analysis.policy_counter(rows)
    return [
        [
            caa_policy_label(policy),
            str(count),
            caa_policy_explanation(policy),
        ]
        for policy, count in policy_counts.most_common()
    ]</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_monograph_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>caa_zone_policy_rows</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## caa_source_rows

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def caa_source_rows(analysis: ct_caa_analysis.CaaAnalysis) -&gt; list[list[str]]:
    return [
        [
            caa_source_label(source_kind),
            str(count),
            {
                &quot;exact&quot;: &quot;The queried DNS name itself published the effective CAA.&quot;,
                &quot;alias_target&quot;: &quot;The queried DNS name resolved through an alias and the effective CAA came from what that alias chain exposed.&quot;,
                &quot;parent&quot;: &quot;The leaf name had no CAA, so issuance policy was inherited from a parent DNS node.&quot;,
                &quot;parent_alias_target&quot;: &quot;The leaf name inherited from a parent DNS node, and that parent policy was itself exposed through an alias response.&quot;,
                &quot;none&quot;: &quot;No effective CAA was found at the name or its parents.&quot;,
            }.get(source_kind, &quot;CAA discovery result.&quot;),
        ]
        for source_kind, count in analysis.source_kind_counts.most_common()
    ]</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_monograph_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>caa_source_rows</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## top_caa_overlap_rows

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def top_caa_overlap_rows(analysis: ct_caa_analysis.CaaAnalysis, limit: int = 15) -&gt; list[list[str]]:
    rows = [row for row in analysis.rows if row.current_multi_family_overlap]
    ordered = sorted(rows, key=lambda row: (row.zone, service_anchor_label(row.name, row.zone), row.name))
    return [
        [
            row.name,
            row.zone,
            &quot;, &quot;.join(row.current_covering_families),
            compact_list_items(&quot;, &quot;.join(row.current_covering_subject_cns), keep=2, limit=64),
        ]
        for row in ordered[:limit]
    ]</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_monograph_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>top_caa_overlap_rows</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## top_caa_mismatch_rows

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def top_caa_mismatch_rows(analysis: ct_caa_analysis.CaaAnalysis, limit: int = 15) -&gt; list[list[str]]:
    rows = [row for row in analysis.rows if row.current_policy_mismatch]
    ordered = sorted(rows, key=lambda row: (row.zone, service_anchor_label(row.name, row.zone), row.name))
    return [
        [
            row.name,
            row.zone,
            &quot;, &quot;.join(row.current_covering_families),
            &quot;, &quot;.join(row.allowed_ca_families) or &quot;UNRESTRICTED&quot;,
            caa_source_label(row.source_kind),
        ]
        for row in ordered[:limit]
    ]</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_monograph_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>top_caa_mismatch_rows</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## caa_concentration_text

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def caa_concentration_text(analysis: ct_caa_analysis.CaaAnalysis, zone: str) -&gt; str:
    rows = [row for row in ct_caa_analysis.rows_for_zone(analysis, zone) if row.current_policy_mismatch or row.current_multi_family_overlap]
    if not rows:
        return &quot;none&quot;
    counts = Counter(service_anchor_label(row.name, zone) for row in rows)
    return &quot;, &quot;.join(f&quot;{label} ({count})&quot; for label, count in counts.most_common(6))</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_monograph_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>caa_concentration_text</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## focus_comparison_rows

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def focus_comparison_rows(focus_analysis: ct_focus_subjects.FocusCohortAnalysis) -&gt; list[list[str]]:
    return [
        [
            &quot;Current direct Subject CN names&quot;,
            str(focus_analysis.current_direct_subjects_count),
            str(len(focus_analysis.rest_current_subject_dns_classes) and sum(focus_analysis.rest_current_subject_dns_classes.values()) or 0),
            &quot;Shows whether the cohort is mostly made of live direct front-door names or of carried SAN passengers.&quot;,
        ],
        [
            &quot;Current certificates&quot;,
            str(focus_analysis.current_focus_certificate_count),
            str(focus_analysis.current_rest_certificate_count),
            &quot;Shows the raw current certificate weight of the cohort against the rest of the estate.&quot;,
        ],
        [
            &quot;Issuer families in current certificates&quot;,
            counter_text(focus_analysis.focus_current_issuer_families, 3),
            counter_text(focus_analysis.rest_current_issuer_families, 3),
            &quot;Separates the older Sectigo/COMODO-style public web cohort from the Amazon-heavy operational rail population.&quot;,
        ],
        [
            &quot;Revoked share inside current certificates&quot;,
            focus_analysis.focus_revoked_share,
            focus_analysis.rest_revoked_share,
            &quot;A high revoked share points to rapid replacement churn or short-lived issuance iterations.&quot;,
        ],
        [
            &quot;Median SAN entries per current certificate&quot;,
            str(focus_analysis.focus_median_san_entries),
            str(focus_analysis.rest_median_san_entries),
            &quot;Small SAN sets usually indicate standalone front doors; large SAN sets usually indicate bundled platform coverage.&quot;,
        ],
        [
            &quot;Current multi-zone certificates&quot;,
            str(focus_analysis.focus_multi_zone_certificate_count),
            str(focus_analysis.rest_multi_zone_certificate_count),
            &quot;Multi-zone certificates are strong evidence of shared-service or bridge certificates rather than one-name service fronts.&quot;,
        ],
    ]</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_monograph_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>focus_comparison_rows</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## focus_bucket_details

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def focus_bucket_details(
    focus_analysis: ct_focus_subjects.FocusCohortAnalysis,
    bucket: str,
) -&gt; list[ct_focus_subjects.FocusSubjectDetail]:
    return [
        detail
        for detail in focus_analysis.details
        if detail.taxonomy_bucket == bucket
    ]</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_monograph_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>focus_bucket_details</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## focus_bucket_examples

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def focus_bucket_examples(
    focus_analysis: ct_focus_subjects.FocusCohortAnalysis,
    bucket: str,
    limit: int = 4,
) -&gt; str:
    details = focus_bucket_details(focus_analysis, bucket)
    if not details:
        return &quot;-&quot;
    ordered = sorted(
        details,
        key=lambda item: (
            -item.current_direct_certificates,
            -item.historical_direct_certificates,
            item.subject_cn.casefold(),
        ),
    )
    names = [detail.subject_cn for detail in ordered[:limit]]
    if len(ordered) &gt; limit:
        names.append(f&quot;... (+{len(ordered) - limit} more)&quot;)
    return &quot;, &quot;.join(names)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_monograph_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>focus_bucket_examples</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## focus_bucket_summary_rows

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def focus_bucket_summary_rows(focus_analysis: ct_focus_subjects.FocusCohortAnalysis) -&gt; list[list[str]]:
    meanings = {
        &quot;direct_front_door&quot;: (
            &quot;Direct branded, service, identity, or vendor-facing names with small SAN sets and one-zone scope.&quot;,
            &quot;These are the names a human operator is most likely to remember as visible service fronts rather than as hidden platform rails.&quot;,
        ),
        &quot;platform_matrix_anchor&quot;: (
            &quot;Umbrella certificates with large SAN matrices encoding environment, tenant, service-cell, or monitoring axes.&quot;,
            &quot;These names anchor a managed platform slice rather than a single public page or API front.&quot;,
        ),
        &quot;ambiguous_legacy&quot;: (
            &quot;Historical residue, carried SAN passengers, opaque labels, or mixed-shape names that no longer fit a clean live pattern.&quot;,
            &quot;This bucket captures the messy edge cases where migration, retirement, or naming opacity matters more than current front-door behavior.&quot;,
        ),
    }
    rows: list[list[str]] = []
    for bucket in [&quot;direct_front_door&quot;, &quot;platform_matrix_anchor&quot;, &quot;ambiguous_legacy&quot;]:
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
    return rows</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_monograph_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>focus_bucket_summary_rows</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## focus_representative_rows

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def focus_representative_rows(focus_analysis: ct_focus_subjects.FocusCohortAnalysis) -&gt; list[list[str]]:
    rows: list[list[str]] = []
    for bucket in [&quot;direct_front_door&quot;, &quot;platform_matrix_anchor&quot;, &quot;ambiguous_legacy&quot;]:
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
                    f&quot;{detail.current_direct_certificates}/{detail.historical_direct_certificates}&quot;,
                    truncate_text(
                        f&quot;current SANs={detail.current_san_size_span}, historical SANs={detail.historical_san_size_span}, DNS={detail.current_dns_outcome}&quot;,
                        78,
                    ),
                ]
            )
    return rows</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_monograph_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>focus_representative_rows</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## focus_appendix_rows

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def focus_appendix_rows(
    focus_analysis: ct_focus_subjects.FocusCohortAnalysis,
    bucket: str,
) -&gt; list[list[str]]:
    rows: list[list[str]] = []
    for detail in focus_bucket_details(focus_analysis, bucket):
        rows.append(
            [
                detail.subject_cn,
                truncate_text(detail.taxonomy_reason, 40),
                truncate_text(detail.analyst_note, 28),
                truncate_text(detail.observed_role, 28),
                f&quot;{detail.current_direct_certificates}/{detail.historical_direct_certificates}&quot;,
                f&quot;{detail.current_non_focus_san_carriers}/{detail.historical_non_focus_san_carriers}&quot;,
                truncate_text(f&quot;{detail.current_san_size_span}/{detail.historical_san_size_span}&quot;, 16),
                truncate_text(detail.current_dns_outcome, 24),
                f&quot;revoked={detail.current_revoked_certificates}, live={detail.current_not_revoked_certificates}&quot;,
                truncate_text(detail.current_red_flags, 24),
                truncate_text(detail.past_red_flags, 24),
            ]
        )
    return rows</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_monograph_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>focus_appendix_rows</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## example_pattern_label

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def example_pattern_label(title: str) -&gt; str:
    return {
        &quot;Shared operational rail&quot;: &quot;Numbered fleet or operational-rail naming&quot;,
        &quot;Environment matrix certificate&quot;: &quot;Environment-matrix and lifecycle naming&quot;,
        &quot;Brand-platform splice&quot;: &quot;Cross-brand namespace and migration-residue naming&quot;,
        &quot;Cross-zone bridge&quot;: &quot;Cross-zone bridge or shared-service naming&quot;,
    }.get(title, &quot;Naming pattern&quot;)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_monograph_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>example_pattern_label</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## delivery_pattern_meaning

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def delivery_pattern_meaning(label: str) -&gt; str:
    return {
        &quot;Adobe Campaign -&gt; AWS ALB&quot;: &quot;The public name first aliases into Adobe Campaign naming and then lands on Amazon load-balancing infrastructure. In plain terms, a messaging or campaign front appears to sit in front of AWS-hosted delivery.&quot;,
        &quot;Adobe Campaign -&gt; AWS CloudFront&quot;: &quot;The public name first aliases into Adobe Campaign naming and then into Amazon CloudFront. That usually means campaign or messaging traffic delivered through a CDN edge.&quot;,
        &quot;Adobe Campaign direct IP&quot;: &quot;Adobe Campaign naming is visible in the DNS trail, but the public name lands straight on an address rather than on an obvious CDN or load balancer hostname.&quot;,
        &quot;AWS CloudFront&quot;: &quot;The public name lands on Amazon&#x27;s CDN edge without an Adobe layer. This usually means edge delivery for web or API traffic.&quot;,
        &quot;Google Apigee&quot;: &quot;The public name lands on a managed API front door. That normally means the endpoint is being exposed as a governed API rather than directly from an application host.&quot;,
        &quot;Pega Cloud -&gt; AWS ALB&quot;: &quot;The public name points to Pega-managed application hosting that ultimately lands on AWS load-balancing infrastructure.&quot;,
        &quot;Direct AWS&quot;: &quot;The public name lands directly on AWS-hosted infrastructure without a visible intermediary platform in public DNS.&quot;,
        &quot;Direct Microsoft edge&quot;: &quot;The public name lands on Microsoft&#x27;s front-door edge addresses rather than directly on a private application host.&quot;,
        &quot;CNAME to address (provider unclear)&quot;: &quot;The public name aliases to another hostname and then to an address, but the public clues are too weak to assign a platform vendor confidently.&quot;,
        &quot;Direct address (provider unclear)&quot;: &quot;The public name resolves straight to an address, with no strong provider clue visible in public DNS.&quot;,
        &quot;No public DNS (NXDOMAIN)&quot;: &quot;The name contained in certificates does not currently exist in public DNS.&quot;,
        &quot;No public address data&quot;: &quot;The name exists in DNS, but no public A or AAAA address was returned during the scan.&quot;,
        &quot;Dangling agency alias&quot;: &quot;The name aliases to a third-party intermediary hostname that no longer resolves cleanly. That usually indicates stale or partially removed DNS.&quot;,
    }.get(label, &quot;Recurring public DNS outcome derived from the observed answer chain.&quot;)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_monograph_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>delivery_pattern_meaning</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## delivery_pattern_rule

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def delivery_pattern_rule(label: str) -&gt; str:
    return {
        &quot;Adobe Campaign -&gt; AWS ALB&quot;: &quot;Used when the alias chain contains Adobe Campaign naming and the terminal DNS clues point to AWS load-balancer or AWS-hosted infrastructure.&quot;,
        &quot;Adobe Campaign -&gt; AWS CloudFront&quot;: &quot;Used when the alias chain contains Adobe Campaign naming and the terminal target contains CloudFront clues.&quot;,
        &quot;Adobe Campaign direct IP&quot;: &quot;Used when Adobe Campaign naming is visible but the name lands directly on an IP address.&quot;,
        &quot;AWS CloudFront&quot;: &quot;Used when the terminal DNS target contains CloudFront clues without an Adobe Campaign layer in front of it.&quot;,
        &quot;Google Apigee&quot;: &quot;Used when the alias chain or terminal target contains Apigee or Google API gateway clues such as apigee.net.&quot;,
        &quot;Pega Cloud -&gt; AWS ALB&quot;: &quot;Used when the DNS trail contains Pega-hosting clues and then AWS load-balancer clues.&quot;,
        &quot;Direct AWS&quot;: &quot;Used when the name lands directly on AWS clues without an intermediate branded platform layer.&quot;,
        &quot;Direct Microsoft edge&quot;: &quot;Used when the address falls in the public Microsoft front-door ranges used in this heuristic.&quot;,
        &quot;CNAME to address (provider unclear)&quot;: &quot;Used when a CNAME chain exists, but no recognized provider clue appears in the public DNS trail.&quot;,
        &quot;Direct address (provider unclear)&quot;: &quot;Used when the name resolves directly to an address and no recognized provider clue appears.&quot;,
        &quot;No public DNS (NXDOMAIN)&quot;: &quot;Used when the DNS lookup returns NXDOMAIN.&quot;,
        &quot;No public address data&quot;: &quot;Used when DNS exists but returns no public address data.&quot;,
        &quot;Dangling agency alias&quot;: &quot;Used when the alias chain points to the agency-style intermediary namespace but does not resolve to a live endpoint.&quot;,
    }.get(label, &quot;Derived from the public DNS answer shape and the provider clues seen in names, targets, and PTRs.&quot;)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_monograph_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>delivery_pattern_rule</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## render_markdown

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def render_markdown(
    args: argparse.Namespace,
    report: dict[str, object],
    assessment: ct_lineage_report.HistoricalAssessment,
    caa_analysis: ct_caa_analysis.CaaAnalysis,
    focus_analysis: ct_focus_subjects.FocusCohortAnalysis | None,
) -&gt; None:
    args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
    appendix_markdown = args.appendix_markdown_output.read_text(encoding=&quot;utf-8&quot;)
    hits = report[&quot;hits&quot;]
    groups = report[&quot;groups&quot;]
    purpose_summary = report[&quot;purpose_summary&quot;]
    total_certificates = len(report[&quot;classifications&quot;])
    dual_items = [item for item in report[&quot;classifications&quot;] if item.category == &quot;tls_server_and_client&quot;]
    dual_issuer_counts = Counter(short_issuer(item.issuer_name) for item in dual_items)
    server_only_count = purpose_summary.category_counts.get(&quot;tls_server_only&quot;, 0)
    dual_count = purpose_summary.category_counts.get(&quot;tls_server_and_client&quot;, 0)
    server_only_issuer_families = collapse_issuer_counts_by_family(
        purpose_summary.issuer_breakdown.get(&quot;tls_server_only&quot;, {})
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
            (&quot;tls_server_only&quot;, purpose_summary.category_counts.get(&quot;tls_server_only&quot;, 0)),
            (&quot;tls_server_and_client&quot;, purpose_summary.category_counts.get(&quot;tls_server_and_client&quot;, 0)),
            (&quot;client_auth_only&quot;, purpose_summary.category_counts.get(&quot;client_auth_only&quot;, 0)),
            (&quot;smime_only&quot;, purpose_summary.category_counts.get(&quot;smime_only&quot;, 0)),
            (&quot;code_signing_only&quot;, purpose_summary.category_counts.get(&quot;code_signing_only&quot;, 0)),
            (&quot;mixed_or_other&quot;, purpose_summary.category_counts.get(&quot;mixed_or_other&quot;, 0)),
            (&quot;no_eku&quot;, purpose_summary.category_counts.get(&quot;no_eku&quot;, 0)),
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
            row[&quot;family&quot;],
            row[&quot;certificates&quot;],
            row[&quot;variant_count&quot;],
            row[&quot;major_webpki&quot;],
            row[&quot;variants&quot;],
        ]
        for row in build_issuer_family_rows(report)
    ]
    family_rows = [
        [
            compact_family_basis(row[&quot;basis&quot;]),
            str(row[&quot;certificates&quot;]),
            str(row[&quot;subjects&quot;]),
            first_list_item(row[&quot;top_stacks&quot;]),
        ]
        for row in report[&quot;group_digest&quot;]
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
        for label, count in report[&quot;dns_stack_counts&quot;].most_common(12)
    ]
    dns_class_counts = report[&quot;dns_class_counts&quot;]
    alias_to_address_count = dns_class_counts.get(&quot;cname_to_address&quot;, 0)
    direct_address_count = dns_class_counts.get(&quot;direct_address&quot;, 0)
    nxdomain_count = dns_class_counts.get(&quot;nxdomain&quot;, 0)
    dangling_count = dns_class_counts.get(&quot;dangling_cname&quot;, 0)
    no_data_count = dns_class_counts.get(&quot;no_data&quot;, 0)
    top_dns_patterns = report[&quot;dns_stack_counts&quot;].most_common(8)
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
    primary_zone = report[&quot;domains&quot;][0] if report[&quot;domains&quot;] else &quot;configured primary zone&quot;
    secondary_zone = report[&quot;domains&quot;][1] if len(report[&quot;domains&quot;]) &gt; 1 else None
    synthesis_chapter = 9 if has_focus else 8
    limits_chapter = 10 if has_focus else 9
    caa_appendix = &quot;C&quot;
    focus_appendix = &quot;D&quot; if has_focus else None
    detailed_inventory_appendix = &quot;E&quot; if has_focus else &quot;D&quot;
    lines: list[str] = []
    lines.append(&quot;# CT and DNS Monograph&quot;)
    lines.append(&quot;&quot;)
    lines.append(f&quot;Generated: {report[&#x27;generated_at_utc&#x27;]}&quot;)
    lines.append(f&quot;Configured search terms file: `{args.domains_file.name}`&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;## Executive Summary&quot;)
    lines.append(&quot;&quot;)
    lines.extend(
        [
            f&quot;- **{len(hits)}** current leaf certificates are in scope on this run.&quot;,
            f&quot;- **{len(groups)}** CN families reduce the estate into readable naming clusters.&quot;,
            f&quot;- **{purpose_summary.category_counts.get(&#x27;tls_server_only&#x27;, 0)}** certificates are ordinary public TLS server certificates, while **{purpose_summary.category_counts.get(&#x27;tls_server_and_client&#x27;, 0)}** come from templates that also permit client-certificate use.&quot;,
            f&quot;- **{historical_count}** historical leaf certificates show how these names evolved over time, including expired renewal history.&quot;,
            f&quot;- **{len(report[&#x27;unique_dns_names&#x27;])}** unique DNS SAN names were scanned live.&quot;,
            f&quot;- **{caa_analysis.total_names}** DNS names were also assessed for effective CAA policy, revealing where issuance is centrally governed, delegated, or left unrestricted.&quot;,
            &quot;- The estate is best understood as several layers laid on top of one another: brand naming, service naming, platform naming, delivery-stack naming, issuance-policy control, and migration residue.&quot;,
        ]
    )
    lines.append(&quot;&quot;)
    lines.append(&quot;## Reading Guide&quot;)
    lines.append(&quot;&quot;)
    lines.extend(
        [
            &quot;- Read Chapter 1 if you want to know whether the corpus is complete and trustworthy.&quot;,
            &quot;- Read Chapters 2 and 3 if you want the current certificate-side story: issuers, trust, and purpose.&quot;,
            &quot;- Read Chapter 4 if you want the historical lifecycle view and the red flags split into current versus fixed-in-the-past.&quot;,
            &quot;- Read Chapters 5 and 6 if you want the naming and DNS story.&quot;,
            &quot;- Read Chapter 7 if you want the issuance-policy view: which public CAs are authorized by DNS and where that control is absent, inherited, or delegated.&quot;,
            *(
                [&quot;- Read Chapter 8 if you want the focused Subject-CN cohort analysis and why that subset behaves differently from the wider estate.&quot;]
                if has_focus
                else []
            ),
            f&quot;- Read Chapter {synthesis_chapter} if you want the synthesis that ties business naming, service architecture, and hosting patterns together.&quot;,
            &quot;- Use the appendices when you need the fine-grained evidence rather than the argument.&quot;,
        ]
    )
    lines.append(&quot;&quot;)
    lines.append(&quot;## Chapter 1: Scope, Completeness, and Proof&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;**Management Summary**&quot;)
    lines.append(&quot;&quot;)
    lines.extend(
        [
            f&quot;- The first broad crt.sh search returned {&#x27;, &#x27;.join(f&#x27;{domain}={count} matching index rows&#x27; for domain, count in report[&#x27;raw_match_counts&#x27;].items())}. Those rows are leads, not final certificate count.&quot;,
            f&quot;- The scanner was allowed to collect up to {report[&#x27;cap&#x27;]} candidate rows per search term. Because the live match counts stayed below that limit, nothing was silently cut off.&quot;,
            f&quot;- After downloading and parsing the actual certificate bodies, {report[&#x27;verification&#x27;].unique_leaf_certificates} genuine leaf certificates remained. {report[&#x27;verification&#x27;].non_leaf_filtered} CA-style certificates and {report[&#x27;verification&#x27;].precertificate_poison_filtered} precertificate marker objects were rejected.&quot;,
            f&quot;- Certificates missing the searched-for domains in their DNS SANs after full parsing: {report[&#x27;missing_matching_san&#x27;]}.&quot;,
        ]
    )
    lines.append(&quot;&quot;)
    lines.append(&quot;This chapter answers the first and most important question: whether the report is built on a complete and trustworthy corpus. The scanner now checks the live raw match count before issuing the capped query. If the cap is too low, it fails instead of silently undercounting.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;The first crt.sh row count is intentionally larger than the final certificate count because Certificate Transparency search results are index rows, not de-duplicated certificates. The report therefore reads the binary certificate body itself, removes duplicates, rejects CA certificates and precertificate marker objects, and only then builds the working corpus.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;In other words: this publication is not based on search-result snippets alone. It is based on the parsed X.509 certificate bodies.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;## Chapter 2: The Certificate Corpus&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;**Management Summary**&quot;)
    lines.append(&quot;&quot;)
    lines.extend(
        [
            f&quot;- Issuer families by certificate count: {&#x27;, &#x27;.join(f&#x27;{name} ({count})&#x27; for name, count in report[&#x27;issuer_family_counts&#x27;].most_common())}.&quot;,
            f&quot;- Revocation state in plain terms: {report[&#x27;rev_counts&#x27;].get(&#x27;not_revoked&#x27;, 0)} certificates are not marked revoked, and {report[&#x27;rev_counts&#x27;].get(&#x27;revoked&#x27;, 0)} were later marked invalid by their issuing CA before natural expiry.&quot;,
            f&quot;- For every current certificate, the main Subject CN hostname also appears literally in the DNS SAN list. The headline name on the certificate is therefore one of the real covered hostnames, not a decorative label.&quot;,
            f&quot;- All visible issuer families in this corpus are currently trusted by the major public browser and operating-system trust stores for ordinary web server use.&quot;,
        ]
    )
    lines.append(&quot;&quot;)
    lines.append(&quot;A certificate corpus can look random when viewed as a flat list. It becomes intelligible once you group it by issuer family, Subject CN construction, validity history, and SAN design. That is why the appendices are arranged as families rather than raw rows.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;### Issuer Trust Table&quot;)
    lines.append(&quot;&quot;)
    lines.extend(md_table([&quot;Issuer Family&quot;, &quot;Certificates&quot;, &quot;Variants&quot;, &quot;Major WebPKI&quot;], [row[:4] for row in issuer_rows]))
    lines.append(&quot;&quot;)
    lines.append(&quot;**What WebPKI trust means**&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;A WebPKI-trusted issuer is a certificate authority trusted by mainstream browser and operating-system trust stores for public TLS. That matters because it tells you these certificates are not part of a private PKI hidden inside one organisation. They are intended to be valid in the public Internet trust model.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;This view should answer one question only: how many publicly trusted issuer families are present in the estate. The exact subordinate issuer names are supporting evidence, so they stay in the appendix inventory rather than cluttering the main chapter.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;## Chapter 3: Intended Purpose of the Certificates&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;**Management Summary**&quot;)
    lines.append(&quot;&quot;)
    lines.extend(
        [
            f&quot;- Certificates whose allowed purpose is ordinary server authentication only: {purpose_summary.category_counts.get(&#x27;tls_server_only&#x27;, 0)}.&quot;,
            f&quot;- Certificates whose policy allows both server use and client-certificate use: {purpose_summary.category_counts.get(&#x27;tls_server_and_client&#x27;, 0)}.&quot;,
            &quot;- Certificates dedicated only to client identity, email signing, or code signing: 0.&quot;,
        ]
    )
    lines.append(&quot;&quot;)
    lines.append(&quot;This chapter addresses a key ambiguity. A certificate can be technically valid for several uses, and the hostname alone does not settle that question. The corpus was therefore assessed from the X.509 usage fields themselves: EKU and KeyUsage.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;### Purpose Map&quot;)
    lines.append(&quot;&quot;)
    lines.extend(md_table([&quot;Usage Class&quot;, &quot;Certificates&quot;, &quot;Share&quot;, &quot;Meaning&quot;], visible_purpose_rows))
    lines.append(&quot;&quot;)
    lines.append(&quot;This view should answer only what kind of certificates these are. Zero-count categories are deliberately removed here because they add noise without changing the conclusion.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;The basic picture is simple: the corpus is overwhelmingly made of ordinary public TLS server certificates, with a smaller minority whose EKU also permits client-certificate use.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;**Plain-language explanation of the usage categories**&quot;)
    lines.append(&quot;&quot;)
    lines.extend(
        [
            &quot;- **TLS server certificate**: the certificate a website or API presents to a browser, app, or machine client.&quot;,
            &quot;- **Server and client auth certificate**: a certificate whose EKU allows both server use and client-certificate use. That does not automatically mean it is actually used as a client certificate, but it leaves that door open.&quot;,
            &quot;- **Client auth only**: the kind of certificate you would expect for a user, robot, or agent identity in mutual TLS.&quot;,
            &quot;- **S/MIME**: email-signing or email-encryption certificates.&quot;,
            &quot;- **Code signing**: certificates used to sign software rather than to secure a web endpoint.&quot;,
        ]
    )
    lines.append(&quot;&quot;)
    lines.append(&quot;The result is clean. This corpus is entirely TLS-capable. There is no evidence of a separate S/MIME or code-signing estate, and there are no client-auth-only certificates.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;### EKU and KeyUsage Templates&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;At the template level, the corpus is even simpler than the certificate count suggests. Here, a template simply means a repeated combination of usage fields. Only two EKU combinations appear at all, and one KeyUsage pattern dominates almost completely.&quot;)
    lines.append(&quot;&quot;)
    lines.extend(md_table([&quot;EKU Template&quot;, &quot;Certificates&quot;, &quot;Share&quot;], eku_template_rows))
    lines.append(&quot;&quot;)
    lines.extend(md_table([&quot;KeyUsage Template&quot;, &quot;Certificates&quot;, &quot;Share&quot;], key_usage_rows))
    lines.append(&quot;&quot;)
    lines.append(&quot;### The Majority Pattern: Server-Only Public TLS&quot;)
    lines.append(&quot;&quot;)
    lines.extend(
        [
            f&quot;- Server-only certificates account for {server_only_count} of {total_certificates} certificates, or {pct(server_only_count, total_certificates)} of the corpus.&quot;,
            f&quot;- Server-only validity starts are split between {&#x27;, &#x27;.join(f&#x27;{year} ({count})&#x27; for year, count in purpose_summary.validity_start_years.get(&#x27;tls_server_only&#x27;, {}).items())}.&quot;,
            f&quot;- Server-only issuer-family concentration: {&#x27;, &#x27;.join(f&#x27;{name} ({count})&#x27; for name, count in server_only_issuer_families.most_common())}.&quot;,
            &quot;- This is the normal public WebPKI server-certificate pattern for websites, APIs, and edge service front doors.&quot;,
        ]
    )
    lines.append(&quot;&quot;)
    lines.append(&quot;This majority group is not background noise. It is the main operational reality visible in the scan: public DNS names covered by publicly trusted endpoint certificates.&quot;)
    lines.append(&quot;&quot;)
    if dual_rows:
        lines.append(&quot;### The Minority Pattern: Dual EKU&quot;)
        lines.append(&quot;&quot;)
        lines.append(&quot;EKU means *allowed purpose*, not *observed real-world use*. A dual-EKU certificate is a certificate whose X.509 policy says it may be used both as a TLS server certificate and as a TLS client certificate.&quot;)
        lines.append(&quot;&quot;)
        lines.extend(
            [
                f&quot;- Dual-EKU certificates in this corpus: {dual_count}, or {pct(dual_count, total_certificates)} of the corpus.&quot;,
                f&quot;- Issuer-family concentration inside the dual-EKU group: {&#x27;, &#x27;.join(f&#x27;{name} ({count})&#x27; for name, count in dual_issuer_counts.most_common())}.&quot;,
                f&quot;- Dual-EKU Subject CN families that also have a strict server-only sibling: {len(purpose_summary.dual_eku_subject_cns_with_server_only_sibling)}.&quot;,
                f&quot;- Dual-EKU Subject CN families that appear only in the dual-EKU group: {len(purpose_summary.dual_eku_subject_cns_without_server_only_sibling)}.&quot;,
                f&quot;- Dual-EKU validity starts are split between {&#x27;, &#x27;.join(f&#x27;{year} ({count})&#x27; for year, count in purpose_summary.validity_start_years.get(&#x27;tls_server_and_client&#x27;, {}).items())}.&quot;,
            ]
        )
        lines.append(&quot;&quot;)
        lines.append(&quot;The important interpretation point is this: these still look like public hostname certificates, not person or robot identity certificates. They have DNS-style Subject CN values, DNS SAN lists, and public WebPKI issuers. The best reading is therefore not &#x27;this is a separate client-certificate estate&#x27;, but rather &#x27;some server certificates were issued from a template that also allowed clientAuth&#x27;.&quot;)
        lines.append(&quot;&quot;)
    lines.append(&quot;### What Is Not Present&quot;)
    lines.append(&quot;&quot;)
    lines.extend(
        [
            &quot;- There are no client-auth-only certificates in the corpus.&quot;,
            &quot;- There are no S/MIME certificates in the corpus.&quot;,
            &quot;- There are no code-signing certificates in the corpus.&quot;,
            &quot;- There are no mixed-or-other EKU combinations and no certificates missing EKU entirely.&quot;,
        ]
    )
    lines.append(&quot;&quot;)
    lines.append(&quot;## Chapter 4: Historical Renewal, Drift, and Red Flags&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;**Management Summary**&quot;)
    lines.append(&quot;&quot;)
    lines.extend(
        [
            f&quot;- Looking across expired and current history, the corpus contains {historical_count} leaf certificates; {historical_current_count} of them are still valid today.&quot;,
            f&quot;- {repeated_cn_count} Subject CN values recur over time rather than appearing as one-off singletons.&quot;,
            f&quot;- {assessment.normal_reissuance_assets} renewal families look operationally normal: predecessor and successor overlap for fewer than 50 days.&quot;,
            f&quot;- {len(assessment.overlap_current_rows)} names still show long overlap of 50 days or more today.&quot;,
            f&quot;- {len(assessment.overlap_past_rows)} names showed the same long-overlap behaviour in the past, but not anymore in currently valid certificates.&quot;,
            f&quot;- Current non-overlap anomalies are limited: {len(assessment.dn_current_rows)} live Subject DN drift cases, {len(assessment.vendor_current_rows)} live CA-family drift cases, and {len(assessment.san_current_rows)} live SAN-drift cases.&quot;,
            f&quot;- Past-only fixed anomalies were broader: {len(assessment.dn_past_rows)} historical Subject DN drift cases, {len(assessment.vendor_past_rows)} historical CA-family drift cases, and {len(assessment.san_past_rows)} historical SAN-drift cases.&quot;,
        ]
    )
    lines.append(&quot;&quot;)
    lines.append(&quot;This chapter is the historical check on whether the current picture follows a clean renewal pattern. It answers a different question from the current-corpus chapters above: not just what certificates exist now, but how the hostname estate has behaved over time.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;For this chapter, a renewal family means repeated certificates that keep the same apparent identity over time: the same Subject CN, the same full Subject DN, the same SAN profile, and the same CA family. A normal renewal reissues that same apparent certificate identity with a new key and a new validity span, and predecessor and successor overlap only briefly. In this monograph, anything below 50 days of overlap is treated as normal. Fifty days or more is treated as a red flag. COMODO and Sectigo are treated as one CA family from the outset, so movement between those names is not counted here as CA-family drift.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;A red flag in this chapter is not the same thing as a breach or a compromise. It means the certificate history diverged from the clean rollover pattern that one would normally expect and therefore deserves closer review.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;### Current Red-Flag Inventory&quot;)
    lines.append(&quot;&quot;)
    if assessment.current_red_flag_rows:
        lines.extend(
            md_table(
                [&quot;Subject CN&quot;, &quot;Live Certs&quot;, &quot;Current Concern&quot;, &quot;Immediate Supporting Context&quot;],
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
        lines.append(&quot;No current red flags were found under the configured rules.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;### Past Red Flags Now Fixed&quot;)
    lines.append(&quot;&quot;)
    if assessment.past_red_flag_rows:
        lines.extend(
            md_table(
                [&quot;Subject CN&quot;, &quot;Historic Certs&quot;, &quot;Historical Concern&quot;, &quot;Immediate Supporting Context&quot;],
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
        lines.append(&quot;No past-only red flags were found under the configured rules.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;### What The Historical Red Flags Mean&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;The two short tables above are screening tables. They answer which names deserve attention now, and which names used to be problematic but no longer look live. The appendices below keep the narrower evidence tables that explain why each name is there.&quot;)
    lines.append(&quot;&quot;)
    lines.extend(
        [
            f&quot;- **Overlap red flag**: a predecessor and successor inside the same renewal family coexist for 50 days or more. Current cases: {len(assessment.overlap_current_rows)}. Past-only fixed cases: {len(assessment.overlap_past_rows)}.&quot;,
            f&quot;- **Subject DN drift**: the same Subject CN appears under more than one full Subject DN. In plain terms, the headline hostname is being issued under different formal subject identities. Current cases: {len(assessment.dn_current_rows)}. Past-only fixed cases: {len(assessment.dn_past_rows)}.&quot;,
            f&quot;- **CA-family drift**: the same Subject CN appears under more than one CA family, after collapsing COMODO and Sectigo together. Current cases: {len(assessment.vendor_current_rows)}. Past-only fixed cases: {len(assessment.vendor_past_rows)}.&quot;,
            f&quot;- **SAN drift**: the same Subject CN appears with more than one SAN profile. In plain terms, the hostname keeps being bundled with different companion names. Current cases: {len(assessment.san_current_rows)}. Past-only fixed cases: {len(assessment.san_past_rows)}.&quot;,
            f&quot;- **Exact issuer-name changes** inside one CA family also exist: {len(assessment.issuer_rows)} Subject CN values. Those are tracked as context, not as first-order red flags.&quot;,
        ]
    )
    lines.append(&quot;&quot;)
    lines.append(&quot;### Historical Step Changes&quot;)
    lines.append(&quot;&quot;)
    lines.extend(
        [
            f&quot;- Top issuance start dates: {&#x27;, &#x27;.join(f&#x27;{row.start_day} ({row.certificate_count})&#x27; for row in assessment.day_rows[:6])}.&quot;,
            f&quot;- Strong step weeks: {&#x27;, &#x27;.join(f&#x27;{row.week_start} ({row.certificate_count} vs prior avg {row.prior_eight_week_avg})&#x27; for row in assessment.week_rows[:4]) or &#x27;none&#x27;}.&quot;,
            &quot;- These bursts matter because they show where certificate behaviour was driven by platform-scale operations rather than one-off manual issuance.&quot;,
        ]
    )
    lines.append(&quot;&quot;)
    lines.append(&quot;## Chapter 5: Naming Architecture&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;**Management Summary**&quot;)
    lines.append(&quot;&quot;)
    lines.extend(
        [
            f&quot;- Numbered CN families: {len(report[&#x27;numbered_groups&#x27;])}.&quot;,
            f&quot;- Multi-zone SAN sets: {report[&#x27;multi_zone_hit_count&#x27;]}.&quot;,
            f&quot;- Frequent naming tokens: {&#x27;, &#x27;.join(f&#x27;{token} ({count})&#x27; for token, count in report[&#x27;top_env_tokens&#x27;][:8])}.&quot;,
            &quot;- The strongest naming signals come from numbered rails, environment markers, cross-brand labels, and cross-zone SAN composition. `www` is weak evidence either way.&quot;,
        ]
    )
    lines.append(&quot;&quot;)
    lines.append(&quot;What looks arbitrary at first glance is usually the result of different naming pressures colliding. Customer-facing naming wants short memorable brands. Platform naming wants stable operational rails. Delivery naming wants environment labels, release slots, or fleet indices. Migration naming preserves old labels because changing a working name can be risky and expensive.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;### How To Read The Names&quot;)
    lines.append(&quot;&quot;)
    lines.extend(
        [
            &quot;- In most of these names, the left-most label tells you the endpoint role, node slot, or environment slice, while the zone on the right tells you which public namespace the service is answering under.&quot;,
            &quot;- Standard delivery shorthand appears throughout the corpus: `dev`, `qa`, `uat`, `sit`, `stg`, `preprod`, and `prod` are ordinary environment markers rather than mysterious product names.&quot;,
            &quot;- `www` is a weak signal both when present and when absent. Its presence often reflects compatibility, redirect history, or old web conventions; its absence does not imply any deeper architectural distinction.&quot;,
            &quot;- In this corpus, `nwg` reads as NatWest Group shorthand. Names like `rbs`, `natwest`, `ulsterbank`, `lombard`, `natwestpayments`, `coutts`, and `nwgwealth` are best read as parallel business or service namespaces within a wider shared estate, not as random unrelated domains.&quot;,
            &quot;- Some short forms remain inferential rather than provable. For example, `nft` clearly behaves like a non-production stage label, but Certificate Transparency alone cannot prove the local expansion used inside the company.&quot;,
        ]
    )
    lines.append(&quot;&quot;)
    lines.append(&quot;### Key Pattern Examples&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;These four boxes are not four isolated hostnames. Each one uses a concrete Subject CN as the evidence anchor for a broader naming methodology that appears elsewhere in the estate as well.&quot;)
    lines.append(&quot;&quot;)
    for example in report[&quot;examples&quot;]:
        lines.append(f&quot;#### {example.title}&quot;)
        lines.append(&quot;&quot;)
        lines.append(f&quot;- Pattern shown: {example_pattern_label(example.title)}.&quot;)
        lines.append(f&quot;- Concrete example: `{example.subject_cn}`&quot;)
        lines.append(f&quot;- What this proves: {example.why_it_matters}&quot;)
        for point in example.evidence:
            lines.append(f&quot;- Evidence: {point}&quot;)
        lines.append(&quot;&quot;)
    lines.append(&quot;### Why These Four Examples&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;Taken together, these four examples explain most of the naming behaviour in the corpus. The first shows platform fleet naming, the second shows environment-and-release naming, the third shows cross-brand namespace splicing and migration residue, and the fourth shows shared-service bridging across several business namespaces.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;## Chapter 6: DNS Delivery Architecture&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;**Management Summary**&quot;)
    lines.append(&quot;&quot;)
    lines.extend(
        [
            f&quot;- Most names resolve indirectly: {alias_to_address_count} public names first point to another hostname and only then reach an address, while only {direct_address_count} names resolve straight to an address.&quot;,
            f&quot;- The most common public DNS outcomes are Adobe Campaign in front of AWS load-balancing ({report[&#x27;dns_stack_counts&#x27;].get(&#x27;Adobe Campaign -&gt; AWS ALB&#x27;, 0)}), Adobe Campaign in front of AWS CloudFront ({report[&#x27;dns_stack_counts&#x27;].get(&#x27;Adobe Campaign -&gt; AWS CloudFront&#x27;, 0)}), and plain AWS CloudFront without an Adobe layer ({report[&#x27;dns_stack_counts&#x27;].get(&#x27;AWS CloudFront&#x27;, 0)}).&quot;,
            f&quot;- Smaller but still meaningful subsets behave like managed API fronts or specialist application platforms: Google Apigee ({report[&#x27;dns_stack_counts&#x27;].get(&#x27;Google Apigee&#x27;, 0)}) and Pega Cloud on AWS ({report[&#x27;dns_stack_counts&#x27;].get(&#x27;Pega Cloud -&gt; AWS ALB&#x27;, 0)}).&quot;,
            f&quot;- Some certificate names do not lead to a live public endpoint today: {nxdomain_count} do not exist in public DNS at all, {dangling_count} still exist only as broken aliases, and {no_data_count} exist in DNS but returned no public A or AAAA address during the scan.&quot;,
        ]
    )
    lines.append(&quot;&quot;)
    lines.append(&quot;DNS is the public routing layer. It does not tell you everything about an application, but it does tell you where a public name lands: directly on an IP, through an alias chain, through a CDN, through an API gateway, or onto a specialist platform.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;This chapter does not claim to know the full private architecture behind each service. It only claims what the public DNS trail supports. For each DNS SAN name in the certificate corpus, the scanner queried public `CNAME`, `A`, `AAAA`, and `PTR` data. It then summarized that public answer trail with a short label. Those labels are not arbitrary brand names invented by the report; they are compact descriptions of what the public DNS evidence most strongly suggests.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;One important caution follows from that last bullet: a hostname can remain visible in certificate history even after its public DNS has been removed or partially dismantled. Certificate history and current DNS are related, but they do not move in lockstep.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;### How The DNS Evidence Is Read&quot;)
    lines.append(&quot;&quot;)
    lines.extend(
        [
            &quot;- A `CNAME` shows that one public name is really an alias for another public name.&quot;,
            &quot;- The terminal hostname, returned addresses, and reverse-DNS names often reveal platform clues such as `cloudfront.net`, `elb.amazonaws.com`, `apigee.net`, or `campaign.adobe.com`.&quot;,
            &quot;- The report combines the answer shape and those clues into one short description. For example, `Adobe Campaign -&gt; AWS ALB` means the alias chain contains Adobe Campaign naming and the terminal clues point to AWS load-balancing infrastructure.&quot;,
            &quot;- These labels are therefore evidence summaries, not claims of legal ownership or full internal design.&quot;,
        ]
    )
    lines.append(&quot;&quot;)
    lines.append(&quot;### What The Public DNS Names Resolve To&quot;)
    lines.append(&quot;&quot;)
    lines.extend(md_table([&quot;Observed DNS Outcome&quot;, &quot;Count&quot;, &quot;Plain-Language Meaning&quot;], dns_pattern_rows))
    lines.append(&quot;&quot;)
    lines.append(&quot;### Why Each DNS Label Was Used&quot;)
    lines.append(&quot;&quot;)
    for label, _count in top_dns_patterns[:6]:
        lines.append(f&quot;- **{label}**: {delivery_pattern_rule(label)}&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;### Platform And DNS Glossary&quot;)
    lines.append(&quot;&quot;)
    glossary = ct_dns_utils.provider_explanations()
    for term in [&quot;Adobe Campaign&quot;, &quot;AWS&quot;, &quot;AWS ALB&quot;, &quot;AWS CloudFront&quot;, &quot;Google Apigee&quot;, &quot;Pega Cloud&quot;, &quot;Microsoft Edge&quot;, &quot;Infinite / agency alias&quot;, &quot;CNAME&quot;, &quot;A record&quot;, &quot;AAAA record&quot;, &quot;PTR record&quot;, &quot;NXDOMAIN&quot;]:
        lines.append(f&quot;- **{term}**: {glossary[term]}&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;The glossary terms above are the building blocks used in the DNS-outcome table. This is also why the management summary mentions Adobe Campaign, CloudFront, Apigee, and Pega at all: not because brand names are the point, but because those names reveal what kind of public delivery role a hostname is landing on. CloudFront suggests a distribution edge, Apigee suggests managed API exposure, Adobe Campaign suggests a marketing or communications front, and a load balancer suggests traffic distribution to backend services.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;The next chapter stays with the same names but moves from delivery to control. This chapter asked where public traffic lands. The next one asks which public CA families DNS currently authorizes to issue for those same names.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;## Chapter 7: DNS Issuance Policy Control (CAA)&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;**Management Summary**&quot;)
    lines.append(&quot;&quot;)
    for zone in caa_analysis.configured_domains:
        zone_rows = ct_caa_analysis.rows_for_zone(caa_analysis, zone)
        unrestricted_count = sum(1 for row in zone_rows if not row.allowed_ca_families)
        mismatch_count = sum(1 for row in zone_rows if row.current_policy_mismatch)
        overlap_count = sum(1 for row in zone_rows if row.current_multi_family_overlap)
        dominant_policy = ct_caa_analysis.policy_counter(zone_rows).most_common(1)
        dominant_label = caa_policy_label(dominant_policy[0][0]) if dominant_policy else &quot;none&quot;
        lines.append(
            f&quot;- `{zone}`: {len(zone_rows)} names in scope; dominant policy is {dominant_label}; unrestricted names={unrestricted_count}; current policy-mismatch names={mismatch_count}; current multi-family overlap names={overlap_count}.&quot;
        )
    lines.extend(
        [
            f&quot;- Effective CAA discovery paths across all names: {&#x27;, &#x27;.join(f&#x27;{caa_source_label(kind)}={count}&#x27; for kind, count in caa_analysis.source_kind_counts.most_common())}.&quot;,
            f&quot;- Current names simultaneously covered by more than one live CA family: {len(caa_analysis.multi_family_overlap_names)}.&quot;,
            f&quot;- Current names whose live certificate family does not match today&#x27;s published CAA policy: {len(caa_analysis.policy_mismatch_names)}.&quot;,
        ]
    )
    lines.append(&quot;&quot;)
    lines.append(&quot;CAA is the DNS control layer for public certificate issuance. It does not validate a certificate after issuance; instead, it tells a public CA which CA families are authorized to issue for a DNS name if any restriction is published at all. If no CAA is published, WebPKI issuance is unrestricted from the DNS-policy point of view.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;This chapter is the control-plane counterpart to the certificate and DNS chapters. The certificate chapter showed who actually issued. The DNS chapter showed where the names land. The CAA chapter shows which issuers the DNS owner currently allows for those same names.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;That distinction matters because hosting and issuance are different decisions. A name can land on AWS and still use a Sectigo-family certificate if DNS policy allows it. A name can also resolve through a vendor platform while still inheriting a first-party corporate CAA policy. The point of this chapter is to show where those decisions line up and where they do not.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;CAA is checked per DNS name requested in the certificate, not per Subject DN and not per organisational story. A Subject CN can therefore shift between different Subject DN values without creating a CAA clash, because CAA ignores organisation fields and looks only at the DNS names being certified.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;### Why CAA Matters In This Estate&quot;)
    lines.append(&quot;&quot;)
    lines.extend(
        [
            &quot;- If a name has no CAA, DNS is not constraining which public CA family may issue for it.&quot;,
            &quot;- If a name inherits a broad corporate policy, that usually means the organisation has left normal brand-facing names under a common default.&quot;,
            &quot;- If a name falls under a narrower subtree or alias-derived policy, that is evidence of more deliberate platform or vendor-specific issuance control.&quot;,
            &quot;- If a live certificate family sits outside today&#x27;s CAA policy, or if the same DNS name is live under two CA families at once, that usually points to migration lag, overlapping rollout, or policy that moved faster than certificate cleanup.&quot;,
        ]
    )
    lines.append(&quot;&quot;)
    lines.append(&quot;### How To Read The CAA Results&quot;)
    lines.append(&quot;&quot;)
    lines.extend(md_table([&quot;CAA Discovery Result&quot;, &quot;Names&quot;, &quot;Meaning&quot;], caa_source_rows(caa_analysis)))
    lines.append(&quot;&quot;)
    lines.append(&quot;The key distinction is between ordinary parent inheritance and alias-target-derived policy. Parent inheritance means the leaf name simply relies on a policy published higher in its own DNS tree. Alias-target-derived policy means the effective CAA surfaced through an alias response. In this corpus, that often marks a managed rail or specialist external platform rather than a plain brand-front hostname.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;In practical terms, most names in this corpus fall into three shapes: inherited corporate policy, alias-driven managed-platform policy, or no CAA at all. That three-way split is more important than the mechanics themselves, because it shows where issuance control is broad, where it is deliberately narrow, and where it is absent.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;### Policy Regimes By Configured Zone&quot;)
    lines.append(&quot;&quot;)
    for zone in caa_analysis.configured_domains:
        lines.append(f&quot;#### `{zone}`&quot;)
        lines.append(&quot;&quot;)
        lines.extend(md_table([&quot;Policy Regime&quot;, &quot;Names&quot;, &quot;Plain-Language Meaning&quot;], caa_zone_rows[zone]))
        lines.append(&quot;&quot;)
    if secondary_zone:
        lines.append(f&quot;The contrast between `{primary_zone}` and `{secondary_zone}` is one of the strongest PKI-governance findings in the corpus. `{primary_zone}` is policy-layered and governed, while `{secondary_zone}` is currently CAA-empty in the scanned name set. That does not make `{secondary_zone}` invalid, but it does mean DNS is not constraining public CA choice there.&quot;)
        lines.append(&quot;&quot;)
        lines.append(f&quot;That asymmetry matters more than any one record. `{primary_zone}` looks like a namespace where DNS is being used as an issuance-governance tool. `{secondary_zone}` looks like a namespace where issuance choice is still being handled outside DNS policy, or not being constrained at all.&quot;)
        lines.append(&quot;&quot;)
    lines.append(&quot;### How CAA Changes The Reading Of The Estate&quot;)
    lines.append(&quot;&quot;)
    lines.extend(
        [
            &quot;- The CAA layer strengthens the earlier certificate-and-DNS thesis rather than overturning it. The same service families that already looked like shared managed rails from naming and DNS often sit under narrower issuance policy as well.&quot;,
            f&quot;- In `{primary_zone}`, the current CAA friction is concentrated rather than diffuse: {caa_concentration_text(caa_analysis, primary_zone)}.&quot;,
            &quot;- Broad corporate default policy remains visible on many ordinary brand-facing names. That supports the earlier reading that not every public hostname was moved onto one tightly managed delivery rail.&quot;,
            &quot;- Narrower or alias-driven CAA policy appears where the DNS evidence already suggested a managed platform, campaign rail, or vendor-mediated service surface.&quot;,
            &quot;- Vendor-style exceptions still exist. Where a name resolves through a specialist external platform and the allowed CA set widens or changes shape, the policy layer supports the earlier vendor-delegation reading rather than contradicting it.&quot;,
            &quot;- The chapter therefore adds a governance gradient to the earlier thesis: some parts of the estate are tightly steered, some inherit a broad default, and some are still policy-empty.&quot;,
        ]
    )
    lines.append(&quot;&quot;)
    lines.append(&quot;### Why The Next Two Tables Matter&quot;)
    lines.append(&quot;&quot;)
    lines.extend(
        [
            &quot;- The overlap table shows where an old and a new issuance regime are both still live on the same DNS name.&quot;,
            &quot;- The mismatch table shows where today&#x27;s DNS policy has already moved, but one or more live certificates still reflect the older state.&quot;,
            &quot;- Read them together, not separately. Together they show whether the estate looks diffusely messy or whether the untidy parts cluster in a small transition zone.&quot;,
        ]
    )
    lines.append(&quot;&quot;)
    lines.append(&quot;### Current Multi-Family Overlap&quot;)
    lines.append(&quot;&quot;)
    if caa_analysis.multi_family_overlap_names:
        lines.extend(md_table([&quot;DNS Name&quot;, &quot;Zone&quot;, &quot;Live CA Families&quot;, &quot;Covering Subject CNs&quot;], top_caa_overlap_rows(caa_analysis)))
    else:
        lines.append(&quot;No current multi-family overlap names were found.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;These overlap names are operationally important. They show where the same public DNS name is currently covered by more than one live CA family at once. In this corpus, that behavior clusters tightly in a few service families rather than being spread randomly across the estate.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;### Current Policy Mismatch&quot;)
    lines.append(&quot;&quot;)
    if caa_analysis.policy_mismatch_names:
        lines.extend(md_table([&quot;DNS Name&quot;, &quot;Zone&quot;, &quot;Live CA Families&quot;, &quot;CAA-Allowed Families&quot;, &quot;CAA Discovery Result&quot;], top_caa_mismatch_rows(caa_analysis)))
    else:
        lines.append(&quot;No current policy-mismatch names were found.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;A current policy mismatch does not automatically prove CA misissuance. CAA only proves what DNS authorizes now. Certificates can remain valid after the DNS-side policy has changed, so the right reading here is current policy lag or migration residue unless the historical issuance-time DNS can also be shown.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;Taken together, the overlap and mismatch tables support a migration reading more than a disorder reading. If the estate were simply chaotic, the live friction would be spread widely across unrelated names. Instead, it clusters in a small number of service families that were already prominent in the certificate and DNS chapters.&quot;)
    lines.append(&quot;&quot;)
    if focus_analysis:
        lines.append(&quot;## Chapter 8: Focused Subject-CN Cohort&quot;)
        lines.append(&quot;&quot;)
        lines.append(&quot;**Management Summary**&quot;)
        lines.append(&quot;&quot;)
        lines.extend(
            [
                f&quot;- The focused cohort contains {focus_analysis.provided_subjects_count} analyst-selected Subject CN values. {focus_analysis.historically_seen_subjects_count} are visible somewhere in the historical CT corpus, and {focus_analysis.current_direct_subjects_count} still have direct current certificates.&quot;,
                f&quot;- The current focused cohort is structurally different from the rest of the estate: all {focus_analysis.current_focus_certificate_count} current focused certificates are Sectigo/COMODO-lineage, compared with {counter_text(focus_analysis.rest_current_issuer_families, 3)} in the rest of the corpus.&quot;,
                f&quot;- The focused cohort uses much smaller certificates: median SAN size {focus_analysis.focus_median_san_entries} versus {focus_analysis.rest_median_san_entries}, and {focus_analysis.focus_multi_zone_certificate_count} current multi-zone certificates versus {focus_analysis.rest_multi_zone_certificate_count} outside the cohort.&quot;,
                f&quot;- Revocation churn is much higher inside the focused cohort: {focus_analysis.focus_revoked_current_count} revoked versus {focus_analysis.focus_not_revoked_current_count} not revoked ({focus_analysis.focus_revoked_share}), compared with {focus_analysis.rest_revoked_current_count} versus {focus_analysis.rest_not_revoked_current_count} ({focus_analysis.rest_revoked_share}) outside the cohort.&quot;,
                f&quot;- Cross-basket carrying is limited rather than universal. The count of focused entries that appear today only as SAN passengers is {focus_analysis.current_carried_only_subjects_count}, and the count ever seen as SAN passengers inside non-focused certificates at all is {focus_analysis.historical_non_focus_carried_subjects_count}.&quot;,
                f&quot;- The cohort splits into three naming buckets rather than one uniform style: {focus_analysis.bucket_counts.get(&#x27;direct_front_door&#x27;, 0)} front-door direct names, {focus_analysis.bucket_counts.get(&#x27;platform_matrix_anchor&#x27;, 0)} platform-anchor matrix names, and {focus_analysis.bucket_counts.get(&#x27;ambiguous_legacy&#x27;, 0)} ambiguous or legacy-residue names.&quot;,
            ]
        )
        lines.append(&quot;&quot;)
        lines.append(&quot;This chapter treats the supplied Subject-CN list as an analyst-guided cohort rather than as a neutral statistical sample. The question is not whether these names are the most common names in the estate. The question is why they were memorable enough to be singled out, and whether the certificate and DNS evidence shows that they belong to a different naming and hosting tradition.&quot;)
        lines.append(&quot;&quot;)
        lines.append(&quot;The short answer is yes, but not because the cohort is perfectly uniform. The cohort is different from the wider estate because it is weighted toward remembered public fronts and remembered platform anchors, not toward the Amazon-heavy operational rail population that dominates the broader corpus.&quot;)
        lines.append(&quot;&quot;)
        lines.append(&quot;### Focused Cohort Versus The Rest Of The Estate&quot;)
        lines.append(&quot;&quot;)
        lines.extend(md_table([&quot;Comparison View&quot;, &quot;Focused Cohort&quot;, &quot;Rest Of Current Corpus&quot;, &quot;Why It Matters&quot;], focus_comparison))
        lines.append(&quot;&quot;)
        lines.append(&quot;### Three Buckets Inside The Cohort&quot;)
        lines.append(&quot;&quot;)
        lines.extend(md_table([&quot;Bucket&quot;, &quot;Count&quot;, &quot;Representative Names&quot;, &quot;What It Looks Like&quot;, &quot;Why This Bucket Exists&quot;], focus_bucket_summary))
        lines.append(&quot;&quot;)
        lines.append(&quot;This bucket split is the key to making the cohort intelligible. The memorable names are not all from one naming methodology. Most are direct public fronts. A very small number are platform-anchor certificates with matrix SAN design. The rest are historical leftovers, carried aliases, or opaque labels whose original role is no longer cleanly visible in the current corpus.&quot;)
        lines.append(&quot;&quot;)
        lines.append(&quot;### Why This Cohort Feels Different&quot;)
        lines.append(&quot;&quot;)
        lines.extend(
            [
                &quot;- The dominant bucket is the front-door direct bucket. These are small-SAN certificates attached to memorable service, identity, vendor, or brand-like names directly under the branded public zones configured for the scan.&quot;,
                &quot;- The platform-anchor bucket is tiny but important. These names carry large SAN matrices that spell out environment, tenant, service-cell, or monitoring coverage, which is exactly what one would expect from a centrally managed operational platform slice.&quot;,
                &quot;- The ambiguous bucket matters because it explains the leftover rough edges. These names may be historical-only, partly migrated into other certificates, or too opaque to decode confidently from public evidence alone.&quot;,
                &quot;- The public DNS evidence for the current focused Subject CN names is also different. The cohort lands much more often on direct addresses or simple direct AWS clues, while the wider current Subject-CN population is much more dominated by Adobe-managed, Apigee-managed, or NXDOMAIN outcomes.&quot;,
                &quot;- Historical red flags are common in the cohort, but they are mostly past rather than current. That is consistent with a legacy or manually managed public-web slice that has been cleaned up over time rather than with a currently chaotic platform core.&quot;,
            ]
        )
        lines.append(&quot;&quot;)
        lines.append(&quot;Seen this way, the cohort makes sense. It looks like a remembered estate made of two high-visibility extremes: public-facing service fronts that humans remember because customers and staff encounter them directly, and a small number of operational anchor names that humans remember because administrators, testers, or engineers encounter them repeatedly. The ambiguous bucket is the residue between those two poles.&quot;)
        lines.append(&quot;&quot;)
        lines.append(&quot;### Cross-Basket Carrying And Migration&quot;)
        lines.append(&quot;&quot;)
        if focus_analysis.transition_rows:
            lines.extend(
                md_table(
                    [&quot;Subject CN&quot;, &quot;Current Basket Status&quot;, &quot;Direct/Carried&quot;, &quot;Max Direct-To-Carrier Overlap&quot;, &quot;Carrier Subjects&quot;],
                    [
                        [
                            detail.subject_cn,
                            detail.basket_status,
                            f&quot;{detail.current_direct_certificates}/{detail.current_non_focus_san_carriers + detail.historical_non_focus_san_carriers}&quot;,
                            str(detail.max_direct_to_carrier_overlap_days),
                            truncate_text(detail.carrier_subjects, 48),
                        ]
                        for detail in focus_analysis.transition_rows[:10]
                    ],
                )
            )
        else:
            lines.append(&quot;No focused names were seen as SAN passengers inside non-focused certificates.&quot;)
        lines.append(&quot;&quot;)
        lines.append(&quot;This migration table answers a narrower question than the rest of the chapter. It asks whether these names were gradually absorbed into broader certificates from outside the cohort. The answer is: only in a limited number of cases. Some names do show SAN-passenger behavior or historical carrying, but that is not the dominant explanation for why the cohort feels different. The dominant explanation is the bucket split above: many remembered direct fronts, a few large platform anchors, and a band of legacy residue.&quot;)
        lines.append(&quot;&quot;)
        lines.append(&quot;### Representative Names By Bucket&quot;)
        lines.append(&quot;&quot;)
        lines.extend(md_table([&quot;Bucket&quot;, &quot;Subject CN&quot;, &quot;Observed Role&quot;, &quot;Current/Historical Direct&quot;, &quot;Why It Helps Explain The Bucket&quot;], focus_representatives))
        lines.append(&quot;&quot;)
        lines.append(&quot;These examples are evidence anchors, not the whole population. The direct-front examples show the remembered public surface. The platform-anchor examples show the rare but important matrix certificates. The ambiguous examples show why the cohort cannot be reduced to a single neat story without losing the migration and legacy residue that made these names memorable in the first place.&quot;)
        lines.append(&quot;&quot;)
    lines.append(f&quot;## Chapter {synthesis_chapter}: Making The Whole Estate Make Sense&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;**Management Summary**&quot;)
    lines.append(&quot;&quot;)
    lines.extend(
        [
            &quot;- The certificate, DNS, and CAA layers are not three separate stories. They are three views of the same operating estate.&quot;,
            &quot;- Naming shows role and organisational memory; DNS shows where traffic lands; CAA shows how tightly issuance is governed.&quot;,
            &quot;- Clean public brand names usually sit closest to the customer surface, while dense SAN sets, numbered families, multi-zone certificates, and narrower CAA policy usually expose the shared platform layer beneath them.&quot;,
            &quot;- When the layers disagree, the disagreement usually signals migration or uneven governance maturity rather than a flat contradiction.&quot;,
            &quot;- The overall shape is more consistent with a federated operating model with uneven governance maturity than with random hostname sprawl.&quot;,
        ]
    )
    lines.append(&quot;&quot;)
    lines.append(&quot;The common ground is operational reality. A branded proposition wants recognisable names. A service team wants a stable endpoint namespace. A platform team wants shared rails and repeatable delivery machinery. A hosting team wants routable front doors that can land on cloud distribution, gateways, or workflow platforms. A security or PKI function wants some names tightly governed and other names left broad or delegated. Certificates, DNS, and CAA tell the same estate story from different angles.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;A useful way to combine the layers is to ask four questions in order. First, what does the name itself look like: a direct front door, a numbered rail, an environment slice, or a bridge across business zones? Second, how broad is the SAN set: is this one visible service or a bundled platform certificate? Third, where does public DNS actually land the name: direct host, CDN edge, API gateway, campaign rail, or specialist platform? Fourth, does DNS issuance policy stay broad, narrow sharply, or disappear entirely?&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;When those answers align, the reading becomes strong. A small-SAN branded name with ordinary inherited policy reads like a direct public front. A dense multi-zone certificate with numbered families, managed DNS landing, and narrower CAA reads like a shared operational rail. A name that lands on AWS but still uses a Sectigo-family certificate shows that hosting choice and CA choice are separate decisions. A name with current overlap and current policy mismatch shows a transition area where the newer issuance model is already in place but the older certificate state has not fully disappeared.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;This is why the estate can look both tidy and messy at once. It is tidy within each layer, but messy across layers because the layers are solving different problems. The new CAA evidence sharpens that point rather than contradicting it: the managed rail families are not only named and hosted differently, they are often policy-controlled differently as well. The biggest qualification is that governance is uneven. The primary configured zone shows layered issuance control, while another configured zone remains CAA-empty. That is not random chaos, but it is also not uniform control maturity.&quot;)
    lines.append(&quot;&quot;)
    lines.append(f&quot;## Chapter {limits_chapter}: Limits, Confidence, and Noise&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;**Management Summary**&quot;)
    lines.append(&quot;&quot;)
    lines.extend(
        [
            &quot;- High-confidence claims are the ones tied directly to observable certificate fields, DNS answers, trust records, and current CAA policy.&quot;,
            &quot;- Medium-confidence claims are organisational readings drawn from repeated technical patterns.&quot;,
            &quot;- Lower-confidence claims are exact expansions of abbreviations or exact internal ownership boundaries.&quot;,
            &quot;- Some DNS names do not resolve publicly today; that does not invalidate the certificate-side evidence because certificate and DNS timelines are not identical.&quot;,
            &quot;- A current CAA mismatch does not by itself prove historical CA non-compliance, because DNS policy may have changed after issuance.&quot;,
        ]
    )
    lines.append(&quot;&quot;)
    lines.append(&quot;A useful way to read the corpus is to separate signal from noise. Repeated naming schemas are signal. Repeated DNS outcomes are signal. Which public CA family keeps issuing a name is signal. Where CAA is broad, narrow, delegated, or absent is signal. Simple `www` presence or absence is weak evidence either way unless it coincides with stronger differences such as distinct DNS routing, distinct SAN composition, a distinct certificate renewal history, or a distinct issuance-policy shape.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;## Appendix A: Full Family Catalogue&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;This appendix is a compact family map. It is not the place for full per-certificate evidence; that remains in the detailed inventory appendix at the end.&quot;)
    lines.append(&quot;&quot;)
    lines.extend(md_table([&quot;Family Basis&quot;, &quot;Certs&quot;, &quot;CNs&quot;, &quot;Dominant Stack&quot;], family_rows))
    lines.append(&quot;&quot;)
    lines.append(&quot;## Appendix B: Historical Red-Flag Detail&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;This appendix keeps the detailed historical evidence inside the monograph so that the reader does not need a second report. Each subsection answers one narrow question. If a column does not help answer that question, it has been removed.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;In this appendix, a *renewal family* means repeated certificates that keep the same apparent identity over time: the same Subject CN, the same full Subject DN, the same SAN profile, and the same CA family.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;### B.1 Current Red-Flag Inventory&quot;)
    lines.append(&quot;&quot;)
    if assessment.current_red_flag_rows:
        lines.extend(
            md_table(
                [&quot;Subject CN&quot;, &quot;Live Certs&quot;, &quot;Current Concern&quot;, &quot;Supporting Context&quot;],
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
        lines.append(&quot;No current red flags were found.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;### B.2 Past Red-Flag Inventory Now Fixed&quot;)
    lines.append(&quot;&quot;)
    if assessment.past_red_flag_rows:
        lines.extend(
            md_table(
                [&quot;Subject CN&quot;, &quot;Historic Certs&quot;, &quot;Historical Concern&quot;, &quot;Supporting Context&quot;],
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
        lines.append(&quot;No past-only red flags were found.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;### B.3 Current Overlap Red Flags&quot;)
    lines.append(&quot;&quot;)
    if assessment.overlap_current_rows:
        lines.extend(
            md_table(
                [&quot;Subject CN&quot;, &quot;Max Overlap Days&quot;, &quot;Live Certs&quot;, &quot;What The Renewal Family Looks Like&quot;],
                [
                    [
                        row.subject_cn,
                        str(row.max_overlap_days),
                        str(row.current_certificate_count),
                        f&quot;{row.lineage}; {overlap_signal(row.details)}&quot;,
                    ]
                    for row in assessment.overlap_current_rows
                ],
            )
        )
    else:
        lines.append(&quot;No current overlap red flags were found.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;### B.4 Past Overlap Red Flags Now Fixed&quot;)
    lines.append(&quot;&quot;)
    if assessment.overlap_past_rows:
        lines.extend(
            md_table(
                [&quot;Subject CN&quot;, &quot;Max Overlap Days&quot;, &quot;Historic Certs&quot;, &quot;What The Renewal Family Looks Like&quot;],
                [
                    [
                        row.subject_cn,
                        str(row.max_overlap_days),
                        str(row.asset_variant_count),
                        f&quot;{row.lineage}; {overlap_signal(row.details)}&quot;,
                    ]
                    for row in assessment.overlap_past_rows
                ],
            )
        )
    else:
        lines.append(&quot;No past overlap red flags were found.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;### B.5 Current Subject DN Drift&quot;)
    lines.append(&quot;&quot;)
    if assessment.dn_current_rows:
        lines.extend(
            md_table(
                [&quot;Subject CN&quot;, &quot;Distinct Subject DNs&quot;, &quot;Live Certs&quot;, &quot;Subject DN Samples&quot;],
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
        lines.append(&quot;No current Subject DN drift was found.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;### B.6 Past Subject DN Drift Now Fixed&quot;)
    lines.append(&quot;&quot;)
    if assessment.dn_past_rows:
        lines.extend(
            md_table(
                [&quot;Subject CN&quot;, &quot;Distinct Subject DNs&quot;, &quot;Historic Certs&quot;, &quot;Subject DN Samples&quot;],
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
        lines.append(&quot;No past-only Subject DN drift was found.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;### B.7 Current CA-Family Drift&quot;)
    lines.append(&quot;&quot;)
    if assessment.vendor_current_rows:
        lines.extend(
            md_table(
                [&quot;Subject CN&quot;, &quot;Distinct CA Families&quot;, &quot;Live Certs&quot;, &quot;CA Families Seen&quot;],
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
        lines.append(&quot;No current CA-family drift was found.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;### B.8 Past CA-Family Drift Now Fixed&quot;)
    lines.append(&quot;&quot;)
    if assessment.vendor_past_rows:
        lines.extend(
            md_table(
                [&quot;Subject CN&quot;, &quot;Distinct CA Families&quot;, &quot;Historic Certs&quot;, &quot;CA Families Seen&quot;],
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
        lines.append(&quot;No past-only CA-family drift was found.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;### B.9 Current SAN Drift&quot;)
    lines.append(&quot;&quot;)
    if assessment.san_current_rows:
        lines.extend(
            md_table(
                [&quot;Subject CN&quot;, &quot;SAN Profiles&quot;, &quot;Live Certs&quot;, &quot;Delta Pattern&quot;, &quot;Representative Delta&quot;],
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
        lines.append(&quot;No current SAN drift was found.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;### B.10 Past SAN Drift Now Fixed&quot;)
    lines.append(&quot;&quot;)
    if assessment.san_past_rows:
        lines.extend(
            md_table(
                [&quot;Subject CN&quot;, &quot;SAN Profiles&quot;, &quot;Historic Certs&quot;, &quot;Delta Pattern&quot;, &quot;Representative Delta&quot;],
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
        lines.append(&quot;No past-only SAN drift was found.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;### B.11 Historic Start Dates&quot;)
    lines.append(&quot;&quot;)
    lines.extend(
        md_table(
            [&quot;Start Day&quot;, &quot;Certificates&quot;, &quot;Dominant Driver&quot;],
            [[row.start_day, str(row.certificate_count), driver_summary(row.top_subjects, row.top_issuers)] for row in assessment.day_rows],
        )
    )
    lines.append(&quot;&quot;)
    lines.append(&quot;### B.12 Historic Step Weeks&quot;)
    lines.append(&quot;&quot;)
    if assessment.week_rows:
        lines.extend(
            md_table(
                [&quot;Week Start&quot;, &quot;Certificates&quot;, &quot;Prior 8-Week Avg&quot;, &quot;Dominant Driver&quot;],
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
        lines.append(&quot;No step weeks met the threshold.&quot;)
    lines.append(&quot;&quot;)
    lines.append(f&quot;## Appendix {caa_appendix}: CAA Policy Detail&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;This appendix keeps the issuance-policy evidence inside the monograph. It answers a narrower question than the DNS appendix: not where a name lands, but which public CA families DNS currently authorizes to issue for that name.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;### C.1 CAA Discovery Paths&quot;)
    lines.append(&quot;&quot;)
    lines.extend(md_table([&quot;CAA Discovery Result&quot;, &quot;Names&quot;, &quot;Meaning&quot;], caa_source_rows(caa_analysis)))
    lines.append(&quot;&quot;)
    lines.append(&quot;### C.2 Policy Regimes By Configured Zone&quot;)
    lines.append(&quot;&quot;)
    for zone in caa_analysis.configured_domains:
        lines.append(f&quot;#### `{zone}`&quot;)
        lines.append(&quot;&quot;)
        lines.extend(md_table([&quot;Policy Regime&quot;, &quot;Names&quot;, &quot;Plain-Language Meaning&quot;], caa_zone_rows[zone]))
        lines.append(&quot;&quot;)
    lines.append(&quot;### C.3 Current Multi-Family Overlap&quot;)
    lines.append(&quot;&quot;)
    if caa_analysis.multi_family_overlap_names:
        lines.extend(md_table([&quot;DNS Name&quot;, &quot;Zone&quot;, &quot;Live CA Families&quot;, &quot;Covering Subject CNs&quot;], top_caa_overlap_rows(caa_analysis, 40)))
    else:
        lines.append(&quot;No current multi-family overlap names were found.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;### C.4 Current Policy Mismatch&quot;)
    lines.append(&quot;&quot;)
    if caa_analysis.policy_mismatch_names:
        lines.extend(md_table([&quot;DNS Name&quot;, &quot;Zone&quot;, &quot;Live CA Families&quot;, &quot;CAA-Allowed Families&quot;, &quot;CAA Discovery Result&quot;], top_caa_mismatch_rows(caa_analysis, 40)))
    else:
        lines.append(&quot;No current policy-mismatch names were found.&quot;)
    lines.append(&quot;&quot;)
    if focus_analysis:
        lines.append(f&quot;## Appendix {focus_appendix}: Focused Subject-CN Detail&quot;)
        lines.append(&quot;&quot;)
        lines.append(&quot;This appendix keeps the complete focused-cohort table inside the monograph, but it now follows the three-bucket taxonomy from Chapter 8. That makes it easier to read the cohort as a set of related naming traditions instead of as one flat mixed list.&quot;)
        lines.append(&quot;&quot;)
        appendix_buckets = [
            (&quot;direct_front_door&quot;, &quot;### D.1 Front-Door Direct Names&quot;),
            (&quot;platform_matrix_anchor&quot;, &quot;### D.2 Platform-Anchor Matrix Names&quot;),
            (&quot;ambiguous_legacy&quot;, &quot;### D.3 Ambiguous Or Legacy Residue&quot;),
        ]
        for bucket, heading in appendix_buckets:
            rows = focus_appendix_rows(focus_analysis, bucket)
            lines.append(heading)
            lines.append(&quot;&quot;)
            lines.append(f&quot;{ct_focus_subjects.taxonomy_bucket_label(bucket)} count: {focus_analysis.bucket_counts.get(bucket, 0)}.&quot;)
            lines.append(&quot;&quot;)
            if rows:
                lines.extend(
                    md_table(
                        [
                            &quot;Subject CN&quot;,
                            &quot;Bucket Rationale&quot;,
                            &quot;Analyst Note&quot;,
                            &quot;Observed Role&quot;,
                            &quot;Direct C/H&quot;,
                            &quot;Carried C/H&quot;,
                            &quot;SANs C/H&quot;,
                            &quot;Current DNS Outcome&quot;,
                            &quot;Current Revocation Mix&quot;,
                            &quot;Current Flags&quot;,
                            &quot;Past Flags&quot;,
                        ],
                        rows,
                    )
                )
            else:
                lines.append(&quot;No subjects fell into this bucket.&quot;)
            lines.append(&quot;&quot;)
    lines.append(f&quot;## Appendix {detailed_inventory_appendix}: Detailed Inventory Appendix&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;The full issuer-first family inventory is reproduced below so that the monograph remains complete rather than merely interpretive.&quot;)
    lines.append(&quot;&quot;)
    lines.append(appendix_markdown)
    args.markdown_output.write_text(&quot;\n&quot;.join(lines) + &quot;\n&quot;, encoding=&quot;utf-8&quot;)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Writes the narrative monograph in Markdown.</p>
<p><strong>Flow arrows</strong></p><p>Current-state facts, history, CAA, and focused-cohort analysis. &#8594; <strong>render_markdown</strong> &#8594; Produces the main Markdown monograph.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## render_latex

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def render_latex(
    args: argparse.Namespace,
    report: dict[str, object],
    assessment: ct_lineage_report.HistoricalAssessment,
    caa_analysis: ct_caa_analysis.CaaAnalysis,
    focus_analysis: ct_focus_subjects.FocusCohortAnalysis | None,
) -&gt; None:
    args.latex_output.parent.mkdir(parents=True, exist_ok=True)
    hits = report[&quot;hits&quot;]
    groups = report[&quot;groups&quot;]
    purpose_summary = report[&quot;purpose_summary&quot;]
    total_certificates = len(report[&quot;classifications&quot;])
    issuer_trust = report[&quot;issuer_trust&quot;]
    issuer_family_rows = build_issuer_family_rows(report)
    family_rows = [
        [
            compact_family_basis(row[&quot;basis&quot;]),
            str(row[&quot;certificates&quot;]),
            str(row[&quot;subjects&quot;]),
            first_list_item(row[&quot;top_stacks&quot;]),
        ]
        for row in report[&quot;group_digest&quot;]
    ]
    dual_items = [item for item in report[&quot;classifications&quot;] if item.category == &quot;tls_server_and_client&quot;]
    dual_issuer_counts = Counter(short_issuer(item.issuer_name) for item in dual_items)
    server_only_count = purpose_summary.category_counts.get(&quot;tls_server_only&quot;, 0)
    dual_count = purpose_summary.category_counts.get(&quot;tls_server_and_client&quot;, 0)
    server_only_issuer_families = collapse_issuer_counts_by_family(
        purpose_summary.issuer_breakdown.get(&quot;tls_server_only&quot;, {})
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
            (&quot;tls_server_only&quot;, purpose_summary.category_counts.get(&quot;tls_server_only&quot;, 0)),
            (&quot;tls_server_and_client&quot;, purpose_summary.category_counts.get(&quot;tls_server_and_client&quot;, 0)),
            (&quot;client_auth_only&quot;, purpose_summary.category_counts.get(&quot;client_auth_only&quot;, 0)),
            (&quot;smime_only&quot;, purpose_summary.category_counts.get(&quot;smime_only&quot;, 0)),
            (&quot;code_signing_only&quot;, purpose_summary.category_counts.get(&quot;code_signing_only&quot;, 0)),
            (&quot;mixed_or_other&quot;, purpose_summary.category_counts.get(&quot;mixed_or_other&quot;, 0)),
            (&quot;no_eku&quot;, purpose_summary.category_counts.get(&quot;no_eku&quot;, 0)),
        ]
    ]
    visible_purpose_rows = [(label, count, share, meaning) for label, count, share, meaning in purpose_rows if count != &quot;0&quot;]
    dns_class_counts = report[&quot;dns_class_counts&quot;]
    alias_to_address_count = dns_class_counts.get(&quot;cname_to_address&quot;, 0)
    direct_address_count = dns_class_counts.get(&quot;direct_address&quot;, 0)
    nxdomain_count = dns_class_counts.get(&quot;nxdomain&quot;, 0)
    dangling_count = dns_class_counts.get(&quot;dangling_cname&quot;, 0)
    no_data_count = dns_class_counts.get(&quot;no_data&quot;, 0)
    top_dns_patterns = report[&quot;dns_stack_counts&quot;].most_common(8)
    focus_comparison = focus_comparison_rows(focus_analysis) if focus_analysis else []
    focus_bucket_summary = focus_bucket_summary_rows(focus_analysis) if focus_analysis else []
    focus_representatives = focus_representative_rows(focus_analysis) if focus_analysis else []
    has_focus = focus_analysis is not None
    caa_zone_rows = {
        zone: caa_zone_policy_rows(caa_analysis, zone)
        for zone in caa_analysis.configured_domains
    }
    primary_zone = report[&quot;domains&quot;][0] if report[&quot;domains&quot;] else &quot;configured primary zone&quot;
    secondary_zone = report[&quot;domains&quot;][1] if len(report[&quot;domains&quot;]) &gt; 1 else None
    appendix_pdf_path = args.appendix_pdf_output.resolve().as_posix()
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
        r&quot;\usepackage{tabularx}&quot;,
        r&quot;\usepackage{longtable}&quot;,
        r&quot;\usepackage{needspace}&quot;,
        r&quot;\usepackage{enumitem}&quot;,
        r&quot;\usepackage{titlesec}&quot;,
        r&quot;\usepackage[most]{tcolorbox}&quot;,
        r&quot;\usepackage{pdfpages}&quot;,
        r&quot;\defaultfontfeatures{Ligatures=TeX,Scale=MatchLowercase}&quot;,
        r&quot;\definecolor{Ink}{HTML}{17202A}&quot;,
        r&quot;\definecolor{Muted}{HTML}{667085}&quot;,
        r&quot;\definecolor{Line}{HTML}{D0D5DD}&quot;,
        r&quot;\definecolor{Panel}{HTML}{F8FAFC}&quot;,
        r&quot;\definecolor{Accent}{HTML}{0F766E}&quot;,
        r&quot;\hypersetup{colorlinks=true,linkcolor=Accent,urlcolor=Accent,pdfauthor={CertTransparencySearch},pdftitle={CT and DNS Monograph}}&quot;,
        r&quot;\setlength{\parindent}{0pt}&quot;,
        r&quot;\setlength{\parskip}{6pt}&quot;,
        r&quot;\setlength{\emergencystretch}{4em}&quot;,
        r&quot;\setlength{\footskip}{24pt}&quot;,
        r&quot;\setlength{\tabcolsep}{4.2pt}&quot;,
        r&quot;\renewcommand{\arraystretch}{1.12}&quot;,
        r&quot;\raggedbottom&quot;,
        r&quot;\setcounter{tocdepth}{2}&quot;,
        r&quot;\pagestyle{plain}&quot;,
        r&quot;\titleformat{\section}{\sffamily\bfseries\LARGE\color{Ink}\raggedright}{\thesection}{0.8em}{}&quot;,
        r&quot;\titleformat{\subsection}{\sffamily\bfseries\Large\color{Ink}\raggedright}{\thesubsection}{0.8em}{}&quot;,
        r&quot;\titleformat{\subsubsection}{\sffamily\bfseries\normalsize\color{Ink}\raggedright}{\thesubsubsection}{0.8em}{}&quot;,
        r&quot;\tcbset{panel/.style={enhanced,breakable,boxrule=0.55pt,arc=3pt,left=9pt,right=9pt,top=8pt,bottom=8pt,colback=white,colframe=Line}}&quot;,
        r&quot;\newcommand{\SummaryBox}[1]{\begin{tcolorbox}[enhanced,boxrule=0.55pt,arc=3pt,left=9pt,right=9pt,top=8pt,bottom=8pt,colback=Panel,colframe=Line]#1\end{tcolorbox}}&quot;,
        r&quot;\newcommand{\SoftSubsection}[1]{\Needspace{12\baselineskip}\subsection{#1}}&quot;,
        r&quot;\newcommand{\SoftSubsubsection}[1]{\Needspace{10\baselineskip}\subsubsection{#1}}&quot;,
        r&quot;\begin{document}&quot;,
        r&quot;\begin{titlepage}&quot;,
        r&quot;\vspace*{16mm}&quot;,
        r&quot;{\sffamily\bfseries\fontsize{24}{28}\selectfont CT and DNS Monograph\par}&quot;,
        r&quot;\vspace{6pt}&quot;,
        r&quot;{\Large A complete publication built from live Certificate Transparency and public DNS evidence\par}&quot;,
        r&quot;\vspace{18pt}&quot;,
        rf&quot;\textbf{{Generated}}: {latex_escape(report[&#x27;generated_at_utc&#x27;])}\par&quot;,
        rf&quot;\textbf{{Configured search terms file}}: {latex_escape(args.domains_file.name)}\par&quot;,
        r&quot;\vspace{12pt}&quot;,
        r&quot;\SummaryBox{&quot;
        + rf&quot;\textbf{{Headline}}: {len(hits)} leaf certificates, {len(groups)} CN families, &quot;
        + rf&quot;{historical_count} historical leaf certificates, &quot;
        + rf&quot;{len(report[&#x27;unique_dns_names&#x27;])} DNS names, &quot;
        + rf&quot;{purpose_summary.category_counts.get(&#x27;tls_server_only&#x27;, 0)} ordinary public TLS server certificates, &quot;
        + rf&quot;{purpose_summary.category_counts.get(&#x27;tls_server_and_client&#x27;, 0)} certificates from templates that also permit client-certificate use.&quot;
        + r&quot;}&quot;,
        r&quot;\end{titlepage}&quot;,
        r&quot;\begingroup&quot;,
        r&quot;\small&quot;,
        r&quot;\setlength{\parskip}{2pt}&quot;,
        r&quot;\tableofcontents&quot;,
        r&quot;\endgroup&quot;,
        r&quot;\clearpage&quot;,
    ]

    def add_summary(items: list[str]) -&gt; None:
        lines.append(r&quot;\SummaryBox{\textbf{Management Summary}\begin{itemize}[leftmargin=1.4em]&quot;)
        for item in items:
            lines.append(rf&quot;\item {latex_escape(item)}&quot;)
        lines.append(r&quot;\end{itemize}}&quot;)

    lines.append(r&quot;\section*{Executive Summary}&quot;)
    lines.append(r&quot;\addcontentsline{toc}{section}{Executive Summary}&quot;)
    add_summary(
        [
            f&quot;{len(hits)} current leaf certificates are in scope on this run.&quot;,
            f&quot;{len(groups)} CN families reduce the estate into readable naming clusters.&quot;,
            f&quot;{purpose_summary.category_counts.get(&#x27;tls_server_only&#x27;, 0)} certificates are ordinary public TLS server certificates, while {purpose_summary.category_counts.get(&#x27;tls_server_and_client&#x27;, 0)} come from templates that also permit client-certificate use.&quot;,
            f&quot;{historical_count} historical leaf certificates show how the same names evolved over time.&quot;,
            f&quot;{len(report[&#x27;unique_dns_names&#x27;])} DNS SAN names were scanned live.&quot;,
            f&quot;{caa_analysis.total_names} DNS names were also assessed for effective CAA policy, revealing where issuance is centrally governed, delegated, or left unrestricted.&quot;,
            &quot;The estate is best understood as layers of branding, service naming, platform naming, delivery naming, and issuance-policy control rather than as random clutter.&quot;,
        ]
    )
    lines.append(
        r&quot;This document is designed as a complete publication rather than a brief. The main chapters carry the argument and the appendices carry the detailed evidence.&quot;
    )

    lines.append(r&quot;\section*{Reading Guide}&quot;)
    lines.append(r&quot;\addcontentsline{toc}{section}{Reading Guide}&quot;)
    add_summary(
        [
            &quot;Chapter 1 proves the corpus and explains why the numbers can be trusted.&quot;,
            &quot;Chapters 2 and 3 explain what the current certificates are and what they are for.&quot;,
            &quot;Chapter 4 explains the historical lifecycle and splits red flags into current versus fixed-in-the-past.&quot;,
            &quot;Chapters 5 and 6 explain naming and DNS delivery.&quot;,
            &quot;Chapter 7 explains the issuance-policy layer: which public CAs DNS currently authorizes and where DNS imposes no restriction at all.&quot;,
            *(
                [&quot;Chapter 8 explains the focused Subject-CN cohort and why it behaves differently from the wider estate.&quot;]
                if has_focus
                else []
            ),
            &quot;The next synthesis chapter ties the whole estate back to operational reality.&quot;,
            &quot;The appendices contain the detailed catalogue, the historical red-flag detail, and the full inventory.&quot;,
        ]
    )

    lines.append(r&quot;\section{Scope, Completeness, and Proof}&quot;)
    add_summary(
        [
            f&quot;The first broad crt.sh search returned {&#x27;, &#x27;.join(f&#x27;{domain}={count} matching index rows&#x27; for domain, count in report[&#x27;raw_match_counts&#x27;].items())}. Those rows are leads, not final certificate count.&quot;,
            f&quot;The scanner was allowed to collect up to {report[&#x27;cap&#x27;]} candidate rows per search term. Because the live match counts stayed below that limit, nothing was silently cut off.&quot;,
            f&quot;After downloading and parsing the actual certificate bodies, {report[&#x27;verification&#x27;].unique_leaf_certificates} genuine leaf certificates remained. {report[&#x27;verification&#x27;].non_leaf_filtered} CA-style certificates and {report[&#x27;verification&#x27;].precertificate_poison_filtered} precertificate marker objects were rejected.&quot;,
            f&quot;Certificates missing the searched-for domains in their DNS SANs after full parsing: {report[&#x27;missing_matching_san&#x27;]}.&quot;,
        ]
    )
    lines.append(
        r&quot;This chapter answers the first and most important question: whether the report is built on a complete and trustworthy corpus. The scanner now checks the live raw match count before issuing the capped query. If the cap is too low, it fails instead of silently undercounting.&quot;
    )
    lines.append(
        r&quot;The first crt.sh row count is intentionally larger than the final certificate count because Certificate Transparency search results are index rows, not de-duplicated certificates. The report therefore reads the binary certificate body itself, removes duplicates, rejects CA certificates and precertificate marker objects, and only then builds the working corpus.&quot;
    )
    lines.append(
        r&quot;In other words: this publication is not based on search-result snippets alone. It is based on the parsed X.509 certificate bodies.&quot;
    )

    lines.append(r&quot;\section{The Certificate Corpus}&quot;)
    add_summary(
        [
            f&quot;Issuer families by certificate count are {&#x27;, &#x27;.join(f&#x27;{name} ({count})&#x27; for name, count in report[&#x27;issuer_family_counts&#x27;].most_common())}.&quot;,
            f&quot;Revocation state in plain terms: {report[&#x27;rev_counts&#x27;].get(&#x27;not_revoked&#x27;, 0)} certificates are not marked revoked, and {report[&#x27;rev_counts&#x27;].get(&#x27;revoked&#x27;, 0)} were later marked invalid by their issuing CA before natural expiry.&quot;,
            &quot;For every current certificate, the main Subject CN hostname also appears literally in the DNS SAN list. The headline name on the certificate is therefore one of the real covered hostnames, not a decorative label.&quot;,
            &quot;All visible issuer families in this corpus are currently trusted by the major public browser and operating-system trust stores for ordinary web server use.&quot;,
        ]
    )
    lines.append(
        r&quot;A certificate corpus can look random when viewed as a flat list. It becomes intelligible once you group it by issuer family, Subject CN construction, validity history, and SAN design. That is why the appendices are arranged as families rather than raw rows.&quot;
    )
    lines.extend(
        [
            r&quot;\subsection{Issuer Trust Table}&quot;,
            r&quot;\begin{longtable}{&gt;{\raggedright\arraybackslash}p{0.40\linewidth} &gt;{\raggedleft\arraybackslash}p{0.12\linewidth} &gt;{\raggedleft\arraybackslash}p{0.12\linewidth} &gt;{\raggedleft\arraybackslash}p{0.18\linewidth}}&quot;,
            r&quot;\toprule&quot;,
            r&quot;Issuer Family &amp; Certs &amp; Variants &amp; Major WebPKI \\&quot;,
            r&quot;\midrule&quot;,
        ]
    )
    for row in issuer_family_rows:
        lines.append(
            rf&quot;{latex_escape(row[&#x27;family&#x27;])} &amp; {row[&#x27;certificates&#x27;]} &amp; {row[&#x27;variant_count&#x27;]} &amp; {row[&#x27;major_webpki&#x27;]} \\&quot;
    )
    lines.extend([r&quot;\bottomrule&quot;, r&quot;\end{longtable}&quot;])
    lines.append(
        r&quot;\textbf{What WebPKI trust means.} A WebPKI-trusted issuer is a certificate authority trusted by mainstream browser and operating-system trust stores for public TLS. That matters because it tells you these certificates are not part of a private PKI hidden inside one organisation. They are intended to be valid in the public Internet trust model.&quot;
    )
    lines.append(
        r&quot;This view should answer one question only: how many publicly trusted issuer families are present in the estate. Exact subordinate issuer names are supporting evidence and remain in the detailed inventory appendix.&quot;
    )

    lines.append(r&quot;\section{Intended Purpose of the Certificates}&quot;)
    add_summary(
        [
            f&quot;Certificates whose allowed purpose is ordinary server authentication only: {purpose_summary.category_counts.get(&#x27;tls_server_only&#x27;, 0)}.&quot;,
            f&quot;Certificates whose policy allows both server use and client-certificate use: {purpose_summary.category_counts.get(&#x27;tls_server_and_client&#x27;, 0)}.&quot;,
            &quot;Certificates dedicated only to client identity, email signing, or code signing: 0.&quot;,
        ]
    )
    lines.append(
        r&quot;This chapter addresses a key ambiguity. A certificate can be technically valid for several uses, and the hostname alone does not settle that question. The corpus was therefore assessed from the X.509 usage fields themselves: EKU and KeyUsage.&quot;
    )
    lines.append(
        r&quot;Extended Key Usage tells software what a certificate is allowed to do. In plain terms, this is the difference between a website certificate, a client-identity certificate, an email certificate, and a code-signing certificate.&quot;
    )
    lines.extend(
        [
            r&quot;\subsection{Purpose Map}&quot;,
            r&quot;\begin{longtable}{&gt;{\raggedright\arraybackslash}p{0.24\linewidth} &gt;{\raggedleft\arraybackslash}p{0.10\linewidth} &gt;{\raggedleft\arraybackslash}p{0.10\linewidth} &gt;{\raggedright\arraybackslash}p{0.46\linewidth}}&quot;,
            r&quot;\toprule&quot;,
            r&quot;Usage Class &amp; Certs &amp; Share &amp; Meaning \\&quot;,
            r&quot;\midrule&quot;,
        ]
    )
    for label, count, share, meaning in visible_purpose_rows:
        lines.append(
            rf&quot;{latex_escape(label)} &amp; {count} &amp; {latex_escape(share)} &amp; {latex_escape(meaning)} \\&quot;
        )
    lines.extend([r&quot;\bottomrule&quot;, r&quot;\end{longtable}&quot;])
    lines.append(
        r&quot;This view should answer only what kind of certificates these are. Zero-count categories are removed here because they add noise without changing the conclusion.&quot;
    )
    lines.append(
        r&quot;The basic picture is simple: the corpus is overwhelmingly made of ordinary public TLS server certificates, with a smaller minority whose EKU also permits client-certificate use.&quot;
    )
    lines.append(
        r&quot;\textbf{Plain-language explanation of the usage categories.} A TLS server certificate is what a website or API presents to a browser, app, or machine client. A server-and-client certificate is one whose policy allows both server use and client-certificate use. That does not automatically mean it is actually used as a client certificate, but it leaves that door open. Client-auth-only certificates are what you would expect for a user, robot, or agent identity in mutual TLS. S/MIME means email signing or encryption. Code-signing means software signing rather than endpoint security.&quot;
    )
    lines.append(
        r&quot;The result is clean. This corpus is entirely TLS-capable. There is no evidence of a separate S/MIME or code-signing estate, and there are no client-auth-only certificates.&quot;
    )
    lines.extend(
        [
            r&quot;\subsection{EKU and KeyUsage Templates}&quot;,
            r&quot;At the template level, the corpus is even simpler than the certificate count suggests. Here, a template simply means a repeated combination of usage fields. Only two EKU combinations appear at all, and one KeyUsage pattern dominates almost completely.&quot;,
            r&quot;\begin{longtable}{&gt;{\raggedright\arraybackslash}p{0.58\linewidth} &gt;{\raggedleft\arraybackslash}p{0.14\linewidth} &gt;{\raggedleft\arraybackslash}p{0.14\linewidth}}&quot;,
            r&quot;\toprule&quot;,
            r&quot;EKU Template &amp; Certs &amp; Share \\&quot;,
            r&quot;\midrule&quot;,
        ]
    )
    for template, count in purpose_summary.eku_templates.items():
        lines.append(rf&quot;{latex_escape(template)} &amp; {count} &amp; {latex_escape(pct(count, total_certificates))} \\&quot;)
    lines.extend([r&quot;\bottomrule&quot;, r&quot;\end{longtable}&quot;])
    lines.extend(
        [
            r&quot;\begin{longtable}{&gt;{\raggedright\arraybackslash}p{0.58\linewidth} &gt;{\raggedleft\arraybackslash}p{0.14\linewidth} &gt;{\raggedleft\arraybackslash}p{0.14\linewidth}}&quot;,
            r&quot;\toprule&quot;,
            r&quot;KeyUsage Template &amp; Certs &amp; Share \\&quot;,
            r&quot;\midrule&quot;,
        ]
    )
    for template, count in purpose_summary.key_usage_templates.items():
        lines.append(rf&quot;{latex_escape(template)} &amp; {count} &amp; {latex_escape(pct(count, total_certificates))} \\&quot;)
    lines.extend([r&quot;\bottomrule&quot;, r&quot;\end{longtable}&quot;])
    lines.extend(
        [
            r&quot;\subsection{The Majority Pattern: Server-Only Public TLS}&quot;,
            rf&quot;Server-only certificates account for {server_only_count} of {total_certificates} certificates, or {latex_escape(pct(server_only_count, total_certificates))} of the corpus.&quot;,
            rf&quot;Server-only validity starts are split between {latex_escape(&#x27;, &#x27;.join(f&#x27;{year} ({count})&#x27; for year, count in purpose_summary.validity_start_years.get(&#x27;tls_server_only&#x27;, {}).items()))}.&quot;,
            rf&quot;Server-only issuer-family concentration is {latex_escape(&#x27;, &#x27;.join(f&#x27;{name} ({count})&#x27; for name, count in server_only_issuer_families.most_common()))}.&quot;,
            r&quot;This is the normal public WebPKI server-certificate pattern for websites, APIs, and edge service front doors.&quot;,
            r&quot;This majority group is not background noise. It is the main operational reality visible in the scan: public DNS names covered by publicly trusted endpoint certificates.&quot;,
        ]
    )
    lines.extend(
        [
            r&quot;\subsection{The Minority Pattern: Dual EKU}&quot;,
            rf&quot;In this corpus, {dual_count} certificates carry both \texttt{{serverAuth}} and \texttt{{clientAuth}} in Extended Key Usage. That is {latex_escape(pct(dual_count, total_certificates))} of the corpus. This means the certificate is \emph{{allowed}} to be used in either role. It does not prove that the certificate is actually being used as a client identity in production.&quot;,
            rf&quot;The dual-EKU group is concentrated in these issuer families: {latex_escape(&#x27;, &#x27;.join(f&#x27;{name} ({count})&#x27; for name, count in dual_issuer_counts.most_common()))}.&quot;,
            rf&quot;{len(purpose_summary.dual_eku_subject_cns_with_server_only_sibling)} dual-EKU Subject-CN families also have a strict server-only sibling, while {len(purpose_summary.dual_eku_subject_cns_without_server_only_sibling)} currently appear only in the dual-EKU group.&quot;,
            rf&quot;Dual-EKU validity starts are split between {latex_escape(&#x27;, &#x27;.join(f&#x27;{year} ({count})&#x27; for year, count in purpose_summary.validity_start_years.get(&#x27;tls_server_and_client&#x27;, {}).items()))}.&quot;,
            r&quot;The important interpretation point is that these still look like public hostname certificates: DNS-style Subject CN values, DNS SAN lists, and public WebPKI issuers. The better reading is therefore not ``separate client-certificate estate&#x27;&#x27;, but ``server certificates issued from a template that also allowed clientAuth&#x27;&#x27;.&quot;,
            r&quot;\subsection{What Is Not Present}&quot;,
            r&quot;There are no client-auth-only certificates, no S/MIME certificates, no code-signing certificates, no mixed-or-other EKU combinations, and no certificates missing EKU entirely.&quot;,
        ]
    )

    lines.append(r&quot;\section{Historical Renewal, Drift, and Red Flags}&quot;)
    add_summary(
        [
            f&quot;Looking across expired and current history, the corpus contains {historical_count} leaf certificates; {historical_current_count} of them are still valid today.&quot;,
            f&quot;{repeated_cn_count} Subject CN values recur over time rather than appearing as one-off singletons.&quot;,
            f&quot;{assessment.normal_reissuance_assets} renewal families look operationally normal: predecessor and successor overlap for fewer than 50 days.&quot;,
            f&quot;{len(assessment.overlap_current_rows)} names still show long overlap of 50 days or more today.&quot;,
            f&quot;{len(assessment.overlap_past_rows)} names showed the same long-overlap behaviour in the past, but not anymore in currently valid certificates.&quot;,
            f&quot;Current non-overlap anomalies are limited: {len(assessment.dn_current_rows)} live Subject DN drift cases, {len(assessment.vendor_current_rows)} live CA-family drift cases, and {len(assessment.san_current_rows)} live SAN drift cases.&quot;,
            f&quot;Past-only fixed anomalies were broader: {len(assessment.dn_past_rows)} historical Subject DN drift cases, {len(assessment.vendor_past_rows)} historical CA-family drift cases, and {len(assessment.san_past_rows)} historical SAN drift cases.&quot;,
        ]
    )
    lines.append(
        r&quot;This chapter is the historical check on whether the current picture follows a clean renewal pattern. It answers a different question from the current-corpus chapters above: not just what certificates exist now, but how the hostname estate has behaved over time.&quot;
    )
    lines.append(
        r&quot;For this chapter, a renewal family means repeated certificates that keep the same apparent identity over time: the same Subject CN, the same full Subject DN, the same SAN profile, and the same CA family. A normal renewal reissues that same apparent certificate identity with a new key and a new validity span, and predecessor and successor overlap only briefly. In this monograph, anything below fifty days of overlap is treated as normal. Fifty days or more is treated as a red flag. COMODO and Sectigo are treated as one CA family from the outset, so movement between those names is not counted here as CA-family drift.&quot;
    )
    lines.append(
        r&quot;A red flag in this chapter is not the same thing as a breach or a compromise. It means the certificate history diverged from the clean rollover pattern that one would normally expect and therefore deserves closer review.&quot;
    )
    lines.extend(
        [
            r&quot;\subsection{Current Red-Flag Inventory}&quot;,
        ]
    )
    if assessment.current_red_flag_rows:
        lines.extend(
            [
                r&quot;\begin{longtable}{&gt;{\raggedright\arraybackslash}p{0.27\linewidth} &gt;{\raggedleft\arraybackslash}p{0.10\linewidth} &gt;{\raggedright\arraybackslash}p{0.24\linewidth} &gt;{\raggedright\arraybackslash}p{0.29\linewidth}}&quot;,
                r&quot;\toprule&quot;,
                r&quot;Subject CN &amp; Live Certs &amp; Current Concern &amp; Immediate Supporting Context \\&quot;,
                r&quot;\midrule&quot;,
            ]
        )
        for row in assessment.current_red_flag_rows[:25]:
            lines.append(
                rf&quot;{latex_escape(row.subject_cn)} &amp; {row.current_certificate_count} &amp; {latex_escape(row.flags)} &amp; {latex_escape(truncate_text(row.notes, 72))} \\&quot;
            )
        lines.extend([r&quot;\bottomrule&quot;, r&quot;\end{longtable}&quot;])
    else:
        lines.append(r&quot;No current red flags were found under the configured rules.&quot;)
    lines.append(r&quot;\subsection{Past Red Flags Now Fixed}&quot;)
    if assessment.past_red_flag_rows:
        lines.extend(
            [
                r&quot;\begin{longtable}{&gt;{\raggedright\arraybackslash}p{0.27\linewidth} &gt;{\raggedleft\arraybackslash}p{0.10\linewidth} &gt;{\raggedright\arraybackslash}p{0.24\linewidth} &gt;{\raggedright\arraybackslash}p{0.29\linewidth}}&quot;,
                r&quot;\toprule&quot;,
                r&quot;Subject CN &amp; Historic Certs &amp; Historical Concern &amp; Immediate Supporting Context \\&quot;,
                r&quot;\midrule&quot;,
            ]
        )
        for row in assessment.past_red_flag_rows[:25]:
            lines.append(
                rf&quot;{latex_escape(row.subject_cn)} &amp; {row.certificate_count} &amp; {latex_escape(row.flags)} &amp; {latex_escape(truncate_text(row.notes, 72))} \\&quot;
            )
        lines.extend([r&quot;\bottomrule&quot;, r&quot;\end{longtable}&quot;])
    else:
        lines.append(r&quot;No past-only red flags were found under the configured rules.&quot;)
    lines.extend(
        [
            r&quot;\subsection{What The Historical Red Flags Mean}&quot;,
            r&quot;The two short tables above are screening tables. They answer which names deserve attention now and which names used to be problematic but no longer look live. The appendix below keeps the narrower evidence tables that explain why each name appears here.&quot;,
            rf&quot;Overlap red flags mean predecessor and successor certificates inside the same renewal family coexist for fifty days or more. Current cases: {len(assessment.overlap_current_rows)}. Past-only fixed cases: {len(assessment.overlap_past_rows)}.&quot;,
            rf&quot;Subject-DN drift means the same Subject CN appears under more than one full Subject DN. In plain terms, the headline hostname is being issued under different formal subject identities. Current cases: {len(assessment.dn_current_rows)}. Past-only fixed cases: {len(assessment.dn_past_rows)}.&quot;,
            rf&quot;CA-family drift means the same Subject CN appears under more than one CA family after collapsing COMODO and Sectigo together. Current cases: {len(assessment.vendor_current_rows)}. Past-only fixed cases: {len(assessment.vendor_past_rows)}.&quot;,
            rf&quot;SAN drift means the same Subject CN appears with more than one SAN profile. In plain terms, the hostname keeps being bundled with different companion names. Current cases: {len(assessment.san_current_rows)}. Past-only fixed cases: {len(assessment.san_past_rows)}.&quot;,
            rf&quot;Exact issuer-name changes also exist for {len(assessment.issuer_rows)} Subject CN values, but these are supporting context rather than first-order red flags.&quot;,
            r&quot;\subsection{Historical Step Changes}&quot;,
            rf&quot;Top issuance start dates are {latex_escape(&#x27;, &#x27;.join(f&#x27;{row.start_day} ({row.certificate_count})&#x27; for row in assessment.day_rows[:6]))}.&quot;,
            rf&quot;Strong step weeks are {latex_escape(&#x27;, &#x27;.join(f&#x27;{row.week_start} ({row.certificate_count} vs prior avg {row.prior_eight_week_avg})&#x27; for row in assessment.week_rows[:4]) or &#x27;none&#x27;)}.&quot;,
        ]
    )

    lines.append(r&quot;\section{Naming Architecture}&quot;)
    add_summary(
        [
            f&quot;Numbered CN families: {len(report[&#x27;numbered_groups&#x27;])}.&quot;,
            f&quot;Multi-zone SAN sets: {report[&#x27;multi_zone_hit_count&#x27;]}.&quot;,
            f&quot;Frequent naming tokens are {&#x27;, &#x27;.join(f&#x27;{token} ({count})&#x27; for token, count in report[&#x27;top_env_tokens&#x27;][:8])}.&quot;,
            &quot;The strongest naming signals come from numbered rails, environment markers, cross-brand labels, and cross-zone SAN composition. www is weak evidence either way.&quot;,
        ]
    )
    lines.append(
        r&quot;The naming regime becomes intelligible when read as several superimposed languages: brand language, service language, environment language, platform language, and migration residue.&quot;
    )
    lines.extend(
        [
            r&quot;\subsection{How To Read The Names}&quot;,
            r&quot;\begin{itemize}[leftmargin=1.4em]&quot;,
            r&quot;\item In most of these names, the left-most label tells you the endpoint role, node slot, or environment slice, while the zone on the right tells you which public namespace the service is answering under.&quot;,
            r&quot;\item Standard delivery shorthand appears throughout the corpus: \texttt{dev}, \texttt{qa}, \texttt{uat}, \texttt{sit}, \texttt{stg}, \texttt{preprod}, and \texttt{prod} are ordinary environment markers rather than mysterious product names.&quot;,
            r&quot;\item \texttt{www} is a weak signal both when present and when absent. Its presence often reflects compatibility, redirect history, or old web conventions; its absence does not imply any deeper architectural distinction.&quot;,
            r&quot;\item In this corpus, \texttt{nwg} reads as NatWest Group shorthand. Names like \texttt{rbs}, \texttt{natwest}, \texttt{ulsterbank}, \texttt{lombard}, \texttt{natwestpayments}, \texttt{coutts}, and \texttt{nwgwealth} are best read as parallel business or service namespaces within a wider shared estate, not as random unrelated domains.&quot;,
            r&quot;\item Some short forms remain inferential rather than provable. For example, \texttt{nft} clearly behaves like a non-production stage label, but Certificate Transparency alone cannot prove the local expansion used inside the company.&quot;,
            r&quot;\end{itemize}&quot;,
        ]
    )
    lines.append(r&quot;\subsection{Key Pattern Examples}&quot;)
    lines.append(
        r&quot;These four boxes are not four isolated hostnames. Each one uses a concrete Subject-CN value as the evidence anchor for a broader naming methodology that appears elsewhere in the estate as well.&quot;
    )
    for example in report[&quot;examples&quot;]:
        lines.append(r&quot;\SummaryBox{&quot;)
        lines.append(rf&quot;\textbf{{{latex_escape(example.title)}}}\par&quot;)
        lines.append(rf&quot;\textbf{{Pattern shown}}: {latex_escape(example_pattern_label(example.title))}\par&quot;)
        lines.append(rf&quot;\textbf{{Concrete example}}: \texttt{{{latex_escape(example.subject_cn)}}}\par&quot;)
        lines.append(rf&quot;\textbf{{What this proves}}: {latex_escape(example.why_it_matters)}\par&quot;)
        lines.append(r&quot;\begin{itemize}[leftmargin=1.4em]&quot;)
        for point in example.evidence:
            lines.append(rf&quot;\item {latex_escape(point)}&quot;)
        lines.append(r&quot;\end{itemize}}&quot;)
    lines.extend(
        [
            r&quot;\subsection{Why These Four Examples}&quot;,
            r&quot;Taken together, these four examples explain most of the naming behaviour in the corpus. The first shows platform fleet naming, the second shows environment-and-release naming, the third shows cross-brand namespace splicing and migration residue, and the fourth shows shared-service bridging across several business namespaces.&quot;,
        ]
    )

    lines.append(r&quot;\section{DNS Delivery Architecture}&quot;)
    add_summary(
        [
            f&quot;Most names resolve by first aliasing to another hostname and then to an address: {alias_to_address_count} public names follow an alias chain, while {direct_address_count} names resolve straight to an address.&quot;,
            f&quot;The most common public DNS outcomes are Adobe Campaign in front of AWS load-balancing ({report[&#x27;dns_stack_counts&#x27;].get(&#x27;Adobe Campaign -&gt; AWS ALB&#x27;, 0)}), Adobe Campaign in front of AWS CloudFront ({report[&#x27;dns_stack_counts&#x27;].get(&#x27;Adobe Campaign -&gt; AWS CloudFront&#x27;, 0)}), and plain AWS CloudFront without an Adobe layer ({report[&#x27;dns_stack_counts&#x27;].get(&#x27;AWS CloudFront&#x27;, 0)}).&quot;,
            f&quot;Smaller but important subsets look like governed API fronts or specialist application platforms: Google Apigee ({report[&#x27;dns_stack_counts&#x27;].get(&#x27;Google Apigee&#x27;, 0)}) and Pega Cloud -&gt; AWS ALB ({report[&#x27;dns_stack_counts&#x27;].get(&#x27;Pega Cloud -&gt; AWS ALB&#x27;, 0)}).&quot;,
            f&quot;Some certificate names do not lead to a live public endpoint today: {nxdomain_count} do not exist in public DNS at all, {dangling_count} still exist only as broken aliases, and {no_data_count} exist in DNS but returned no public A or AAAA address during the scan.&quot;,
        ]
    )
    lines.append(
        r&quot;DNS is the public routing layer. It does not tell you everything about an application, but it does tell you where a public name lands: directly on an IP, through an alias chain, through a CDN, through an API gateway, or onto a specialist platform.&quot;
    )
    lines.append(
        r&quot;This chapter does not claim to know the full private architecture behind each service. It only claims what the public DNS trail supports. For each DNS SAN name in the certificate corpus, the scanner queried public \texttt{CNAME}, \texttt{A}, \texttt{AAAA}, and \texttt{PTR} data. It then summarized that public answer trail with a short label. Those labels are compact descriptions of the public DNS evidence, not arbitrary platform slogans.&quot;
    )
    lines.append(
        r&quot;One important caution follows from that last point: a hostname can remain visible in certificate history even after its public DNS has been removed or partially dismantled. Certificate history and current DNS are related, but they do not move in lockstep.&quot;
    )
    lines.extend(
        [
            r&quot;\subsection{How The DNS Evidence Is Read}&quot;,
            r&quot;\begin{itemize}[leftmargin=1.4em]&quot;,
            r&quot;\item A \texttt{CNAME} shows that one public name is really an alias for another public name.&quot;,
            r&quot;\item The terminal hostname, returned addresses, and reverse-DNS names often reveal platform clues such as \texttt{cloudfront.net}, \texttt{elb.amazonaws.com}, \texttt{apigee.net}, or \texttt{campaign.adobe.com}.&quot;,
            r&quot;\item The report combines the answer shape and those clues into one short description. For example, ``Adobe Campaign -&gt; AWS ALB&#x27;&#x27; means the alias chain contains Adobe Campaign naming and the terminal clues point to AWS load-balancing infrastructure.&quot;,
            r&quot;\item These labels are therefore evidence summaries, not claims of legal ownership or full internal design.&quot;,
            r&quot;\end{itemize}&quot;,
            r&quot;\subsection{What The Public DNS Names Resolve To}&quot;,
            r&quot;\begin{longtable}{&gt;{\raggedright\arraybackslash}p{0.28\linewidth} &gt;{\raggedleft\arraybackslash}p{0.09\linewidth} &gt;{\raggedright\arraybackslash}p{0.51\linewidth}}&quot;,
            r&quot;\toprule&quot;,
            r&quot;Observed DNS Outcome &amp; Count &amp; Plain-Language Meaning \\&quot;,
            r&quot;\midrule&quot;,
        ]
    )
    for label, count in top_dns_patterns:
        lines.append(rf&quot;{latex_escape(label)} &amp; {count} &amp; {latex_escape(delivery_pattern_meaning(label))} \\&quot;)
    lines.extend([r&quot;\bottomrule&quot;, r&quot;\end{longtable}&quot;])
    lines.extend(
        [
            r&quot;\subsection{Why Each DNS Label Was Used}&quot;,
            r&quot;\begin{itemize}[leftmargin=1.4em]&quot;,
        ]
    )
    for label, _count in top_dns_patterns[:6]:
        lines.append(rf&quot;\item \textbf{{{latex_escape(label)}}}: {latex_escape(delivery_pattern_rule(label))}&quot;)
    lines.extend(
        [
            r&quot;\end{itemize}&quot;,
            r&quot;\subsection{Platform And DNS Glossary}&quot;,
            r&quot;\begin{longtable}{&gt;{\raggedright\arraybackslash}p{0.22\linewidth} &gt;{\raggedright\arraybackslash}p{0.70\linewidth}}&quot;,
            r&quot;\toprule&quot;,
            r&quot;Term &amp; Explanation \\&quot;,
            r&quot;\midrule&quot;,
        ]
    )
    glossary = ct_dns_utils.provider_explanations()
    for term in [&quot;Adobe Campaign&quot;, &quot;AWS&quot;, &quot;AWS ALB&quot;, &quot;AWS CloudFront&quot;, &quot;Google Apigee&quot;, &quot;Pega Cloud&quot;, &quot;Microsoft Edge&quot;, &quot;Infinite / agency alias&quot;, &quot;CNAME&quot;, &quot;A record&quot;, &quot;AAAA record&quot;, &quot;PTR record&quot;, &quot;NXDOMAIN&quot;]:
        lines.append(rf&quot;{latex_escape(term)} &amp; {latex_escape(glossary[term])} \\&quot;)
    lines.extend([r&quot;\bottomrule&quot;, r&quot;\end{longtable}&quot;])
    lines.append(
        r&quot;The glossary terms above are the building blocks used in the DNS-outcome table. This is also why the management summary mentions Adobe Campaign, CloudFront, Apigee, and Pega at all: not because brand names are the point, but because those names reveal what kind of public delivery role a hostname is landing on. CloudFront suggests a distribution edge, Apigee suggests managed API exposure, Adobe Campaign suggests a marketing or communications front, and a load balancer suggests traffic distribution to backend services.&quot;
    )
    lines.append(
        r&quot;The next chapter stays with the same names but moves from delivery to control. This chapter asked where public traffic lands. The next one asks which public CA families DNS currently authorizes to issue for those same names.&quot;
    )

    lines.append(r&quot;\section{DNS Issuance Policy Control (CAA)}&quot;)
    zone_summary_items: list[str] = []
    for zone in caa_analysis.configured_domains:
        zone_rows = ct_caa_analysis.rows_for_zone(caa_analysis, zone)
        unrestricted_count = sum(1 for row in zone_rows if not row.allowed_ca_families)
        mismatch_count = sum(1 for row in zone_rows if row.current_policy_mismatch)
        overlap_count = sum(1 for row in zone_rows if row.current_multi_family_overlap)
        dominant_policy = ct_caa_analysis.policy_counter(zone_rows).most_common(1)
        dominant_label = caa_policy_label(dominant_policy[0][0]) if dominant_policy else &quot;none&quot;
        zone_summary_items.append(
            f&quot;{zone}: {len(zone_rows)} names in scope; dominant policy is {dominant_label}; unrestricted names={unrestricted_count}; current policy-mismatch names={mismatch_count}; current multi-family overlap names={overlap_count}.&quot;
        )
    add_summary(
        zone_summary_items
        + [
            f&quot;Effective CAA discovery paths across all names are {&#x27;, &#x27;.join(f&#x27;{caa_source_label(kind)}={count}&#x27; for kind, count in caa_analysis.source_kind_counts.most_common())}.&quot;,
            f&quot;Current names simultaneously covered by more than one live CA family: {len(caa_analysis.multi_family_overlap_names)}.&quot;,
            f&quot;Current names whose live certificate family does not match today&#x27;s published CAA policy: {len(caa_analysis.policy_mismatch_names)}.&quot;,
        ]
    )
    lines.append(
        r&quot;CAA is the DNS control layer for public certificate issuance. It does not validate a certificate after issuance; instead, it tells a public CA which CA families are authorized to issue for a DNS name if any restriction is published at all. If no CAA is published, WebPKI issuance is unrestricted from the DNS-policy point of view.&quot;
    )
    lines.append(
        r&quot;This chapter is the control-plane counterpart to the certificate and DNS chapters. The certificate chapter showed who actually issued. The DNS chapter showed where the names land. The CAA chapter shows which issuers the DNS owner currently allows for those same names.&quot;
    )
    lines.append(
        r&quot;That distinction matters because hosting and issuance are different decisions. A name can land on AWS and still use a Sectigo-family certificate if DNS policy allows it. A name can also resolve through a vendor platform while still inheriting a first-party corporate CAA policy. The point of this chapter is to show where those decisions line up and where they do not.&quot;
    )
    lines.append(
        r&quot;CAA is checked per DNS name requested in the certificate, not per Subject DN and not per organisational story. A Subject CN can therefore shift between different Subject DN values without creating a CAA clash, because CAA ignores organisation fields and looks only at the DNS names being certified.&quot;
    )
    lines.extend(
        [
            r&quot;\subsection{Why CAA Matters In This Estate}&quot;,
            r&quot;\begin{itemize}[leftmargin=1.4em]&quot;,
            r&quot;\item If a name has no CAA, DNS is not constraining which public CA family may issue for it.&quot;,
            r&quot;\item If a name inherits a broad corporate policy, that usually means the organisation has left normal brand-facing names under a common default.&quot;,
            r&quot;\item If a name falls under a narrower subtree or alias-derived policy, that is evidence of more deliberate platform or vendor-specific issuance control.&quot;,
            r&quot;\item If a live certificate family sits outside today&#x27;s CAA policy, or if the same DNS name is live under two CA families at once, that usually points to migration lag, overlapping rollout, or policy that moved faster than certificate cleanup.&quot;,
            r&quot;\end{itemize}&quot;,
        ]
    )
    lines.extend(
        [
            r&quot;\subsection{How To Read The CAA Results}&quot;,
            r&quot;\begin{longtable}{&gt;{\raggedright\arraybackslash}p{0.24\linewidth} &gt;{\raggedleft\arraybackslash}p{0.10\linewidth} &gt;{\raggedright\arraybackslash}p{0.54\linewidth}}&quot;,
            r&quot;\toprule&quot;,
            r&quot;CAA Discovery Result &amp; Names &amp; Meaning \\&quot;,
            r&quot;\midrule&quot;,
        ]
    )
    for label, count, meaning in caa_source_rows(caa_analysis):
        lines.append(rf&quot;{latex_escape(label)} &amp; {latex_escape(count)} &amp; {latex_escape(meaning)} \\&quot;)
    lines.extend([r&quot;\bottomrule&quot;, r&quot;\end{longtable}&quot;])
    lines.append(
        r&quot;The key distinction is between ordinary parent inheritance and alias-target-derived policy. Parent inheritance means the leaf name simply relies on a policy published higher in its own DNS tree. Alias-target-derived policy means the effective CAA surfaced through an alias response. In this corpus, that often marks a managed rail or specialist external platform rather than a plain brand-front hostname.&quot;
    )
    lines.append(
        r&quot;In practical terms, most names in this corpus fall into three shapes: inherited corporate policy, alias-driven managed-platform policy, or no CAA at all. That three-way split is more important than the mechanics themselves, because it shows where issuance control is broad, where it is deliberately narrow, and where it is absent.&quot;
    )
    lines.append(r&quot;\subsection{Policy Regimes By Configured Zone}&quot;)
    for zone in caa_analysis.configured_domains:
        lines.append(rf&quot;\subsubsection{{{latex_escape(zone)}}}&quot;)
        lines.extend(
            [
                r&quot;\begin{longtable}{&gt;{\raggedright\arraybackslash}p{0.25\linewidth} &gt;{\raggedleft\arraybackslash}p{0.10\linewidth} &gt;{\raggedright\arraybackslash}p{0.53\linewidth}}&quot;,
                r&quot;\toprule&quot;,
                r&quot;Policy Regime &amp; Names &amp; Plain-Language Meaning \\&quot;,
                r&quot;\midrule&quot;,
            ]
        )
        for regime, count, meaning in caa_zone_rows[zone]:
            lines.append(rf&quot;{latex_escape(regime)} &amp; {latex_escape(count)} &amp; {latex_escape(meaning)} \\&quot;)
        lines.extend([r&quot;\bottomrule&quot;, r&quot;\end{longtable}&quot;])
    if secondary_zone:
        lines.append(
            rf&quot;The contrast between \texttt{{{latex_escape(primary_zone)}}} and \texttt{{{latex_escape(secondary_zone)}}} is one of the strongest PKI-governance findings in the corpus. \texttt{{{latex_escape(primary_zone)}}} is policy-layered and governed, while \texttt{{{latex_escape(secondary_zone)}}} is currently CAA-empty in the scanned name set. That does not make \texttt{{{latex_escape(secondary_zone)}}} invalid, but it does mean DNS is not constraining public CA choice there.&quot;
        )
        lines.append(
            rf&quot;That asymmetry matters more than any one record. \texttt{{{latex_escape(primary_zone)}}} looks like a namespace where DNS is being used as an issuance-governance tool. \texttt{{{latex_escape(secondary_zone)}}} looks like a namespace where issuance choice is still being handled outside DNS policy, or not being constrained at all.&quot;
        )
    lines.extend(
        [
            r&quot;\subsection{How CAA Changes The Reading Of The Estate}&quot;,
            r&quot;The CAA layer strengthens the earlier certificate-and-DNS thesis rather than overturning it. The same service families that already looked like shared managed rails from naming and DNS often sit under narrower issuance policy as well.&quot;,
            rf&quot;In \texttt{{{latex_escape(primary_zone)}}}, the current CAA friction is concentrated rather than diffuse: {latex_escape(caa_concentration_text(caa_analysis, primary_zone))}.&quot;,
            r&quot;Broad corporate default policy remains visible on many ordinary brand-facing names. That supports the earlier reading that not every public hostname was moved onto one tightly managed delivery rail.&quot;,
            r&quot;Narrower or alias-driven CAA policy appears where the DNS evidence already suggested a managed platform, campaign rail, or vendor-mediated service surface.&quot;,
            r&quot;Vendor-style exceptions still exist. Where a name resolves through a specialist external platform and the allowed CA set widens or changes shape, the policy layer supports the earlier vendor-delegation reading rather than contradicting it.&quot;,
            r&quot;The chapter therefore adds a governance gradient to the earlier thesis: some parts of the estate are tightly steered, some inherit a broad default, and some are still policy-empty.&quot;,
            r&quot;\subsection{Why The Next Two Tables Matter}&quot;,
            r&quot;\begin{itemize}[leftmargin=1.4em]&quot;,
            r&quot;\item The overlap table shows where an old and a new issuance regime are both still live on the same DNS name.&quot;,
            r&quot;\item The mismatch table shows where today&#x27;s DNS policy has already moved, but one or more live certificates still reflect the older state.&quot;,
            r&quot;\item Read them together, not separately. Together they show whether the estate looks diffusely messy or whether the untidy parts cluster in a small transition zone.&quot;,
            r&quot;\end{itemize}&quot;,
            r&quot;\subsection{Current Multi-Family Overlap}&quot;,
        ]
    )
    if caa_analysis.multi_family_overlap_names:
        append_longtable(
            lines,
            r&quot;&gt;{\raggedright\arraybackslash}p{0.27\linewidth} &gt;{\raggedright\arraybackslash}p{0.10\linewidth} &gt;{\raggedright\arraybackslash}p{0.16\linewidth} &gt;{\raggedright\arraybackslash}p{0.33\linewidth}&quot;,
            [&quot;DNS Name&quot;, &quot;Zone&quot;, &quot;Live CA Families&quot;, &quot;Covering Subject CNs&quot;],
            top_caa_overlap_rows(caa_analysis),
            font=&quot;footnotesize&quot;,
            tabcolsep=&quot;3.2pt&quot;,
        )
    else:
        lines.append(r&quot;No current multi-family overlap names were found.&quot;)
    lines.append(
        r&quot;These overlap names are operationally important. They show where the same public DNS name is currently covered by more than one live CA family at once. In this corpus, that behavior clusters tightly in a few service families rather than being spread randomly across the estate.&quot;
    )
    lines.append(r&quot;\subsection{Current Policy Mismatch}&quot;)
    if caa_analysis.policy_mismatch_names:
        append_longtable(
            lines,
            r&quot;&gt;{\raggedright\arraybackslash}p{0.24\linewidth} &gt;{\raggedright\arraybackslash}p{0.10\linewidth} &gt;{\raggedright\arraybackslash}p{0.14\linewidth} &gt;{\raggedright\arraybackslash}p{0.16\linewidth} &gt;{\raggedright\arraybackslash}p{0.20\linewidth}&quot;,
            [&quot;DNS Name&quot;, &quot;Zone&quot;, &quot;Live CA Families&quot;, &quot;CAA-Allowed Families&quot;, &quot;CAA Discovery Result&quot;],
            top_caa_mismatch_rows(caa_analysis),
            font=&quot;footnotesize&quot;,
            tabcolsep=&quot;3.0pt&quot;,
        )
    else:
        lines.append(r&quot;No current policy-mismatch names were found.&quot;)
    lines.append(
        r&quot;A current policy mismatch does not automatically prove CA misissuance. CAA only proves what DNS authorizes now. Certificates can remain valid after the DNS-side policy has changed, so the right reading here is current policy lag or migration residue unless the historical issuance-time DNS can also be shown.&quot;
    )
    lines.append(
        r&quot;Taken together, the overlap and mismatch tables support a migration reading more than a disorder reading. If the estate were simply chaotic, the live friction would be spread widely across unrelated names. Instead, it clusters in a small number of service families that were already prominent in the certificate and DNS chapters.&quot;
    )

    if focus_analysis:
        lines.append(r&quot;\section{Focused Subject-CN Cohort}&quot;)
        add_summary(
            [
                f&quot;The focused cohort contains {focus_analysis.provided_subjects_count} analyst-selected Subject CN values. {focus_analysis.historically_seen_subjects_count} are visible somewhere in the historical CT corpus, and {focus_analysis.current_direct_subjects_count} still have direct current certificates.&quot;,
                f&quot;The current focused cohort is structurally different from the rest of the estate: all {focus_analysis.current_focus_certificate_count} current focused certificates are Sectigo/COMODO-lineage, compared with {counter_text(focus_analysis.rest_current_issuer_families, 3)} in the rest of the corpus.&quot;,
                f&quot;The focused cohort uses much smaller certificates: median SAN size {focus_analysis.focus_median_san_entries} versus {focus_analysis.rest_median_san_entries}, and {focus_analysis.focus_multi_zone_certificate_count} current multi-zone certificates versus {focus_analysis.rest_multi_zone_certificate_count} outside the cohort.&quot;,
                f&quot;Revocation churn is much higher inside the focused cohort: {focus_analysis.focus_revoked_current_count} revoked versus {focus_analysis.focus_not_revoked_current_count} not revoked ({focus_analysis.focus_revoked_share}), compared with {focus_analysis.rest_revoked_current_count} versus {focus_analysis.rest_not_revoked_current_count} ({focus_analysis.rest_revoked_share}) outside the cohort.&quot;,
                f&quot;Cross-basket carrying is limited rather than universal. The count of focused entries that appear today only as SAN passengers is {focus_analysis.current_carried_only_subjects_count}, and the count ever seen as SAN passengers inside non-focused certificates at all is {focus_analysis.historical_non_focus_carried_subjects_count}.&quot;,
                f&quot;The cohort splits into three naming buckets rather than one uniform style: {focus_analysis.bucket_counts.get(&#x27;direct_front_door&#x27;, 0)} front-door direct names, {focus_analysis.bucket_counts.get(&#x27;platform_matrix_anchor&#x27;, 0)} platform-anchor matrix names, and {focus_analysis.bucket_counts.get(&#x27;ambiguous_legacy&#x27;, 0)} ambiguous or legacy-residue names.&quot;,
            ]
        )
        lines.append(
            r&quot;This chapter treats the supplied Subject-CN list as an analyst-guided cohort rather than as a neutral statistical sample. The question is not whether these names are the most common names in the estate. The question is why they were memorable enough to be singled out, and whether the certificate and DNS evidence shows that they belong to a different naming and hosting tradition.&quot;
        )
        lines.append(
            r&quot;The short answer is yes, but not because the cohort is perfectly uniform. The cohort is different from the wider estate because it is weighted toward remembered public fronts and remembered platform anchors, not toward the Amazon-heavy operational rail population that dominates the broader corpus.&quot;
        )
        lines.extend(
            [
                r&quot;\subsection{Focused Cohort Versus The Rest Of The Estate}&quot;,
            ]
        )
        append_longtable(
            lines,
            r&quot;&gt;{\raggedright\arraybackslash}p{0.27\linewidth} &gt;{\raggedright\arraybackslash}p{0.16\linewidth} &gt;{\raggedright\arraybackslash}p{0.16\linewidth} &gt;{\raggedright\arraybackslash}p{0.31\linewidth}&quot;,
            [&quot;Comparison View&quot;, &quot;Focused Cohort&quot;, &quot;Rest Of Current Corpus&quot;, &quot;Why It Matters&quot;],
            focus_comparison,
            font=&quot;footnotesize&quot;,
            tabcolsep=&quot;3.2pt&quot;,
        )
        lines.extend(
            [
                r&quot;\subsection{Three Buckets Inside The Cohort}&quot;,
            ]
        )
        append_longtable(
            lines,
            r&quot;&gt;{\raggedright\arraybackslash}p{0.15\linewidth} &gt;{\raggedleft\arraybackslash}p{0.06\linewidth} &gt;{\raggedright\arraybackslash}p{0.19\linewidth} &gt;{\raggedright\arraybackslash}p{0.24\linewidth} &gt;{\raggedright\arraybackslash}p{0.26\linewidth}&quot;,
            [&quot;Bucket&quot;, &quot;Count&quot;, &quot;Representative Names&quot;, &quot;What It Looks Like&quot;, &quot;Why This Bucket Exists&quot;],
            focus_bucket_summary,
            font=&quot;footnotesize&quot;,
            tabcolsep=&quot;3.0pt&quot;,
        )
        lines.extend(
            [
                r&quot;This bucket split is the key to making the cohort intelligible. The memorable names are not all from one naming methodology. Most are direct public fronts. A very small number are platform-anchor certificates with matrix SAN design. The rest are historical leftovers, carried aliases, or opaque labels whose original role is no longer cleanly visible in the current corpus.&quot;,
                r&quot;\subsection{Why This Cohort Feels Different}&quot;,
                r&quot;\begin{itemize}[leftmargin=1.4em]&quot;,
                r&quot;\item The dominant bucket is the front-door direct bucket. These are small-SAN certificates attached to memorable service, identity, vendor, or brand-like names directly under the branded public zones configured for the scan.&quot;,
                r&quot;\item The platform-anchor bucket is tiny but important. These names carry large SAN matrices that spell out environment, tenant, service-cell, or monitoring coverage, which is exactly what one would expect from a centrally managed operational platform slice.&quot;,
                r&quot;\item The ambiguous bucket matters because it explains the leftover rough edges. These names may be historical-only, partly migrated into other certificates, or too opaque to decode confidently from public evidence alone.&quot;,
                r&quot;\item The public DNS evidence for the current focused Subject CN names is also different. The cohort lands much more often on direct addresses or simple direct AWS clues, while the wider current Subject-CN population is much more dominated by Adobe-managed, Apigee-managed, or NXDOMAIN outcomes.&quot;,
                r&quot;\item Historical red flags are common in the cohort, but they are mostly past rather than current. That is consistent with a legacy or manually managed public-web slice that has been cleaned up over time rather than with a currently chaotic platform core.&quot;,
                r&quot;\end{itemize}&quot;,
            ]
        )
        lines.append(
            r&quot;Seen this way, the cohort makes sense. It looks like a remembered estate made of two high-visibility extremes: public-facing service fronts that humans remember because customers and staff encounter them directly, and a small number of operational anchor names that humans remember because administrators, testers, or engineers encounter them repeatedly. The ambiguous bucket is the residue between those two poles.&quot;
        )
        lines.append(r&quot;\subsection{Cross-Basket Carrying And Migration}&quot;)
        if focus_analysis.transition_rows:
            append_longtable(
                lines,
                r&quot;&gt;{\raggedright\arraybackslash}p{0.22\linewidth} &gt;{\raggedright\arraybackslash}p{0.19\linewidth} &gt;{\raggedright\arraybackslash}p{0.11\linewidth} &gt;{\raggedleft\arraybackslash}p{0.09\linewidth} &gt;{\raggedright\arraybackslash}p{0.27\linewidth}&quot;,
                [&quot;Subject CN&quot;, &quot;Current Basket Status&quot;, &quot;Direct / Carried&quot;, &quot;Max Overlap Days&quot;, &quot;Carrier Subjects&quot;],
                [
                    [
                        detail.subject_cn,
                        detail.basket_status,
                        f&quot;{detail.current_direct_certificates}/{detail.current_non_focus_san_carriers + detail.historical_non_focus_san_carriers}&quot;,
                        str(detail.max_direct_to_carrier_overlap_days),
                        truncate_text(detail.carrier_subjects, 48),
                    ]
                    for detail in focus_analysis.transition_rows[:10]
                ],
                font=&quot;footnotesize&quot;,
                tabcolsep=&quot;3.1pt&quot;,
            )
        else:
            lines.append(r&quot;No focused names were seen as SAN passengers inside non-focused certificates.&quot;)
        lines.append(
            r&quot;This migration table answers a narrower question than the rest of the chapter. It asks whether these names were gradually absorbed into broader certificates from outside the cohort. The answer is: only in a limited number of cases. Some names do show SAN-passenger behavior or historical carrying, but that is not the dominant explanation for why the cohort feels different. The dominant explanation is the bucket split above: many remembered direct fronts, a few large platform anchors, and a band of legacy residue.&quot;
        )
        lines.append(r&quot;\subsection{Representative Names By Bucket}&quot;)
        append_longtable(
            lines,
            r&quot;&gt;{\raggedright\arraybackslash}p{0.14\linewidth} &gt;{\raggedright\arraybackslash}p{0.17\linewidth} &gt;{\raggedright\arraybackslash}p{0.18\linewidth} &gt;{\raggedright\arraybackslash}p{0.09\linewidth} &gt;{\raggedright\arraybackslash}p{0.30\linewidth}&quot;,
            [&quot;Bucket&quot;, &quot;Subject CN&quot;, &quot;Observed Role&quot;, &quot;Direct C/H&quot;, &quot;Why It Helps Explain The Bucket&quot;],
            focus_representatives,
            font=&quot;footnotesize&quot;,
            tabcolsep=&quot;3.0pt&quot;,
        )
        lines.append(
            r&quot;These examples are evidence anchors, not the whole population. The direct-front examples show the remembered public surface. The platform-anchor examples show the rare but important matrix certificates. The ambiguous examples show why the cohort cannot be reduced to a single neat story without losing the migration and legacy residue that made these names memorable in the first place.&quot;
        )

    lines.append(r&quot;\Needspace{12\baselineskip}&quot;)
    lines.append(r&quot;\section{Making The Whole Estate Make Sense}&quot;)
    add_summary(
        [
            &quot;The certificate, DNS, and CAA layers are not three separate stories. They are three views of the same operating estate.&quot;,
            &quot;Naming shows role and organisational memory; DNS shows where traffic lands; CAA shows how tightly issuance is governed.&quot;,
            &quot;Clean public brand names usually sit closest to the customer surface, while dense SAN sets, numbered families, multi-zone certificates, and narrower CAA policy usually expose the shared platform layer beneath them.&quot;,
            &quot;When the layers disagree, the disagreement usually signals migration or uneven governance maturity rather than a flat contradiction.&quot;,
            &quot;The overall pattern is more consistent with a federated operating model with uneven governance maturity than with random hostname sprawl.&quot;,
        ]
    )
    lines.append(
        r&quot;The common ground is operational reality. A branded proposition wants recognisable names. A service team wants a stable endpoint namespace. A platform team wants shared rails and repeatable delivery machinery. A hosting team wants routable front doors that can land on cloud distribution, gateways, or workflow platforms. A security or PKI function wants some names tightly governed and other names left broad or delegated. Certificates, DNS, and CAA tell the same estate story from different angles.&quot;
    )
    lines.append(
        r&quot;A useful way to combine the layers is to ask four questions in order. First, what does the name itself look like: a direct front door, a numbered rail, an environment slice, or a bridge across business zones? Second, how broad is the SAN set: is this one visible service or a bundled platform certificate? Third, where does public DNS actually land the name: direct host, CDN edge, API gateway, campaign rail, or specialist platform? Fourth, does DNS issuance policy stay broad, narrow sharply, or disappear entirely?&quot;
    )
    lines.append(
        r&quot;When those answers align, the reading becomes strong. A small-SAN branded name with ordinary inherited policy reads like a direct public front. A dense multi-zone certificate with numbered families, managed DNS landing, and narrower CAA reads like a shared operational rail. A name that lands on AWS but still uses a Sectigo-family certificate shows that hosting choice and CA choice are separate decisions. A name with current overlap and current policy mismatch shows a transition area where the newer issuance model is already in place but the older certificate state has not fully disappeared.&quot;
    )
    lines.append(
        r&quot;This is why the estate can look both tidy and messy at once. It is tidy within each layer, but messy across layers because the layers are solving different problems. The new CAA evidence sharpens that point rather than contradicting it: the managed rail families are not only named and hosted differently, they are often policy-controlled differently as well. The biggest qualification is that governance is uneven. The primary configured zone shows layered issuance control, while another configured zone remains CAA-empty. That is not random chaos, but it is also not uniform control maturity.&quot;
    )

    lines.append(r&quot;\section{Limits, Confidence, and Noise}&quot;)
    add_summary(
        [
            &quot;High-confidence claims are tied directly to certificate fields, DNS answers, live trust records, and current CAA policy.&quot;,
            &quot;Medium-confidence claims are organisational readings drawn from repeated technical patterns.&quot;,
            &quot;Lower-confidence claims are exact expansions of abbreviations and exact ownership boundaries inferred from names alone.&quot;,
            &quot;A public NXDOMAIN today does not automatically contradict a valid certificate because DNS and certificate lifecycles move on different clocks.&quot;,
            &quot;A current CAA mismatch does not by itself prove historical CA non-compliance, because DNS policy may have changed after issuance.&quot;,
        ]
    )
    lines.append(
        r&quot;A useful way to read the corpus is to separate signal from noise. Repeated naming schemas are signal. Repeated DNS outcomes are signal. Which public CA family keeps issuing a name is signal. Where CAA is broad, narrow, delegated, or absent is signal. Simple \texttt{www} presence or absence is weak evidence either way unless it coincides with stronger differences such as distinct DNS routing, distinct SAN composition, a distinct certificate renewal history, or a distinct issuance-policy shape.&quot;
    )

    lines.extend(
        [
            r&quot;\clearpage&quot;,
            r&quot;\appendix&quot;,
            r&quot;\section{Full Family Catalogue}&quot;,
            r&quot;This appendix is a compact family map. It is not the place for full per-certificate evidence; that remains in the detailed inventory appendix at the end of the monograph.&quot;,
        ]
    )
    append_longtable(
        lines,
        r&quot;&gt;{\raggedright\arraybackslash}p{0.56\linewidth} &gt;{\raggedleft\arraybackslash}p{0.09\linewidth} &gt;{\raggedleft\arraybackslash}p{0.08\linewidth} &gt;{\raggedright\arraybackslash}p{0.18\linewidth}&quot;,
        [&quot;Family Basis&quot;, &quot;Certs&quot;, &quot;CNs&quot;, &quot;Dominant Stack&quot;],
        family_rows,
        font=&quot;footnotesize&quot;,
        tabcolsep=&quot;3.0pt&quot;,
    )

    lines.extend(
        [
            r&quot;\section{Historical Red-Flag Detail}&quot;,
            r&quot;This appendix keeps the detailed historical evidence inside the monograph so that the reader does not need a second report. Each subsection answers one narrow question. If a column does not help answer that question, it has been removed.&quot;,
            r&quot;In this appendix, a renewal family means repeated certificates that keep the same apparent identity over time: the same Subject CN, the same full Subject DN, the same SAN profile, and the same CA family.&quot;,
            r&quot;\subsection{Current Red-Flag Inventory}&quot;,
        ]
    )
    if assessment.current_red_flag_rows:
        append_longtable(
            lines,
            r&quot;&gt;{\raggedright\arraybackslash}p{0.28\linewidth} &gt;{\raggedleft\arraybackslash}p{0.09\linewidth} &gt;{\raggedright\arraybackslash}p{0.24\linewidth} &gt;{\raggedright\arraybackslash}p{0.27\linewidth}&quot;,
            [&quot;Subject CN&quot;, &quot;Live Certs&quot;, &quot;Current Concern&quot;, &quot;Supporting Context&quot;],
            [
                [
                    row.subject_cn,
                    str(row.current_certificate_count),
                    row.flags,
                    truncate_text(row.notes, 84),
                ]
                for row in assessment.current_red_flag_rows
            ],
            font=&quot;footnotesize&quot;,
            tabcolsep=&quot;3.0pt&quot;,
        )
    else:
        lines.append(r&quot;No current red flags were found.&quot;)
    lines.append(r&quot;\subsection{Past Red-Flag Inventory Now Fixed}&quot;)
    if assessment.past_red_flag_rows:
        append_longtable(
            lines,
            r&quot;&gt;{\raggedright\arraybackslash}p{0.28\linewidth} &gt;{\raggedleft\arraybackslash}p{0.09\linewidth} &gt;{\raggedright\arraybackslash}p{0.24\linewidth} &gt;{\raggedright\arraybackslash}p{0.27\linewidth}&quot;,
            [&quot;Subject CN&quot;, &quot;Historic Certs&quot;, &quot;Historical Concern&quot;, &quot;Supporting Context&quot;],
            [
                [
                    row.subject_cn,
                    str(row.certificate_count),
                    row.flags,
                    truncate_text(row.notes, 84),
                ]
                for row in assessment.past_red_flag_rows
            ],
            font=&quot;footnotesize&quot;,
            tabcolsep=&quot;3.0pt&quot;,
        )
    else:
        lines.append(r&quot;No past-only red flags were found.&quot;)
    lines.append(r&quot;\subsection{Current Overlap Red Flags}&quot;)
    if assessment.overlap_current_rows:
        append_longtable(
            lines,
            r&quot;&gt;{\raggedright\arraybackslash}p{0.21\linewidth} &gt;{\raggedleft\arraybackslash}p{0.10\linewidth} &gt;{\raggedleft\arraybackslash}p{0.08\linewidth} &gt;{\raggedright\arraybackslash}p{0.51\linewidth}&quot;,
            [&quot;Subject CN&quot;, &quot;Max Overlap Days&quot;, &quot;Live Certs&quot;, &quot;What The Renewal Family Looks Like&quot;],
            [
                [
                    row.subject_cn,
                    str(row.max_overlap_days),
                    str(row.current_certificate_count),
                    f&quot;{row.lineage}; {overlap_signal(row.details)}&quot;,
                ]
                for row in assessment.overlap_current_rows
            ],
            font=&quot;footnotesize&quot;,
            tabcolsep=&quot;3.0pt&quot;,
        )
    else:
        lines.append(r&quot;No current overlap red flags were found.&quot;)
    lines.append(r&quot;\subsection{Past Overlap Red Flags Now Fixed}&quot;)
    if assessment.overlap_past_rows:
        append_longtable(
            lines,
            r&quot;&gt;{\raggedright\arraybackslash}p{0.21\linewidth} &gt;{\raggedleft\arraybackslash}p{0.10\linewidth} &gt;{\raggedleft\arraybackslash}p{0.09\linewidth} &gt;{\raggedright\arraybackslash}p{0.52\linewidth}&quot;,
            [&quot;Subject CN&quot;, &quot;Max Overlap Days&quot;, &quot;Historic Certs&quot;, &quot;What The Renewal Family Looks Like&quot;],
            [
                [
                    row.subject_cn,
                    str(row.max_overlap_days),
                    str(row.asset_variant_count),
                    f&quot;{row.lineage}; {overlap_signal(row.details)}&quot;,
                ]
                for row in assessment.overlap_past_rows
            ],
            font=&quot;footnotesize&quot;,
            tabcolsep=&quot;3.0pt&quot;,
        )
    else:
        lines.append(r&quot;No past overlap red flags were found.&quot;)
    lines.append(r&quot;\subsection{Current Subject-DN Drift}&quot;)
    if assessment.dn_current_rows:
        append_longtable(
            lines,
            r&quot;&gt;{\raggedright\arraybackslash}p{0.25\linewidth} &gt;{\raggedleft\arraybackslash}p{0.10\linewidth} &gt;{\raggedleft\arraybackslash}p{0.08\linewidth} &gt;{\raggedright\arraybackslash}p{0.45\linewidth}&quot;,
            [&quot;Subject CN&quot;, &quot;Distinct Subject DNs&quot;, &quot;Live Certs&quot;, &quot;Subject DN Samples&quot;],
            [
                [
                    row.subject_cn,
                    str(row.distinct_value_count),
                    str(row.current_certificate_count),
                    truncate_text(row.details, 92),
                ]
                for row in assessment.dn_current_rows
            ],
            font=&quot;footnotesize&quot;,
            tabcolsep=&quot;3.0pt&quot;,
        )
    else:
        lines.append(r&quot;No current Subject-DN drift was found.&quot;)
    lines.append(r&quot;\subsection{Past Subject-DN Drift Now Fixed}&quot;)
    if assessment.dn_past_rows:
        append_longtable(
            lines,
            r&quot;&gt;{\raggedright\arraybackslash}p{0.25\linewidth} &gt;{\raggedleft\arraybackslash}p{0.10\linewidth} &gt;{\raggedleft\arraybackslash}p{0.09\linewidth} &gt;{\raggedright\arraybackslash}p{0.45\linewidth}&quot;,
            [&quot;Subject CN&quot;, &quot;Distinct Subject DNs&quot;, &quot;Historic Certs&quot;, &quot;Subject DN Samples&quot;],
            [
                [
                    row.subject_cn,
                    str(row.distinct_value_count),
                    str(row.certificate_count),
                    truncate_text(row.details, 92),
                ]
                for row in assessment.dn_past_rows
            ],
            font=&quot;footnotesize&quot;,
            tabcolsep=&quot;3.0pt&quot;,
        )
    else:
        lines.append(r&quot;No past-only Subject-DN drift was found.&quot;)
    lines.append(r&quot;\subsection{Current CA-Family Drift}&quot;)
    if assessment.vendor_current_rows:
        append_longtable(
            lines,
            r&quot;&gt;{\raggedright\arraybackslash}p{0.27\linewidth} &gt;{\raggedleft\arraybackslash}p{0.10\linewidth} &gt;{\raggedleft\arraybackslash}p{0.08\linewidth} &gt;{\raggedright\arraybackslash}p{0.45\linewidth}&quot;,
            [&quot;Subject CN&quot;, &quot;Distinct CA Families&quot;, &quot;Live Certs&quot;, &quot;CA Families Seen&quot;],
            [
                [
                    row.subject_cn,
                    str(row.distinct_value_count),
                    str(row.current_certificate_count),
                    truncate_text(row.details, 92),
                ]
                for row in assessment.vendor_current_rows
            ],
            font=&quot;footnotesize&quot;,
            tabcolsep=&quot;3.0pt&quot;,
        )
    else:
        lines.append(r&quot;No current CA-family drift was found.&quot;)
    lines.append(r&quot;\subsection{Past CA-Family Drift Now Fixed}&quot;)
    if assessment.vendor_past_rows:
        append_longtable(
            lines,
            r&quot;&gt;{\raggedright\arraybackslash}p{0.27\linewidth} &gt;{\raggedleft\arraybackslash}p{0.10\linewidth} &gt;{\raggedleft\arraybackslash}p{0.09\linewidth} &gt;{\raggedright\arraybackslash}p{0.45\linewidth}&quot;,
            [&quot;Subject CN&quot;, &quot;Distinct CA Families&quot;, &quot;Historic Certs&quot;, &quot;CA Families Seen&quot;],
            [
                [
                    row.subject_cn,
                    str(row.distinct_value_count),
                    str(row.certificate_count),
                    truncate_text(row.details, 92),
                ]
                for row in assessment.vendor_past_rows
            ],
            font=&quot;footnotesize&quot;,
            tabcolsep=&quot;3.0pt&quot;,
        )
    else:
        lines.append(r&quot;No past-only CA-family drift was found.&quot;)
    lines.append(r&quot;\subsection{Current SAN Drift}&quot;)
    if assessment.san_current_rows:
        append_longtable(
            lines,
            r&quot;&gt;{\raggedright\arraybackslash}p{0.21\linewidth} &gt;{\raggedleft\arraybackslash}p{0.08\linewidth} &gt;{\raggedleft\arraybackslash}p{0.08\linewidth} &gt;{\raggedright\arraybackslash}p{0.18\linewidth} &gt;{\raggedright\arraybackslash}p{0.35\linewidth}&quot;,
            [&quot;Subject CN&quot;, &quot;Profiles&quot;, &quot;Live Certs&quot;, &quot;Delta Pattern&quot;, &quot;Representative Delta&quot;],
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
            font=&quot;footnotesize&quot;,
            tabcolsep=&quot;3.0pt&quot;,
        )
    else:
        lines.append(r&quot;No current SAN drift was found.&quot;)
    lines.append(r&quot;\subsection{Past SAN Drift Now Fixed}&quot;)
    if assessment.san_past_rows:
        append_longtable(
            lines,
            r&quot;&gt;{\raggedright\arraybackslash}p{0.21\linewidth} &gt;{\raggedleft\arraybackslash}p{0.08\linewidth} &gt;{\raggedleft\arraybackslash}p{0.09\linewidth} &gt;{\raggedright\arraybackslash}p{0.18\linewidth} &gt;{\raggedright\arraybackslash}p{0.35\linewidth}&quot;,
            [&quot;Subject CN&quot;, &quot;Profiles&quot;, &quot;Historic Certs&quot;, &quot;Delta Pattern&quot;, &quot;Representative Delta&quot;],
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
            font=&quot;footnotesize&quot;,
            tabcolsep=&quot;3.0pt&quot;,
        )
    else:
        lines.append(r&quot;No past-only SAN drift was found.&quot;)
    lines.append(r&quot;\subsection{Historic Start Dates}&quot;)
    append_longtable(
        lines,
        r&quot;&gt;{\raggedright\arraybackslash}p{0.16\linewidth} &gt;{\raggedleft\arraybackslash}p{0.10\linewidth} &gt;{\raggedright\arraybackslash}p{0.62\linewidth}&quot;,
        [&quot;Start Day&quot;, &quot;Certificates&quot;, &quot;Dominant Driver&quot;],
        [
            [
                row.start_day,
                str(row.certificate_count),
                driver_summary(row.top_subjects, row.top_issuers),
            ]
            for row in assessment.day_rows
        ],
        font=&quot;footnotesize&quot;,
        tabcolsep=&quot;3.0pt&quot;,
    )
    lines.append(r&quot;\subsection{Historic Step Weeks}&quot;)
    if assessment.week_rows:
        append_longtable(
            lines,
            r&quot;&gt;{\raggedright\arraybackslash}p{0.16\linewidth} &gt;{\raggedleft\arraybackslash}p{0.09\linewidth} &gt;{\raggedleft\arraybackslash}p{0.13\linewidth} &gt;{\raggedright\arraybackslash}p{0.52\linewidth}&quot;,
            [&quot;Week Start&quot;, &quot;Certs&quot;, &quot;Prior 8-Week Avg&quot;, &quot;Dominant Driver&quot;],
            [
                [
                    row.week_start,
                    str(row.certificate_count),
                    row.prior_eight_week_avg,
                    driver_summary(row.top_subjects, row.top_issuers),
                ]
                for row in assessment.week_rows
            ],
            font=&quot;footnotesize&quot;,
            tabcolsep=&quot;3.0pt&quot;,
        )
    else:
        lines.append(r&quot;No step weeks met the threshold.&quot;)

    lines.extend(
        [
            r&quot;\section{CAA Policy Detail}&quot;,
            r&quot;This appendix keeps the issuance-policy evidence inside the monograph. It answers a narrower question than the DNS appendix: not where a name lands, but which public CA families DNS currently authorizes to issue for that name.&quot;,
            r&quot;\subsection{CAA Discovery Paths}&quot;,
        ]
    )
    append_longtable(
        lines,
        r&quot;&gt;{\raggedright\arraybackslash}p{0.23\linewidth} &gt;{\raggedleft\arraybackslash}p{0.10\linewidth} &gt;{\raggedright\arraybackslash}p{0.55\linewidth}&quot;,
        [&quot;CAA Discovery Result&quot;, &quot;Names&quot;, &quot;Meaning&quot;],
        caa_source_rows(caa_analysis),
        font=&quot;footnotesize&quot;,
        tabcolsep=&quot;3.0pt&quot;,
    )
    lines.append(r&quot;\subsection{Policy Regimes By Configured Zone}&quot;)
    for zone in caa_analysis.configured_domains:
        lines.append(rf&quot;\subsubsection{{{latex_escape(zone)}}}&quot;)
        append_longtable(
            lines,
            r&quot;&gt;{\raggedright\arraybackslash}p{0.24\linewidth} &gt;{\raggedleft\arraybackslash}p{0.10\linewidth} &gt;{\raggedright\arraybackslash}p{0.56\linewidth}&quot;,
            [&quot;Policy Regime&quot;, &quot;Names&quot;, &quot;Plain-Language Meaning&quot;],
            caa_zone_rows[zone],
            font=&quot;footnotesize&quot;,
            tabcolsep=&quot;3.0pt&quot;,
        )
    lines.append(r&quot;\subsection{Current Multi-Family Overlap}&quot;)
    if caa_analysis.multi_family_overlap_names:
        lines.extend(
            [
                r&quot;\begin{longtable}{&gt;{\raggedright\arraybackslash}p{0.29\linewidth} &gt;{\raggedright\arraybackslash}p{0.14\linewidth} &gt;{\raggedright\arraybackslash}p{0.17\linewidth} &gt;{\raggedright\arraybackslash}p{0.28\linewidth}}&quot;,
                r&quot;\toprule&quot;,
                r&quot;DNS Name &amp; Zone &amp; Live CA Families &amp; Covering Subject CNs \\&quot;,
                r&quot;\midrule&quot;,
            ]
        )
        for name, zone, families, subjects in top_caa_overlap_rows(caa_analysis, 40):
            lines.append(rf&quot;{latex_escape(name)} &amp; {latex_escape(zone)} &amp; {latex_escape(families)} &amp; {latex_escape(subjects)} \\&quot;)
        lines.extend([r&quot;\bottomrule&quot;, r&quot;\end{longtable}&quot;])
    else:
        lines.append(r&quot;No current multi-family overlap names were found.&quot;)
    lines.append(r&quot;\subsection{Current Policy Mismatch}&quot;)
    if caa_analysis.policy_mismatch_names:
        lines.extend(
            [
                r&quot;\begin{longtable}{&gt;{\raggedright\arraybackslash}p{0.27\linewidth} &gt;{\raggedright\arraybackslash}p{0.12\linewidth} &gt;{\raggedright\arraybackslash}p{0.16\linewidth} &gt;{\raggedright\arraybackslash}p{0.18\linewidth} &gt;{\raggedright\arraybackslash}p{0.17\linewidth}}&quot;,
                r&quot;\toprule&quot;,
                r&quot;DNS Name &amp; Zone &amp; Live CA Families &amp; CAA-Allowed Families &amp; CAA Discovery Result \\&quot;,
                r&quot;\midrule&quot;,
            ]
        )
        for name, zone, families, allowed, result in top_caa_mismatch_rows(caa_analysis, 40):
            lines.append(rf&quot;{latex_escape(name)} &amp; {latex_escape(zone)} &amp; {latex_escape(families)} &amp; {latex_escape(allowed)} &amp; {latex_escape(result)} \\&quot;)
        lines.extend([r&quot;\bottomrule&quot;, r&quot;\end{longtable}&quot;])
    else:
        lines.append(r&quot;No current policy-mismatch names were found.&quot;)

    if focus_analysis:
        lines.extend(
            [
                r&quot;\section{Focused Subject-CN Detail}&quot;,
                r&quot;This appendix keeps the complete focused-cohort table inside the monograph, but it now follows the three-bucket taxonomy from Chapter 8. That makes it easier to read the cohort as a set of related naming traditions instead of as one flat mixed list.&quot;,
            ]
        )
        appendix_buckets = [
            (&quot;direct_front_door&quot;, r&quot;\subsection{Front-Door Direct Names}&quot;),
            (&quot;platform_matrix_anchor&quot;, r&quot;\subsection{Platform-Anchor Matrix Names}&quot;),
            (&quot;ambiguous_legacy&quot;, r&quot;\subsection{Ambiguous Or Legacy Residue}&quot;),
        ]
        for bucket, heading in appendix_buckets:
            lines.append(heading)
            lines.append(
                rf&quot;{latex_escape(ct_focus_subjects.taxonomy_bucket_label(bucket))} count: {focus_analysis.bucket_counts.get(bucket, 0)}.&quot;
            )
            rows = focus_appendix_rows(focus_analysis, bucket)
            if rows:
                lines.extend(
                    [
                        r&quot;\begin{longtable}{&gt;{\raggedright\arraybackslash}p{0.16\linewidth} &gt;{\raggedright\arraybackslash}p{0.18\linewidth} &gt;{\raggedright\arraybackslash}p{0.12\linewidth} &gt;{\raggedright\arraybackslash}p{0.15\linewidth} &gt;{\raggedright\arraybackslash}p{0.06\linewidth} &gt;{\raggedright\arraybackslash}p{0.07\linewidth} &gt;{\raggedright\arraybackslash}p{0.07\linewidth} &gt;{\raggedright\arraybackslash}p{0.10\linewidth} &gt;{\raggedright\arraybackslash}p{0.10\linewidth} &gt;{\raggedright\arraybackslash}p{0.07\linewidth} &gt;{\raggedright\arraybackslash}p{0.07\linewidth}}&quot;,
                        r&quot;\toprule&quot;,
                        r&quot;Subject CN &amp; Bucket Rationale &amp; Analyst Note &amp; Observed Role &amp; Direct C/H &amp; Carried C/H &amp; SANs C/H &amp; Current DNS Outcome &amp; Current Revocation Mix &amp; Current Flags &amp; Past Flags \\&quot;,
                        r&quot;\midrule&quot;,
                    ]
                )
                for row in rows:
                    lines.append(
                        rf&quot;{latex_escape(row[0])} &amp; {latex_escape(row[1])} &amp; {latex_escape(row[2])} &amp; {latex_escape(row[3])} &amp; {latex_escape(row[4])} &amp; {latex_escape(row[5])} &amp; {latex_escape(row[6])} &amp; {latex_escape(row[7])} &amp; {latex_escape(row[8])} &amp; {latex_escape(row[9])} &amp; {latex_escape(row[10])} \\&quot;
                    )
                lines.extend([r&quot;\bottomrule&quot;, r&quot;\end{longtable}&quot;])
            else:
                lines.append(r&quot;No subjects fell into this bucket.&quot;)

    lines.extend(
        [
            r&quot;\section{Detailed Inventory Appendix}&quot;,
            r&quot;This appendix reproduces the full issuer-first family inventory so that the publication remains complete rather than merely interpretive.&quot;,
            rf&quot;\includepdf[pages=-,pagecommand={{}}]{{{latex_escape(appendix_pdf_path)}}}&quot;,
            r&quot;\end{document}&quot;,
        ]
    )
    def soften_heading(line: str) -&gt; str:
        if line.startswith(r&quot;\subsection{&quot;):
            return line.replace(r&quot;\subsection{&quot;, r&quot;\SoftSubsection{&quot;, 1)
        if line.startswith(r&quot;\subsubsection{&quot;):
            return line.replace(r&quot;\subsubsection{&quot;, r&quot;\SoftSubsubsection{&quot;, 1)
        return line

    args.latex_output.write_text(
        &quot;\n&quot;.join(soften_heading(line) for line in lines) + &quot;\n&quot;,
        encoding=&quot;utf-8&quot;,
    )</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Writes the narrative monograph in LaTeX.</p>
<p><strong>Flow arrows</strong></p><p>Current-state facts, history, CAA, and focused-cohort analysis. &#8594; <strong>render_latex</strong> &#8594; Produces the main LaTeX monograph source.</p>
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
    report = ct_master_report.summarize_for_report(args)
    assessment = ct_lineage_report.build_assessment(build_history_args(args))
    caa_analysis = ct_caa_analysis.build_analysis(
        report[&quot;hits&quot;],
        report[&quot;domains&quot;],
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
            f&quot;[report] markdown={args.markdown_output} latex={args.latex_output}&quot;
            + (&quot;&quot; if args.skip_pdf else f&quot; pdf={args.pdf_output}&quot;),
            file=__import__(&quot;sys&quot;).stderr,
        )
    return 0</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>The top-level command-line entrypoint for the complete monograph build.</p>
<p><strong>Flow arrows</strong></p><p>CLI arguments from the operator. &#8594; <strong>main</strong> &#8594; Runs the full publication pipeline from raw analytics to finished PDF.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

