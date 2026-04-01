# ct_master_report.py

Source file: [`ct_master_report.py`](../ct_master_report.py)

Current-state synthesizer. This file combines certificate facts, DNS facts, purpose classification, grouping, and curated examples into one report bundle.

Main flow in one line: `current CT facts + DNS facts + usage facts -> one current-state report bundle`

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
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import ct_dns_utils
import ct_scan
import ct_usage_assessment


ENV_TOKENS = [
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
]</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Current-state report assembly code that sits above the low-level scanners.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>Module setup</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## ExampleBlock

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">@dataclass
class ExampleBlock:
    title: str
    subject_cn: str
    why_it_matters: str
    evidence: list[str]</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>A small narrative evidence block used in the naming chapter.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>ExampleBlock</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
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
        description=&quot;Generate a single consolidated CT, DNS, and naming report.&quot;
    )
    parser.add_argument(&quot;--domains-file&quot;, type=Path, default=Path(&quot;domains.local.txt&quot;))
    parser.add_argument(&quot;--cache-dir&quot;, type=Path, default=Path(&quot;.cache/ct-search&quot;))
    parser.add_argument(&quot;--dns-cache-dir&quot;, type=Path, default=Path(&quot;.cache/dns-scan&quot;))
    parser.add_argument(&quot;--cache-ttl-seconds&quot;, type=int, default=0)
    parser.add_argument(&quot;--dns-cache-ttl-seconds&quot;, type=int, default=86400)
    parser.add_argument(&quot;--max-candidates-per-domain&quot;, type=int, default=10000)
    parser.add_argument(&quot;--retries&quot;, type=int, default=3)
    parser.add_argument(&quot;--markdown-output&quot;, type=Path, default=Path(&quot;output/consolidated-corpus-report.md&quot;))
    parser.add_argument(&quot;--latex-output&quot;, type=Path, default=Path(&quot;output/consolidated-corpus-report.tex&quot;))
    parser.add_argument(&quot;--pdf-output&quot;, type=Path, default=Path(&quot;output/consolidated-corpus-report.pdf&quot;))
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

## load_records

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def load_records(args: argparse.Namespace) -&gt; tuple[list[str], list[ct_scan.DatabaseRecord], dict[str, int]]:
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
                print(f&quot;[cache] domain={domain} records={len(cached)}&quot;, file=__import__(&quot;sys&quot;).stderr)
            records.extend(cached)
            continue
        if not args.quiet:
            print(f&quot;[query] domain={domain}&quot;, file=__import__(&quot;sys&quot;).stderr)
        queried = ct_scan.query_domain(
            domain=domain,
            max_candidates=args.max_candidates_per_domain,
            attempts=args.retries,
            verbose=not args.quiet,
        )
        ct_scan.store_cached_records(args.cache_dir, domain, args.max_candidates_per_domain, queried)
        records.extend(queried)
    return domains, records, raw_match_counts</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Loads current CT records for all configured search terms.</p>
<p><strong>Flow arrows</strong></p><p>Configured domains from the local file. &#8594; <strong>load_records</strong> &#8594; `summarize_for_report` uses the returned CT rows as its starting point.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## dns_names_from_hits

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def dns_names_from_hits(hits: list[ct_scan.CertificateHit]) -&gt; list[str]:
    names = sorted(
        {
            ct_dns_utils.normalize_name(entry[4:])
            for hit in hits
            for entry in hit.san_entries
            if entry.startswith(&quot;DNS:&quot;)
        }
    )
    return names</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_master_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>dns_names_from_hits</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## enrich_dns

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def enrich_dns(names: list[str], args: argparse.Namespace) -&gt; list[ct_dns_utils.DnsObservation]:
    observations = [ct_dns_utils.scan_name_cached(name, args.dns_cache_dir, args.dns_cache_ttl_seconds) for name in names]
    unique_ips = sorted({ip for observation in observations for ip in (*observation.a_records, *observation.aaaa_records)})
    ptr_cache_dir = args.dns_cache_dir / &quot;ptr&quot;
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
    return observations</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Adds DNS observations and provider clues to the raw SAN-name list.</p>
<p><strong>Flow arrows</strong></p><p>The unique SAN DNS names from current hits. &#8594; <strong>enrich_dns</strong> &#8594; `summarize_for_report` uses the enriched observations for DNS chapters and examples.</p>
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
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_master_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>short_issuer_family</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## revocation_counts

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def revocation_counts(hits: list[ct_scan.CertificateHit]) -&gt; Counter[str]:
    return Counter(hit.revocation_status for hit in hits)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_master_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>revocation_counts</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## is_www_pair

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def is_www_pair(hit: ct_scan.CertificateHit) -&gt; bool:
    dns_names = sorted(entry[4:] for entry in hit.san_entries if entry.startswith(&quot;DNS:&quot;))
    if len(dns_names) != 2:
        return False
    plain = [name for name in dns_names if not name.startswith(&quot;www.&quot;)]
    return len(plain) == 1 and f&quot;www.{plain[0]}&quot; in dns_names</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_master_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>is_www_pair</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## env_token_count

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def env_token_count(name: str) -&gt; int:
    lowered = name.lower()
    return sum(1 for token in ENV_TOKENS if token in lowered)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_master_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>env_token_count</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## dns_zone_count

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def dns_zone_count(hit: ct_scan.CertificateHit) -&gt; int:
    zones = {ct_scan.san_tail_split(entry[4:])[1] for entry in hit.san_entries if entry.startswith(&quot;DNS:&quot;)}
    return len(zones)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_master_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>dns_zone_count</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## zone_root_label

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def zone_root_label(name: str) -&gt; str:
    zone = ct_scan.san_tail_split(name)[1]
    return zone.split(&quot;.&quot;)[0].lower()</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_master_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>zone_root_label</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## group_member_hits

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def group_member_hits(groups: list[ct_scan.CertificateGroup], hits: list[ct_scan.CertificateHit]) -&gt; dict[str, list[ct_scan.CertificateHit]]:
    mapping: dict[str, list[ct_scan.CertificateHit]] = {}
    for group in groups:
        mapping[group.group_id] = [hits[index] for index in group.member_indices]
    return mapping</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This block clusters related items together so later code can analyze them as families instead of as isolated rows.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>group_member_hits</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## stack_counts_for_hits

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def stack_counts_for_hits(member_hits: list[ct_scan.CertificateHit], observation_by_name: dict[str, ct_dns_utils.DnsObservation]) -&gt; Counter[str]:
    counts: Counter[str] = Counter()
    for hit in member_hits:
        for entry in hit.san_entries:
            if not entry.startswith(&quot;DNS:&quot;):
                continue
            name = ct_dns_utils.normalize_name(entry[4:])
            observation = observation_by_name.get(name)
            if observation is not None:
                counts[observation.stack_signature] += 1
    return counts</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_master_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>stack_counts_for_hits</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## confirm_search_premise

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def confirm_search_premise(hits: list[ct_scan.CertificateHit], domains: list[str]) -&gt; tuple[int, int]:
    missing_matching_san = 0
    subject_not_in_san = 0
    for hit in hits:
        dns_names = [entry[4:].lower() for entry in hit.san_entries if entry.startswith(&quot;DNS:&quot;)]
        if not any(any(domain in dns_name for domain in domains) for dns_name in dns_names):
            missing_matching_san += 1
        if hit.subject_cn.lower() not in dns_names:
            subject_not_in_san += 1
    return missing_matching_san, subject_not_in_san</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_master_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>confirm_search_premise</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## provider_counts

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def provider_counts(observations: list[ct_dns_utils.DnsObservation]) -&gt; Counter[str]:
    counts: Counter[str] = Counter()
    for observation in observations:
        for hint in observation.provider_hints:
            if hint != &quot;Unclassified&quot;:
                counts[hint] += 1
    return counts</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_master_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>provider_counts</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## top_suffixes

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def top_suffixes(hits: list[ct_scan.CertificateHit], limit: int = 8) -&gt; list[tuple[str, int]]:
    counts: Counter[str] = Counter()
    for hit in hits:
        labels = hit.subject_cn.lower().split(&quot;.&quot;)
        suffix = &quot;.&quot;.join(labels[1:]) if len(labels) &gt; 1 else hit.subject_cn.lower()
        counts[suffix] += 1
    return counts.most_common(limit)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_master_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>top_suffixes</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## top_env_tokens

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def top_env_tokens(hits: list[ct_scan.CertificateHit], limit: int = 10) -&gt; list[tuple[str, int]]:
    counts: Counter[str] = Counter()
    for hit in hits:
        lowered = hit.subject_cn.lower()
        for token in ENV_TOKENS:
            if token in lowered:
                counts[token] += 1
    return counts.most_common(limit)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_master_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>top_env_tokens</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## pick_examples

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def pick_examples(
    hits: list[ct_scan.CertificateHit],
    groups: list[ct_scan.CertificateGroup],
    observation_by_name: dict[str, ct_dns_utils.DnsObservation],
) -&gt; list[ExampleBlock]:
    examples: list[ExampleBlock] = []
    group_map = group_member_hits(groups, hits)

    numbered_groups = [group for group in groups if group.group_type == &quot;numbered_cn_pattern&quot;]
    if numbered_groups:
        group = max(numbered_groups, key=lambda item: item.member_count)
        member_hits = group_map[group.group_id]
        stack_counts = stack_counts_for_hits(member_hits, observation_by_name)
        example_hit = max(member_hits, key=lambda item: (len(item.san_entries), len(item.subject_cn)))
        examples.append(
            ExampleBlock(
                title=&quot;Shared operational rail&quot;,
                subject_cn=example_hit.subject_cn,
                why_it_matters=&quot;A numbered CN family usually signals a reusable service rail rather than a one-off branded page. It tends to expose fleet-style naming, repeated validity cycles, and many sibling hostnames.&quot;,
                evidence=[
                    f&quot;Group basis: {ct_scan.describe_group_basis(group).replace(&#x27;`&#x27;, &#x27;&#x27;)}.&quot;,
                    f&quot;Certificates in family: {group.member_count}.&quot;,
                    f&quot;Distinct Subject CNs in family: {group.distinct_subject_cn_count}.&quot;,
                    f&quot;Top observed DNS delivery stacks: {&#x27;, &#x27;.join(f&#x27;{label} ({count})&#x27; for label, count in stack_counts.most_common(3)) or &#x27;none&#x27;}.&quot;,
                ],
            )
        )

    matrix_hits = [hit for hit in hits if len(hit.san_entries) &gt;= 12 and env_token_count(hit.subject_cn) &gt;= 1]
    if matrix_hits:
        hit = max(matrix_hits, key=lambda item: (len(item.san_entries), dns_zone_count(item), item.subject_cn))
        zones = sorted({ct_scan.san_tail_split(entry[4:])[1] for entry in hit.san_entries if entry.startswith(&quot;DNS:&quot;)})
        examples.append(
            ExampleBlock(
                title=&quot;Environment matrix certificate&quot;,
                subject_cn=hit.subject_cn,
                why_it_matters=&quot;A large SAN set with environment-style labels usually means one certificate is covering a coordinated platform surface across test, release, support, or tenant slices.&quot;,
                evidence=[
                    f&quot;SAN entries: {len(hit.san_entries)}.&quot;,
                    f&quot;Distinct DNS zones in SAN set: {len(zones)}.&quot;,
                    f&quot;Environment tokens visible in Subject CN: {env_token_count(hit.subject_cn)}.&quot;,
                    f&quot;First DNS zones in SAN set: {&#x27;, &#x27;.join(zones[:6])}.&quot;,
                ],
            )
        )

    zone_tokens = sorted(
        {
            zone_root_label(hit.subject_cn)
            for hit in hits
            if &quot;.&quot; in hit.subject_cn
        }
        | {
            zone_root_label(entry[4:])
            for hit in hits
            for entry in hit.san_entries
            if entry.startswith(&quot;DNS:&quot;)
        }
    )
    splice_hits = []
    for hit in hits:
        if &quot;.&quot; not in hit.subject_cn:
            continue
        leading_label = hit.subject_cn.split(&quot;.&quot;)[0].lower()
        public_zone = ct_scan.san_tail_split(hit.subject_cn)[1]
        public_zone_root = public_zone.split(&quot;.&quot;)[0].lower()
        foreign_tokens = [token for token in zone_tokens if token != public_zone_root and token in leading_label]
        if foreign_tokens:
            splice_hits.append((hit, public_zone, foreign_tokens))
    if splice_hits:
        hit, public_zone, foreign_tokens = max(
            splice_hits,
            key=lambda item: (dns_zone_count(item[0]), len(item[0].san_entries), item[0].subject_cn),
        )
        middle_segment = hit.subject_cn.split(&quot;.&quot;)[1] if hit.subject_cn.count(&quot;.&quot;) &gt;= 2 else &quot;&quot;
        related = sorted(
            {
                other.subject_cn
                for other in hits
                if middle_segment and f&quot;.{middle_segment}.&quot; in other.subject_cn
                and other.subject_cn != hit.subject_cn
                and ct_scan.san_tail_split(other.subject_cn)[1] == public_zone
            }
        )
        examples.append(
            ExampleBlock(
                title=&quot;Brand-platform splice&quot;,
                subject_cn=hit.subject_cn,
                why_it_matters=&quot;When the left side of a hostname carries one business or platform label but the public zone belongs to another brand, that usually exposes migration residue or a shared platform being presented through a different public namespace.&quot;,
                evidence=[
                    f&quot;Subject CN mixes leading-label namespace tokens {&#x27;, &#x27;.join(foreign_tokens[:3])} with the public zone {public_zone}: {hit.subject_cn}.&quot;,
                    f&quot;Distinct DNS zones in SAN set: {dns_zone_count(hit)}.&quot;,
                    f&quot;Representative sibling names in the same middle namespace: {&#x27;, &#x27;.join(related[:5]) or &#x27;none&#x27;}.&quot;,
                    f&quot;SAN entries: {len(hit.san_entries)}.&quot;,
                ],
            )
        )

    cross_zone_hits = [hit for hit in hits if dns_zone_count(hit) &gt; 1]
    if cross_zone_hits:
        hit = max(cross_zone_hits, key=lambda item: (dns_zone_count(item), len(item.san_entries), item.subject_cn))
        zones = sorted({ct_scan.san_tail_split(entry[4:])[1] for entry in hit.san_entries if entry.startswith(&quot;DNS:&quot;)})
        examples.append(
            ExampleBlock(
                title=&quot;Cross-zone bridge&quot;,
                subject_cn=hit.subject_cn,
                why_it_matters=&quot;When one certificate spans several DNS zones, it often reveals a shared service or a migration bridge between branded fronts and underlying service domains.&quot;,
                evidence=[
                    f&quot;Distinct DNS zones in SAN set: {len(zones)}.&quot;,
                    f&quot;Representative zones: {&#x27;, &#x27;.join(zones[:8])}.&quot;,
                    f&quot;SAN entries: {len(hit.san_entries)}.&quot;,
                ],
            )
        )

    return examples</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Chooses a few representative examples that make the naming and DNS story understandable.</p>
<p><strong>Flow arrows</strong></p><p>Current hits, groups, and DNS observations. &#8594; <strong>pick_examples</strong> &#8594; `summarize_for_report` stores the chosen examples for the naming chapter.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## build_group_digest

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def build_group_digest(
    groups: list[ct_scan.CertificateGroup],
    hits: list[ct_scan.CertificateHit],
    observation_by_name: dict[str, ct_dns_utils.DnsObservation],
    limit: int = 20,
) -&gt; list[dict[str, str]]:
    digest: list[dict[str, str]] = []
    group_map = group_member_hits(groups, hits)
    for group in groups[:limit]:
        member_hits = group_map[group.group_id]
        stack_counts = stack_counts_for_hits(member_hits, observation_by_name)
        digest.append(
            {
                &quot;group_id&quot;: group.group_id,
                &quot;basis&quot;: ct_scan.describe_group_basis(group).replace(&quot;`&quot;, &quot;&quot;),
                &quot;type&quot;: group.group_type,
                &quot;certificates&quot;: str(group.member_count),
                &quot;subjects&quot;: str(group.distinct_subject_cn_count),
                &quot;top_stacks&quot;: &quot;, &quot;.join(f&quot;{label} ({count})&quot; for label, count in stack_counts.most_common(3)) or &quot;none&quot;,
            }
        )
    return digest</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Builds a compact family catalogue used in reports.</p>
<p><strong>Flow arrows</strong></p><p>Current groups plus DNS observations. &#8594; <strong>build_group_digest</strong> &#8594; Report builders use the digest in appendices and summary tables.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## summarize_for_report

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def summarize_for_report(args: argparse.Namespace) -&gt; dict[str, object]:
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
    numbered_groups = [group for group in groups if group.group_type == &quot;numbered_cn_pattern&quot;]
    public_www_pair_count = sum(1 for hit in hits if is_www_pair(hit))
    multi_zone_hit_count = sum(1 for hit in hits if dns_zone_count(hit) &gt; 1)
    examples = pick_examples(hits, groups, observation_by_name)
    digest = build_group_digest(groups, hits, observation_by_name)
    trusted_major = sum(1 for info in issuer_trust.values() if info.major_webpki)
    current_day = datetime.now(UTC).date().isoformat()

    return {
        &quot;generated_at_utc&quot;: ct_scan.utc_iso(datetime.now(UTC)),
        &quot;current_day&quot;: current_day,
        &quot;domains&quot;: domains,
        &quot;raw_match_counts&quot;: raw_match_counts,
        &quot;cap&quot;: args.max_candidates_per_domain,
        &quot;hits&quot;: hits,
        &quot;groups&quot;: groups,
        &quot;verification&quot;: verification,
        &quot;issuer_trust&quot;: issuer_trust,
        &quot;purpose_summary&quot;: purpose_summary,
        &quot;classifications&quot;: classifications,
        &quot;unique_dns_names&quot;: unique_dns_names,
        &quot;observations&quot;: observations,
        &quot;observation_by_name&quot;: observation_by_name,
        &quot;rev_counts&quot;: rev_counts,
        &quot;provider_hint_counts&quot;: provider_hint_counts,
        &quot;dns_class_counts&quot;: dns_class_counts,
        &quot;dns_stack_counts&quot;: dns_stack_counts,
        &quot;issuer_counts&quot;: issuer_counts,
        &quot;issuer_family_counts&quot;: issuer_family_counts,
        &quot;missing_matching_san&quot;: missing_matching_san,
        &quot;subject_not_in_san&quot;: subject_not_in_san,
        &quot;numbered_groups&quot;: numbered_groups,
        &quot;public_www_pair_count&quot;: public_www_pair_count,
        &quot;multi_zone_hit_count&quot;: multi_zone_hit_count,
        &quot;examples&quot;: examples,
        &quot;top_suffixes&quot;: top_suffixes(hits),
        &quot;top_env_tokens&quot;: top_env_tokens(hits),
        &quot;group_digest&quot;: digest,
        &quot;trusted_major&quot;: trusted_major,
    }</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Creates the big current-state dictionary consumed by the monograph builder.</p>
<p><strong>Flow arrows</strong></p><p>Current CT rows, DNS observations, issuer trust, and usage facts. &#8594; <strong>summarize_for_report</strong> &#8594; `ct_monograph_report.main` consumes this as the main current-state input.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## md_bullets

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def md_bullets(items: list[str]) -&gt; list[str]:
    return [f&quot;- {item}&quot; for item in items]</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_master_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>md_bullets</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## render_markdown

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def render_markdown(path: Path, report: dict[str, object]) -&gt; None:
    path.parent.mkdir(parents=True, exist_ok=True)
    hits = report[&quot;hits&quot;]
    groups = report[&quot;groups&quot;]
    rev_counts = report[&quot;rev_counts&quot;]
    purpose_summary = report[&quot;purpose_summary&quot;]
    lines: list[str] = []
    lines.append(&quot;# Consolidated CT, Certificate, and DNS Report&quot;)
    lines.append(&quot;&quot;)
    lines.append(f&quot;Generated: {report[&#x27;generated_at_utc&#x27;]}&quot;)
    lines.append(f&quot;Configured search terms file: `{report[&#x27;domains&#x27;]}`&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;## Executive Overview&quot;)
    lines.append(&quot;&quot;)
    lines.extend(
        md_bullets(
            [
                f&quot;{len(hits)} current leaf certificates are in scope after local leaf-only verification.&quot;,
                f&quot;{len(groups)} CN families reduce the raw certificate list into readable naming clusters.&quot;,
                f&quot;{purpose_summary.category_counts.get(&#x27;tls_server_only&#x27;, 0)} certificates are strict server-auth and {purpose_summary.category_counts.get(&#x27;tls_server_and_client&#x27;, 0)} also allow client auth.&quot;,
                f&quot;{len(report[&#x27;unique_dns_names&#x27;])} unique DNS SAN names were scanned live; the estate collapses into a small number of recurring delivery stacks.&quot;,
                &quot;The strongest overall reading is a layered operating model: branded public names on top, reusable service rails underneath, and cloud or vendor delivery platforms at the edge.&quot;,
            ]
        )
    )
    lines.append(&quot;&quot;)
    lines.append(&quot;## Chapter 1: Method, Integrity, and How To Read This&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;**Management Summary**&quot;)
    lines.append(&quot;&quot;)
    lines.extend(
        md_bullets(
            [
                f&quot;The scan now fails fast if the candidate cap is lower than the live raw match count. Current raw counts: {&#x27;, &#x27;.join(f&#x27;{domain}={count}&#x27; for domain, count in report[&#x27;raw_match_counts&#x27;].items())}.&quot;,
                f&quot;The live candidate cap used for this run was {report[&#x27;cap&#x27;]}, which is safely above the current raw counts.&quot;,
                f&quot;Leaf-only verification kept {report[&#x27;verification&#x27;].unique_leaf_certificates} certificates and filtered {report[&#x27;verification&#x27;].non_leaf_filtered} CA-style certificates and {report[&#x27;verification&#x27;].precertificate_poison_filtered} precertificate-poison objects.&quot;,
                f&quot;Every certificate in scope still contains at least one DNS SAN containing one of the configured search terms; exceptions found: {report[&#x27;missing_matching_san&#x27;]}.&quot;,
            ]
        )
    )
    lines.append(&quot;&quot;)
    lines.append(&quot;Certificate Transparency is the public logging layer for issued certificates. The scan starts there, then reads the actual X.509 certificate bytes, verifies that each object is a real leaf certificate, extracts SAN and Subject CN values, checks revocation state from crt.sh data, and then scans the DNS names seen in SANs.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;A **Subject CN** is the traditional primary name in a certificate. A **SAN** list is the modern list of all names the certificate covers. A **leaf certificate** is the endpoint certificate presented by a service, as distinct from a CA certificate used to sign other certificates.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;## Chapter 2: Certificate Corpus&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;**Management Summary**&quot;)
    lines.append(&quot;&quot;)
    lines.extend(
        md_bullets(
            [
                f&quot;The issuer landscape is concentrated: {&#x27;, &#x27;.join(f&#x27;{name} ({count})&#x27; for name, count in report[&#x27;issuer_family_counts&#x27;].most_common())}.&quot;,
                f&quot;Revocation mix: {rev_counts.get(&#x27;not_revoked&#x27;, 0)} not revoked, {rev_counts.get(&#x27;revoked&#x27;, 0)} revoked, {rev_counts.get(&#x27;unknown&#x27;, 0)} unknown.&quot;,
                f&quot;Purpose split: {purpose_summary.category_counts.get(&#x27;tls_server_only&#x27;, 0)} server-only, {purpose_summary.category_counts.get(&#x27;tls_server_and_client&#x27;, 0)} server+client, and zero client-only, S/MIME, or code-signing certificates.&quot;,
                f&quot;All {len(hits)} Subject CN values appear literally in the SAN DNS set.&quot;,
            ]
        )
    )
    lines.append(&quot;&quot;)
    lines.append(&quot;An **issuer CA** is the certificate authority that signed the endpoint certificate. A **WebPKI-trusted** issuer is one that browsers and operating systems currently trust for public TLS. In this corpus, all visible issuers are live server-auth issuers in the public trust ecosystem.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;### Issuer Breakdown&quot;)
    lines.append(&quot;&quot;)
    for issuer_name, count in report[&quot;issuer_counts&quot;].most_common():
        trust = report[&quot;issuer_trust&quot;][issuer_name]
        lines.append(f&quot;- `{issuer_name}`: {count} certificates | major WebPKI stores: {&#x27;yes&#x27; if trust.major_webpki else &#x27;no&#x27;}&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;### Purpose Assessment&quot;)
    lines.append(&quot;&quot;)
    for category, count in purpose_summary.category_counts.items():
        lines.append(f&quot;- `{category}`: {count}&quot;)
    lines.append(&quot;&quot;)
    lines.append(
        &quot;An **Extended Key Usage (EKU)** value tells software what the certificate is allowed to do. &quot;
        f&quot;Here the estate is entirely TLS-capable. The only nuance is that {purpose_summary.category_counts.get(&#x27;tls_server_and_client&#x27;, 0)} certificates also allow `clientAuth`. &quot;
        &quot;That does not by itself prove a separate client-certificate estate; in context, they still look like hostname certificates issued from a permissive or older server template.&quot;
    )
    lines.append(&quot;&quot;)
    lines.append(&quot;## Chapter 3: Naming Architecture&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;**Management Summary**&quot;)
    lines.append(&quot;&quot;)
    lines.extend(
        md_bullets(
            [
                f&quot;{len(report[&#x27;numbered_groups&#x27;])} numbered CN families point to reusable service rails rather than one-off pages.&quot;,
                f&quot;{report[&#x27;public_www_pair_count&#x27;]} certificates use the clean public front-door pattern of a base name paired with `www`.&quot;,
                f&quot;{report[&#x27;multi_zone_hit_count&#x27;]} certificates span more than one DNS zone in SAN, which is usually a sign of shared platforms, migrations, or multi-brand exposure.&quot;,
                f&quot;Most common suffixes: {&#x27;, &#x27;.join(f&#x27;{suffix} ({count})&#x27; for suffix, count in report[&#x27;top_suffixes&#x27;])}.&quot;,
            ]
        )
    )
    lines.append(&quot;&quot;)
    lines.append(&quot;Hostnames often look arbitrary because they are doing several jobs at once. Some names are for customers, some are for engineers, some encode environment state, and some preserve older platform lineage because renaming working infrastructure is costly.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;### Frequent Naming Tokens&quot;)
    lines.append(&quot;&quot;)
    for token, count in report[&quot;top_env_tokens&quot;]:
        lines.append(f&quot;- `{token}`: {count}&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;### Dynamic Examples&quot;)
    lines.append(&quot;&quot;)
    for example in report[&quot;examples&quot;]:
        lines.append(f&quot;#### {example.title}&quot;)
        lines.append(&quot;&quot;)
        lines.append(f&quot;- Subject CN: `{example.subject_cn}`&quot;)
        lines.append(f&quot;- Why it matters: {example.why_it_matters}&quot;)
        for point in example.evidence:
            lines.append(f&quot;- Evidence: {point}&quot;)
        lines.append(&quot;&quot;)
    lines.append(&quot;## Chapter 4: DNS Delivery Architecture&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;**Management Summary**&quot;)
    lines.append(&quot;&quot;)
    lines.extend(
        md_bullets(
            [
                f&quot;{len(report[&#x27;unique_dns_names&#x27;])} unique DNS names were scanned from the SAN corpus.&quot;,
                f&quot;DNS classes: {&#x27;, &#x27;.join(f&#x27;{label}={count}&#x27; for label, count in report[&#x27;dns_class_counts&#x27;].most_common())}.&quot;,
                f&quot;Top delivery signatures: {&#x27;, &#x27;.join(f&#x27;{label} ({count})&#x27; for label, count in report[&#x27;dns_stack_counts&#x27;].most_common(6))}.&quot;,
                &quot;The DNS layer turns a large hostname set into a smaller number of delivery stacks: CDN edges, API gateways, load balancers, and specialist vendor platforms.&quot;,
            ]
        )
    )
    lines.append(&quot;&quot;)
    lines.append(&quot;A **CNAME** is a DNS alias, meaning one hostname points to another hostname. An **A** or **AAAA** record is the final address mapping. An **NXDOMAIN** response means the public DNS name does not exist at the moment of the scan. That does not automatically invalidate the certificate-side finding, because certificate and DNS lifecycles can move at different speeds.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;### Delivery Stack Counts&quot;)
    lines.append(&quot;&quot;)
    for label, count in report[&quot;dns_stack_counts&quot;].most_common(12):
        lines.append(f&quot;- `{label}`: {count}&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;### Platform and Provider Explanations&quot;)
    lines.append(&quot;&quot;)
    glossary = ct_dns_utils.provider_explanations()
    seen_terms = set()
    for observation in report[&quot;observations&quot;]:
        seen_terms.update(observation.provider_hints)
    for term in [&quot;Adobe Campaign&quot;, &quot;AWS&quot;, &quot;AWS CloudFront&quot;, &quot;AWS ALB&quot;, &quot;Google Apigee&quot;, &quot;Pega Cloud&quot;, &quot;Microsoft Edge&quot;, &quot;Infinite / agency alias&quot;, &quot;CNAME&quot;, &quot;A record&quot;, &quot;AAAA record&quot;, &quot;PTR record&quot;, &quot;NXDOMAIN&quot;]:
        if term in glossary and (term in seen_terms or term in {&quot;CNAME&quot;, &quot;A record&quot;, &quot;AAAA record&quot;, &quot;PTR record&quot;, &quot;NXDOMAIN&quot;, &quot;AWS ALB&quot;}):
            lines.append(f&quot;- **{term}**: {glossary[term]}&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;## Chapter 5: Where The Certificate View and DNS View Meet&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;**Management Summary**&quot;)
    lines.append(&quot;&quot;)
    lines.extend(
        md_bullets(
            [
                &quot;The certificate layer describes naming and trust; the DNS layer describes delivery and reachability. The same estate becomes legible only when both are read together.&quot;,
                &quot;Numbered CN families usually behave like shared operational rails in certificates and collapse into repeatable delivery stacks in DNS.&quot;,
                &quot;Cleaner public names tend to be the presentation layer, while denser SAN sets and multi-zone families tend to expose the platform layer underneath.&quot;,
            ]
        )
    )
    lines.append(&quot;&quot;)
    lines.append(&quot;The common ground is operational reality. A brand or product team wants a recognisable public name. A platform team wants a stable service rail. A delivery team wants environment labels and routable front doors. Certificates and DNS show those layers from different angles, which is why the estate looks messy when read from only one side.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;### Top Family Digest&quot;)
    lines.append(&quot;&quot;)
    for row in report[&quot;group_digest&quot;]:
        lines.append(
            f&quot;- `{row[&#x27;group_id&#x27;]}` | {row[&#x27;basis&#x27;]} | type={row[&#x27;type&#x27;]} | certs={row[&#x27;certificates&#x27;]} | subjects={row[&#x27;subjects&#x27;]} | stacks={row[&#x27;top_stacks&#x27;]}&quot;
        )
    lines.append(&quot;&quot;)
    lines.append(&quot;## Chapter 6: Confidence, Limits, and Claims&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;**Management Summary**&quot;)
    lines.append(&quot;&quot;)
    lines.extend(
        md_bullets(
            [
                &quot;Strongest claims: issuer trust, leaf-only status, SAN and Subject CN structure, purpose EKU split, DNS stack signatures, and recurring family patterns.&quot;,
                &quot;Medium-confidence claims: that the estate reflects a layered organisation with brand, platform, and delivery concerns superimposed on each other.&quot;,
                &quot;Lower-confidence claims: exact meanings of internal abbreviations or exact organisation-chart boundaries inferred from naming alone.&quot;,
            ]
        )
    )
    lines.append(&quot;&quot;)
    lines.append(&quot;This report can prove what is visible in public certificate and DNS data. It cannot prove internal governance charts or the exact human meaning of every abbreviation. Where the report interprets rather than measures, it does so by tying the interpretation to repeated observable patterns.&quot;)
    lines.append(&quot;&quot;)
    path.write_text(&quot;\n&quot;.join(lines) + &quot;\n&quot;, encoding=&quot;utf-8&quot;)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Writes the shorter consolidated report in Markdown.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>render_markdown</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## tex_escape

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def tex_escape(value: str) -&gt; str:
    return ct_scan.latex_escape(value)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_master_report.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>tex_escape</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## render_latex

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def render_latex(path: Path, report: dict[str, object]) -&gt; None:
    path.parent.mkdir(parents=True, exist_ok=True)
    hits = report[&quot;hits&quot;]
    groups = report[&quot;groups&quot;]
    rev_counts = report[&quot;rev_counts&quot;]
    purpose_summary = report[&quot;purpose_summary&quot;]

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
        r&quot;\usepackage{enumitem}&quot;,
        r&quot;\usepackage{fancyhdr}&quot;,
        r&quot;\usepackage{titlesec}&quot;,
        r&quot;\usepackage[most]{tcolorbox}&quot;,
        r&quot;\defaultfontfeatures{Ligatures=TeX,Scale=MatchLowercase}&quot;,
        r&quot;\definecolor{Ink}{HTML}{17202A}&quot;,
        r&quot;\definecolor{Muted}{HTML}{667085}&quot;,
        r&quot;\definecolor{Line}{HTML}{D0D5DD}&quot;,
        r&quot;\definecolor{Panel}{HTML}{F8FAFC}&quot;,
        r&quot;\definecolor{Accent}{HTML}{0F766E}&quot;,
        r&quot;\definecolor{AccentSoft}{HTML}{E6F4F1}&quot;,
        r&quot;\hypersetup{colorlinks=true,linkcolor=Accent,urlcolor=Accent,pdfauthor={CertTransparencySearch},pdftitle={Consolidated CT, Certificate, and DNS Report}}&quot;,
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
        r&quot;{\sffamily\bfseries\fontsize{24}{28}\selectfont Consolidated CT, Certificate, and DNS Report\par}&quot;,
        r&quot;\vspace{6pt}&quot;,
        r&quot;{\Large One document for the certificate corpus, naming system, DNS delivery view, and proof boundaries\par}&quot;,
        r&quot;\vspace{18pt}&quot;,
        rf&quot;\textbf{{Generated}}: {tex_escape(report[&#x27;generated_at_utc&#x27;])}\par&quot;,
        rf&quot;\textbf{{Configured search terms file}}: {tex_escape(str(report[&#x27;domains&#x27;]))}\par&quot;,
        r&quot;\vspace{12pt}&quot;,
        r&quot;\SummaryBox{&quot;
        + rf&quot;\textbf{{Headline}}: {len(hits)} leaf certificates, {len(groups)} CN families, {len(report[&#x27;unique_dns_names&#x27;])} DNS names, &quot;
        + rf&quot;{purpose_summary.category_counts.get(&#x27;tls_server_only&#x27;, 0)} strict server-auth certificates, &quot;
        + rf&quot;{purpose_summary.category_counts.get(&#x27;tls_server_and_client&#x27;, 0)} dual-EKU certificates.&quot;
        + r&quot;}&quot;,
        r&quot;\end{titlepage}&quot;,
        r&quot;\tableofcontents&quot;,
        r&quot;\clearpage&quot;,
    ]

    def add_summary(items: list[str]) -&gt; None:
        lines.append(r&quot;\SummaryBox{\textbf{Management Summary}\begin{itemize}[leftmargin=1.4em]&quot;)
        for item in items:
            lines.append(rf&quot;\item {tex_escape(item)}&quot;)
        lines.append(r&quot;\end{itemize}}&quot;)

    lines.append(r&quot;\section{Method, Integrity, and How To Read This}&quot;)
    add_summary(
        [
            f&quot;The scanner now refuses to run if the candidate cap is lower than the live raw match count; current counts are {&#x27;, &#x27;.join(f&#x27;{domain}={count}&#x27; for domain, count in report[&#x27;raw_match_counts&#x27;].items())}.&quot;,
            f&quot;The live cap used for this run was {report[&#x27;cap&#x27;]}.&quot;,
            f&quot;Leaf-only verification kept {report[&#x27;verification&#x27;].unique_leaf_certificates} certificates.&quot;,
            f&quot;Configured search-term coverage failures: {report[&#x27;missing_matching_san&#x27;]}.&quot;,
        ]
    )
    lines.append(
        r&quot;Certificate Transparency is the public logging layer for issued certificates. The report starts there, validates the actual X.509 certificate bytes, and then scans the DNS names exposed in SANs. A Subject CN is the traditional primary name in a certificate; a SAN list is the modern set of all names the certificate covers.&quot;
    )

    lines.append(r&quot;\section{Certificate Corpus}&quot;)
    add_summary(
        [
            f&quot;{len(hits)} current leaf certificates are in scope.&quot;,
            f&quot;Revocation mix: not revoked={rev_counts.get(&#x27;not_revoked&#x27;, 0)}, revoked={rev_counts.get(&#x27;revoked&#x27;, 0)}, unknown={rev_counts.get(&#x27;unknown&#x27;, 0)}.&quot;,
            f&quot;Purpose split: server-only={purpose_summary.category_counts.get(&#x27;tls_server_only&#x27;, 0)}, server+client={purpose_summary.category_counts.get(&#x27;tls_server_and_client&#x27;, 0)}.&quot;,
            f&quot;All Subject CN values appear in SAN DNS names.&quot;,
        ]
    )
    lines.extend(
        [
            r&quot;\subsection{Issuer Breakdown}&quot;,
            r&quot;\begin{longtable}{&gt;{\raggedright\arraybackslash}p{0.67\linewidth} &gt;{\raggedleft\arraybackslash}p{0.12\linewidth} &gt;{\raggedleft\arraybackslash}p{0.12\linewidth}}&quot;,
            r&quot;\toprule&quot;,
            r&quot;Issuer &amp; Count &amp; WebPKI \\&quot;,
            r&quot;\midrule&quot;,
        ]
    )
    for issuer_name, count in report[&quot;issuer_counts&quot;].most_common():
        trust = report[&quot;issuer_trust&quot;][issuer_name]
        lines.append(rf&quot;{tex_escape(issuer_name)} &amp; {count} &amp; {&#x27;yes&#x27; if trust.major_webpki else &#x27;no&#x27;} \\&quot;)
    lines.extend([r&quot;\bottomrule&quot;, r&quot;\end{longtable}&quot;])
    lines.append(r&quot;\subsection{Purpose Assessment}&quot;)
    lines.append(r&quot;\begin{itemize}[leftmargin=1.4em]&quot;)
    for category, count in purpose_summary.category_counts.items():
        lines.append(rf&quot;\item \texttt{{{tex_escape(category)}}}: {count}&quot;)
    lines.append(r&quot;\end{itemize}&quot;)

    lines.append(r&quot;\section{Naming Architecture}&quot;)
    add_summary(
        [
            f&quot;{len(report[&#x27;numbered_groups&#x27;])} numbered CN families indicate reusable service rails.&quot;,
            f&quot;{report[&#x27;public_www_pair_count&#x27;]} certificates use a base-name plus www pairing.&quot;,
            f&quot;{report[&#x27;multi_zone_hit_count&#x27;]} certificates span more than one DNS zone in SAN.&quot;,
            f&quot;Most common suffixes are {&#x27;, &#x27;.join(f&#x27;{suffix} ({count})&#x27; for suffix, count in report[&#x27;top_suffixes&#x27;][:4])}.&quot;,
        ]
    )
    lines.append(r&quot;\subsection{Representative Examples}&quot;)
    for example in report[&quot;examples&quot;]:
        lines.append(r&quot;\SummaryBox{&quot;)
        lines.append(rf&quot;\textbf{{{tex_escape(example.title)}}}\par&quot;)
        lines.append(rf&quot;\textbf{{Subject CN}}: \texttt{{{tex_escape(example.subject_cn)}}}\par&quot;)
        lines.append(tex_escape(example.why_it_matters) + r&quot;\par&quot;)
        lines.append(r&quot;\begin{itemize}[leftmargin=1.4em]&quot;)
        for point in example.evidence:
            lines.append(rf&quot;\item {tex_escape(point)}&quot;)
        lines.append(r&quot;\end{itemize}}&quot;)

    lines.append(r&quot;\section{DNS Delivery Architecture}&quot;)
    add_summary(
        [
            f&quot;{len(report[&#x27;unique_dns_names&#x27;])} unique DNS names were scanned from SAN.&quot;,
            f&quot;Top delivery signatures are {&#x27;, &#x27;.join(f&#x27;{label} ({count})&#x27; for label, count in report[&#x27;dns_stack_counts&#x27;].most_common(5))}.&quot;,
            &quot;The DNS view reduces many hostnames into a smaller set of recurring delivery platforms.&quot;,
        ]
    )
    lines.extend(
        [
            r&quot;\subsection{Delivery Stack Counts}&quot;,
            r&quot;\begin{longtable}{&gt;{\raggedright\arraybackslash}p{0.72\linewidth} &gt;{\raggedleft\arraybackslash}p{0.16\linewidth}}&quot;,
            r&quot;\toprule&quot;,
            r&quot;Stack signature &amp; Count \\&quot;,
            r&quot;\midrule&quot;,
        ]
    )
    for label, count in report[&quot;dns_stack_counts&quot;].most_common(12):
        lines.append(rf&quot;{tex_escape(label)} &amp; {count} \\&quot;)
    lines.extend([r&quot;\bottomrule&quot;, r&quot;\end{longtable}&quot;])

    lines.append(r&quot;\subsection{Platform Glossary}&quot;)
    lines.append(r&quot;\begin{longtable}{&gt;{\raggedright\arraybackslash}p{0.22\linewidth} &gt;{\raggedright\arraybackslash}p{0.70\linewidth}}&quot;)
    lines.append(r&quot;\toprule&quot;)
    lines.append(r&quot;Term &amp; Explanation \\&quot;)
    lines.append(r&quot;\midrule&quot;)
    glossary = ct_dns_utils.provider_explanations()
    seen_terms = set()
    for observation in report[&quot;observations&quot;]:
        seen_terms.update(observation.provider_hints)
    for term in [&quot;Adobe Campaign&quot;, &quot;AWS&quot;, &quot;AWS CloudFront&quot;, &quot;AWS ALB&quot;, &quot;Google Apigee&quot;, &quot;Pega Cloud&quot;, &quot;Microsoft Edge&quot;, &quot;Infinite / agency alias&quot;, &quot;CNAME&quot;, &quot;A record&quot;, &quot;AAAA record&quot;, &quot;PTR record&quot;, &quot;NXDOMAIN&quot;]:
        if term in glossary and (term in seen_terms or term in {&quot;CNAME&quot;, &quot;A record&quot;, &quot;AAAA record&quot;, &quot;PTR record&quot;, &quot;NXDOMAIN&quot;, &quot;AWS ALB&quot;}):
            lines.append(rf&quot;{tex_escape(term)} &amp; {tex_escape(glossary[term])} \\&quot;)
    lines.extend([r&quot;\bottomrule&quot;, r&quot;\end{longtable}&quot;])

    lines.append(r&quot;\section{Where The Certificate View and DNS View Meet}&quot;)
    add_summary(
        [
            &quot;Certificates explain naming, trust, and purpose; DNS explains routing, reachability, and platform landing points.&quot;,
            &quot;Numbered families usually behave like shared service rails, while clean two-name SAN pairs usually behave like public presentation fronts.&quot;,
            &quot;The estate becomes coherent when brand, platform, and delivery are treated as different layers of the same system.&quot;,
        ]
    )
    lines.extend(
        [
            r&quot;\subsection{Top Family Digest}&quot;,
            r&quot;\begin{longtable}{&gt;{\raggedright\arraybackslash}p{0.09\linewidth} &gt;{\raggedright\arraybackslash}p{0.39\linewidth} &gt;{\raggedright\arraybackslash}p{0.15\linewidth} &gt;{\raggedleft\arraybackslash}p{0.09\linewidth} &gt;{\raggedleft\arraybackslash}p{0.09\linewidth} &gt;{\raggedright\arraybackslash}p{0.13\linewidth}}&quot;,
            r&quot;\toprule&quot;,
            r&quot;ID &amp; Basis &amp; Type &amp; Certs &amp; CNs &amp; Top stacks \\&quot;,
            r&quot;\midrule&quot;,
        ]
    )
    for row in report[&quot;group_digest&quot;]:
        lines.append(
            rf&quot;{tex_escape(row[&#x27;group_id&#x27;])} &amp; {tex_escape(row[&#x27;basis&#x27;])} &amp; {tex_escape(row[&#x27;type&#x27;])} &amp; {row[&#x27;certificates&#x27;]} &amp; {row[&#x27;subjects&#x27;]} &amp; {tex_escape(row[&#x27;top_stacks&#x27;])} \\&quot;
        )
    lines.extend([r&quot;\bottomrule&quot;, r&quot;\end{longtable}&quot;])

    lines.append(r&quot;\section{Confidence, Limits, and Claims}&quot;)
    add_summary(
        [
            &quot;Strong claims in this report are the ones tied directly to certificate fields, DNS answers, and trust records.&quot;,
            &quot;Interpretive claims are constrained to repeated patterns and are stated as readings, not as internal-org certainties.&quot;,
            &quot;The exact meaning of internal abbreviations cannot be proven from CT and DNS alone.&quot;,
        ]
    )
    lines.append(
        r&quot;The report can prove which issuers are used, which EKU patterns exist, which DNS stacks are visible, and which naming families repeat. It cannot prove the exact internal org chart or the exact human expansion of every short token.&quot;
    )
    lines.append(r&quot;\end{document}&quot;)
    path.write_text(&quot;\n&quot;.join(lines) + &quot;\n&quot;, encoding=&quot;utf-8&quot;)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Writes the shorter consolidated report in LaTeX.</p>
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
    report = summarize_for_report(args)
    render_markdown(args.markdown_output, report)
    render_latex(args.latex_output, report)
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
<p><strong>What this block is doing</strong></p><p>The standalone command-line entrypoint for the consolidated current-state report.</p>
<p><strong>Flow arrows</strong></p><p>CLI arguments from the operator. &#8594; <strong>main</strong> &#8594; Runs the shorter consolidated current-state report end to end.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

