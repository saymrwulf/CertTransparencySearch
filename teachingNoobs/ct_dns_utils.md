# ct_dns_utils.py

Source file: [`ct_dns_utils.py`](../ct_dns_utils.py)

Public DNS scanner. This file runs dig, follows alias chains, finds public addresses, and collapses raw DNS evidence into readable delivery labels.

Main flow in one line: `DNS name -> dig answers -> normalized observation -> provider hints -> delivery label`

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

import hashlib
import ipaddress
import json
import re
import subprocess
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import ct_scan</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Shared DNS scanning helpers, cache helpers, and the logic that turns raw DNS answers into platform clues.</p>
<p><strong>Flow arrows</strong></p><p>Nothing yet; this is the starting point. &#8594; <strong>Module setup</strong> &#8594; The later DNS helpers all reuse these imports and small shared helpers.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## DnsObservation

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">@dataclass
class DnsObservation:
    original_name: str
    original_status: str
    cname_chain: list[str]
    terminal_name: str
    terminal_status: str
    a_records: list[str]
    aaaa_records: list[str]
    ptr_records: list[str]
    classification: str
    stack_signature: str
    provider_hints: list[str]</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>One complete DNS observation for one hostname.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>DnsObservation</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## normalize_name

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def normalize_name(name: str) -&gt; str:
    return name.rstrip(&quot;.&quot;).lower()</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This block makes values consistent so matching and grouping do not get confused by superficial differences.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>normalize_name</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## cache_key

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def cache_key(value: str) -&gt; str:
    digest = hashlib.sha256(value.encode(&quot;utf-8&quot;)).hexdigest()[:16]
    slug = re.sub(r&quot;[^a-z0-9.-]+&quot;, &quot;-&quot;, value.lower()).strip(&quot;-&quot;)
    slug = slug[:80] or &quot;item&quot;
    return f&quot;v1-{slug}-{digest}.json&quot;</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_dns_utils.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>cache_key</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## load_json_cache

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def load_json_cache(cache_dir: Path, key: str, ttl_seconds: int) -&gt; dict[str, Any] | None:
    path = cache_dir / key
    if not path.exists():
        return None
    payload = json.loads(path.read_text(encoding=&quot;utf-8&quot;))
    cached_at = datetime.fromisoformat(payload[&quot;cached_at&quot;].replace(&quot;Z&quot;, &quot;+00:00&quot;))
    age = time.time() - cached_at.astimezone(UTC).timestamp()
    if age &gt; ttl_seconds:
        return None
    return payload</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This block loads data from disk, cache, or an earlier stage so later code can work with it.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>load_json_cache</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## store_json_cache

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def store_json_cache(cache_dir: Path, key: str, payload: dict[str, Any]) -&gt; None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    enriched = dict(payload)
    enriched[&quot;cached_at&quot;] = ct_scan.utc_iso(datetime.now(UTC))
    (cache_dir / key).write_text(json.dumps(enriched, indent=2, sort_keys=True), encoding=&quot;utf-8&quot;)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This block saves an intermediate result so the next run can reuse it instead of recomputing everything.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>store_json_cache</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## run_dig

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def run_dig(name: str, rrtype: str, short: bool) -&gt; str:
    cmd = [&quot;dig&quot;, &quot;+time=2&quot;, &quot;+tries=1&quot;]
    if short:
        cmd.append(&quot;+short&quot;)
    else:
        cmd.extend([&quot;+noall&quot;, &quot;+comments&quot;, &quot;+answer&quot;])
    cmd.extend([name, rrtype])
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return result.stdout</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_dns_utils.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>A hostname and record type. &#8594; <strong>run_dig</strong> &#8594; `scan_name_live`, `dig_status`, `dig_short`, and `ptr_lookup` all rely on this.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## dig_status

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def dig_status(name: str, rrtype: str = &quot;A&quot;) -&gt; str:
    output = run_dig(name, rrtype, short=False)
    match = re.search(r&quot;status:\s*([A-Z]+)&quot;, output)
    if match:
        return match.group(1)
    if output.strip():
        return &quot;NOERROR&quot;
    return &quot;UNKNOWN&quot;</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_dns_utils.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>dig_status</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## dig_short

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def dig_short(name: str, rrtype: str) -&gt; list[str]:
    output = run_dig(name, rrtype, short=True)
    return [normalize_name(line) for line in output.splitlines() if line.strip()]</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_dns_utils.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>dig_short</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## parse_answer_section

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def parse_answer_section(output: str) -&gt; list[tuple[str, str]]:
    in_answer = False
    parsed: list[tuple[str, str]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith(&quot;;; ANSWER SECTION:&quot;):
            in_answer = True
            continue
        if not in_answer or line.startswith(&quot;;;&quot;):
            continue
        match = re.match(r&quot;^\S+\s+\d+\s+IN\s+(\S+)\s+(.+)$&quot;, line)
        if not match:
            continue
        rrtype, rdata = match.groups()
        parsed.append((rrtype.upper(), normalize_name(rdata)))
    return parsed</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_dns_utils.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>parse_answer_section</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## is_ip_address

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def is_ip_address(value: str) -&gt; bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_dns_utils.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>is_ip_address</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## classify_observation

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def classify_observation(chain: list[str], terminal_status: str, a_records: list[str], aaaa_records: list[str]) -&gt; str:
    has_addresses = bool(a_records or aaaa_records)
    if chain and has_addresses:
        return &quot;cname_to_address&quot;
    if chain and not has_addresses:
        return &quot;dangling_cname&quot;
    if has_addresses:
        return &quot;direct_address&quot;
    if terminal_status == &quot;NXDOMAIN&quot;:
        return &quot;nxdomain&quot;
    if terminal_status == &quot;NOERROR&quot;:
        return &quot;no_data&quot;
    return &quot;other&quot;</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This block applies rules and chooses a category label.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>classify_observation</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## infer_provider_hints

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def infer_provider_hints(observation: DnsObservation) -&gt; list[str]:
    text = &quot; &quot;.join(
        [
            observation.original_name,
            *observation.cname_chain,
            observation.terminal_name,
            *observation.ptr_records,
        ]
    ).lower()
    hints: list[str] = []
    if &quot;campaign.adobe.com&quot; in text:
        hints.append(&quot;Adobe Campaign&quot;)
    if &quot;cloudfront.net&quot; in text:
        hints.append(&quot;AWS CloudFront&quot;)
    if &quot;elb.amazonaws.com&quot; in text or &quot;compute.amazonaws.com&quot; in text:
        hints.append(&quot;AWS&quot;)
    if &quot;apigee.net&quot; in text or &quot;googleusercontent.com&quot; in text:
        hints.append(&quot;Google Apigee&quot;)
    if &quot;pegacloud.net&quot; in text or &quot;.pega.net&quot; in text:
        hints.append(&quot;Pega Cloud&quot;)
    if &quot;useinfinite.io&quot; in text:
        hints.append(&quot;Infinite / agency alias&quot;)
    if any(ip.startswith(&quot;13.107.&quot;) for ip in observation.a_records) or any(ip.startswith(&quot;2620:1ec:&quot;) for ip in observation.aaaa_records):
        hints.append(&quot;Microsoft Edge&quot;)
    if not hints:
        hints.append(&quot;Unclassified&quot;)
    return hints</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Reads the raw DNS trail and pulls out likely platform or vendor clues.</p>
<p><strong>Flow arrows</strong></p><p>One normalized DNS observation. &#8594; <strong>infer_provider_hints</strong> &#8594; `infer_stack_signature` and the report layers use the hints it produces.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## infer_stack_signature

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def infer_stack_signature(observation: DnsObservation) -&gt; str:
    hints = infer_provider_hints(observation)
    if observation.classification == &quot;nxdomain&quot;:
        return &quot;No public DNS (NXDOMAIN)&quot;
    if observation.classification == &quot;no_data&quot;:
        return &quot;No public address data&quot;
    if &quot;Adobe Campaign&quot; in hints and &quot;AWS CloudFront&quot; in hints:
        return &quot;Adobe Campaign -&gt; AWS CloudFront&quot;
    if &quot;Adobe Campaign&quot; in hints and &quot;AWS&quot; in hints:
        return &quot;Adobe Campaign -&gt; AWS ALB&quot;
    if &quot;Adobe Campaign&quot; in hints and observation.a_records:
        return &quot;Adobe Campaign direct IP&quot;
    if &quot;AWS CloudFront&quot; in hints:
        return &quot;AWS CloudFront&quot;
    if &quot;Google Apigee&quot; in hints:
        return &quot;Google Apigee&quot;
    if &quot;Pega Cloud&quot; in hints and &quot;AWS&quot; in hints:
        return &quot;Pega Cloud -&gt; AWS ALB&quot;
    if &quot;Infinite / agency alias&quot; in hints and observation.classification == &quot;dangling_cname&quot;:
        return &quot;Dangling agency alias&quot;
    if &quot;Microsoft Edge&quot; in hints:
        return &quot;Direct Microsoft edge&quot;
    if &quot;AWS&quot; in hints:
        return &quot;Direct AWS&quot;
    if observation.classification == &quot;direct_address&quot;:
        return &quot;Direct address (provider unclear)&quot;
    if observation.classification == &quot;cname_to_address&quot;:
        return &quot;CNAME to address (provider unclear)&quot;
    return hints[0]</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Collapses several low-level DNS clues into one human-readable delivery label.</p>
<p><strong>Flow arrows</strong></p><p>One DNS observation plus provider clues. &#8594; <strong>infer_stack_signature</strong> &#8594; `ct_master_report` uses the resulting label in naming and DNS chapters.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## scan_name_live

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def scan_name_live(name: str) -&gt; DnsObservation:
    name = normalize_name(name)
    a_output = run_dig(name, &quot;A&quot;, short=False)
    aaaa_output = run_dig(name, &quot;AAAA&quot;, short=False)
    original_status = dig_status(name, &quot;A&quot;)
    a_answers = parse_answer_section(a_output)
    aaaa_answers = parse_answer_section(aaaa_output)
    chain: list[str] = []
    for rrtype, rdata in a_answers + aaaa_answers:
        if rrtype == &quot;CNAME&quot; and rdata not in chain:
            chain.append(rdata)
    a_records = sorted({rdata for rrtype, rdata in a_answers if rrtype == &quot;A&quot; and is_ip_address(rdata)})
    aaaa_records = sorted({rdata for rrtype, rdata in aaaa_answers if rrtype == &quot;AAAA&quot; and is_ip_address(rdata)})
    terminal_name = chain[-1] if chain else name
    terminal_status = original_status
    observation = DnsObservation(
        original_name=name,
        original_status=original_status,
        cname_chain=chain,
        terminal_name=terminal_name,
        terminal_status=terminal_status,
        a_records=a_records,
        aaaa_records=aaaa_records,
        ptr_records=[],
        classification=classify_observation(chain, terminal_status, a_records, aaaa_records),
        stack_signature=&quot;&quot;,
        provider_hints=[],
    )
    observation.provider_hints = infer_provider_hints(observation)
    observation.stack_signature = infer_stack_signature(observation)
    return observation</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Runs the live DNS walk for one hostname.</p>
<p><strong>Flow arrows</strong></p><p>One DNS name from a SAN entry. &#8594; <strong>scan_name_live</strong> &#8594; `scan_name_cached` returns this result shape to higher-level analytics.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## scan_name_cached

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def scan_name_cached(name: str, cache_dir: Path, ttl_seconds: int) -&gt; DnsObservation:
    key = cache_key(name)
    cached = load_json_cache(cache_dir, key, ttl_seconds)
    if cached is not None:
        payload = dict(cached)
        payload.pop(&quot;cached_at&quot;, None)
        return DnsObservation(**payload)
    observation = scan_name_live(name)
    store_json_cache(cache_dir, key, asdict(observation))
    return observation</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Reuses a recent DNS result if possible, otherwise performs the live scan.</p>
<p><strong>Flow arrows</strong></p><p>A DNS name plus cache settings. &#8594; <strong>scan_name_cached</strong> &#8594; `ct_master_report.enrich_dns` uses this for every SAN name in the current corpus.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## ptr_lookup

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def ptr_lookup(ip: str, cache_dir: Path, ttl_seconds: int) -&gt; list[str]:
    key = cache_key(f&quot;ptr-{ip}&quot;)
    cached = load_json_cache(cache_dir, key, ttl_seconds)
    if cached is not None:
        return list(cached.get(&quot;answers&quot;, []))
    output = subprocess.run(
        [&quot;dig&quot;, &quot;+time=2&quot;, &quot;+tries=1&quot;, &quot;+short&quot;, &quot;-x&quot;, ip, &quot;PTR&quot;],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    answers = [normalize_name(line) for line in output.splitlines() if line.strip()]
    store_json_cache(cache_dir, key, {&quot;answers&quot;: answers})
    return answers</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_dns_utils.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>ptr_lookup</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## provider_explanations

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def provider_explanations() -&gt; dict[str, str]:
    return {
        &quot;Adobe Campaign&quot;: &quot;A marketing and communication platform often used to send customer messages, email journeys, and campaign traffic. In DNS terms, it can sit in front of cloud infrastructure rather than hosting the final application by itself.&quot;,
        &quot;AWS&quot;: &quot;Amazon Web Services, a large public cloud platform. In this report it usually means the endpoint ultimately lands on Amazon-hosted compute or load-balancing infrastructure.&quot;,
        &quot;AWS ALB&quot;: &quot;AWS Application Load Balancer. A traffic-distribution front door that sends incoming web requests to one or more backend services.&quot;,
        &quot;AWS CloudFront&quot;: &quot;Amazon&#x27;s global content-delivery and edge network. It is often used to front websites, APIs, and static assets close to users.&quot;,
        &quot;Google Apigee&quot;: &quot;An API gateway and API-management layer. If a hostname lands here, it usually means the public endpoint is being governed as an API product rather than being exposed directly from an application server.&quot;,
        &quot;Pega Cloud&quot;: &quot;A managed hosting platform for Pega applications and workflow systems. It often fronts case-management or process-heavy applications.&quot;,
        &quot;Microsoft Edge&quot;: &quot;Microsoft-operated edge infrastructure. In DNS this usually means the public name lands on Microsoft&#x27;s front-door network rather than directly on a private application host.&quot;,
        &quot;Infinite / agency alias&quot;: &quot;A third-party aliasing pattern typically used by an agency or service intermediary. It points traffic onward to the actual delivery platform.&quot;,
        &quot;CNAME&quot;: &quot;A DNS alias record. It says one hostname is really another hostname, rather than directly mapping to an IP address.&quot;,
        &quot;A record&quot;: &quot;A DNS record that maps a hostname to an IPv4 address.&quot;,
        &quot;AAAA record&quot;: &quot;A DNS record that maps a hostname to an IPv6 address.&quot;,
        &quot;PTR record&quot;: &quot;A reverse-DNS record. It maps an IP address back to a hostname and is useful as a provider clue, not as proof of ownership.&quot;,
        &quot;NXDOMAIN&quot;: &quot;A DNS response meaning the name does not exist publicly.&quot;,
    }</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Supplies the glossary text used later in the reports.</p>
<p><strong>Flow arrows</strong></p><p>The delivery labels used by the report. &#8594; <strong>provider_explanations</strong> &#8594; The monograph glossary uses these explanations directly.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

