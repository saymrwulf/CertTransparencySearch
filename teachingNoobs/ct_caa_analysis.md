# ct_caa_analysis.py

Source file: [`ct_caa_analysis.py`](../ct_caa_analysis.py)

CAA analyzer. This file resolves live DNS issuance policy and compares it against the public CA families that are actually covering the names today.

Main flow in one line: `DNS name -> effective CAA lookup -> allowed CA families -> compare with live cert families`

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

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import ct_dns_utils
import ct_scan</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Data structures and lookup logic for effective CAA policy analysis.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>Module setup</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## CaaObservation

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">@dataclass
class CaaObservation:
    name: str
    effective_rr_owner: str | None
    source_kind: str
    source_label: str | None
    aliases_seen: list[str]
    caa_rows: list[tuple[int, str, str]]</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>One resolved CAA result before it is merged with certificate coverage data.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>CaaObservation</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## CaaNameRow

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">@dataclass
class CaaNameRow:
    name: str
    zone: str
    source_kind: str
    effective_rr_owner: str | None
    source_label: str | None
    aliases_seen: list[str]
    issue_values: list[str]
    issuewild_values: list[str]
    iodef_values: list[str]
    allowed_ca_families: list[str]
    current_covering_families: list[str]
    current_covering_subject_cns: list[str]
    current_covering_cert_count: int
    current_multi_family_overlap: bool
    current_policy_mismatch: bool
    mismatch_families: list[str]</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>One final row that compares DNS policy with current live certificate families.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>CaaNameRow</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## CaaAnalysis

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">@dataclass
class CaaAnalysis:
    generated_at_utc: str
    configured_domains: list[str]
    total_names: int
    rows: list[CaaNameRow]
    source_kind_counts: Counter[str]
    zone_counts: Counter[str]
    multi_family_overlap_names: list[str]
    policy_mismatch_names: list[str]</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>The full CAA analysis bundle used by the monograph.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>CaaAnalysis</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## normalize_dns_name

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def normalize_dns_name(value: str) -&gt; str:
    value = value.strip()
    if value.upper().startswith(&quot;DNS:&quot;):
        return ct_dns_utils.normalize_name(value[4:])
    return ct_dns_utils.normalize_name(value)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This block makes values consistent so matching and grouping do not get confused by superficial differences.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>normalize_dns_name</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## issuer_family

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def issuer_family(names: set[str]) -&gt; str:
    lowered = &quot; &quot;.join(sorted(names)).lower()
    if &quot;amazon&quot; in lowered:
        return &quot;Amazon&quot;
    if &quot;google trust services&quot; in lowered or &quot;cn=we1&quot; in lowered:
        return &quot;Google Trust Services&quot;
    if &quot;sectigo&quot; in lowered or &quot;comodo&quot; in lowered:
        return &quot;Sectigo/COMODO&quot;
    if any(token in lowered for token in [&quot;digicert&quot;, &quot;quovadis&quot;, &quot;thawte&quot;, &quot;geotrust&quot;, &quot;rapidssl&quot;, &quot;symantec&quot;, &quot;verisign&quot;]):
        return &quot;DigiCert/QuoVadis&quot;
    return &quot;Other&quot;</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_caa_analysis.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>issuer_family</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## classify_zone

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def classify_zone(name: str, configured_domains: list[str]) -&gt; str:
    for domain in sorted(configured_domains, key=len, reverse=True):
        lowered_domain = domain.lower()
        if name == lowered_domain or name.endswith(f&quot;.{lowered_domain}&quot;):
            return lowered_domain
    return &quot;other&quot;</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This block applies rules and chooses a category label.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>classify_zone</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## cache_path

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def cache_path(cache_dir: Path, name: str) -&gt; Path:
    return cache_dir / ct_dns_utils.cache_key(f&quot;caa-{name}&quot;)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_caa_analysis.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>cache_path</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## serialize_observation

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def serialize_observation(observation: CaaObservation) -&gt; dict[str, Any]:
    return {
        &quot;name&quot;: observation.name,
        &quot;effective_rr_owner&quot;: observation.effective_rr_owner,
        &quot;source_kind&quot;: observation.source_kind,
        &quot;source_label&quot;: observation.source_label,
        &quot;aliases_seen&quot;: observation.aliases_seen,
        &quot;caa_rows&quot;: [list(row) for row in observation.caa_rows],
    }</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_caa_analysis.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>serialize_observation</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## deserialize_observation

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def deserialize_observation(payload: dict[str, Any]) -&gt; CaaObservation:
    return CaaObservation(
        name=payload[&quot;name&quot;],
        effective_rr_owner=payload.get(&quot;effective_rr_owner&quot;),
        source_kind=payload[&quot;source_kind&quot;],
        source_label=payload.get(&quot;source_label&quot;),
        aliases_seen=list(payload.get(&quot;aliases_seen&quot;, [])),
        caa_rows=[(int(flag), str(tag), str(value)) for flag, tag, value in payload.get(&quot;caa_rows&quot;, [])],
    )</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_caa_analysis.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>deserialize_observation</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## parse_caa_response

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def parse_caa_response(lines: list[str]) -&gt; tuple[list[tuple[int, str, str]], list[str]]:
    rows: list[tuple[int, str, str]] = []
    aliases: list[str] = []
    for line in lines:
        parts = line.split(maxsplit=2)
        if len(parts) == 3 and parts[0].isdigit():
            flag, tag, value = parts
            rows.append((int(flag), tag.lower(), value.strip().strip(&#x27;&quot;&#x27;).lower()))
        elif line.endswith(&quot;.&quot;):
            aliases.append(ct_dns_utils.normalize_name(line))
    return rows, aliases</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_caa_analysis.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>parse_caa_response</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## query_caa_lines

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def query_caa_lines(name: str) -&gt; list[str]:
    output = ct_dns_utils.run_dig(name, &quot;CAA&quot;, short=True)
    return [line.strip() for line in output.splitlines() if line.strip()]</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This block asks an external source for data and returns it in a shape the rest of the file can use.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>query_caa_lines</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## relevant_caa_live

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def relevant_caa_live(name: str) -&gt; CaaObservation:
    labels = name.rstrip(&quot;.&quot;).lower().split(&quot;.&quot;)
    for index in range(len(labels)):
        candidate = &quot;.&quot;.join(labels[index:])
        rows, aliases = parse_caa_response(query_caa_lines(candidate))
        if rows:
            if index == 0:
                source_kind = &quot;alias_target&quot; if aliases else &quot;exact&quot;
            else:
                source_kind = &quot;parent_alias_target&quot; if aliases else &quot;parent&quot;
            return CaaObservation(
                name=name,
                effective_rr_owner=candidate,
                source_kind=source_kind,
                source_label=aliases[-1] if aliases else candidate,
                aliases_seen=aliases,
                caa_rows=rows,
            )
    return CaaObservation(
        name=name,
        effective_rr_owner=None,
        source_kind=&quot;none&quot;,
        source_label=None,
        aliases_seen=[],
        caa_rows=[],
    )</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Finds the effective live CAA for one name, including inheritance and alias behavior.</p>
<p><strong>Flow arrows</strong></p><p>One DNS name from the SAN universe. &#8594; <strong>relevant_caa_live</strong> &#8594; `build_analysis` uses this to learn the effective issuance policy per name.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## scan_name_cached

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def scan_name_cached(name: str, cache_dir: Path, ttl_seconds: int) -&gt; CaaObservation:
    key = cache_path(cache_dir, name).name
    cached = ct_dns_utils.load_json_cache(cache_dir, key, ttl_seconds)
    if cached is not None:
        cached.pop(&quot;cached_at&quot;, None)
        return deserialize_observation(cached)
    observation = relevant_caa_live(name)
    ct_dns_utils.store_json_cache(cache_dir, key, serialize_observation(observation))
    return observation</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_caa_analysis.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>scan_name_cached</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## allowed_ca_families

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def allowed_ca_families(caa_rows: list[tuple[int, str, str]]) -&gt; list[str]:
    families: set[str] = set()
    for _flag, tag, value in caa_rows:
        if tag != &quot;issue&quot;:
            continue
        normalized = value[:-1] if value.endswith(&quot;.&quot;) else value
        if any(token in normalized for token in [&quot;amazon.com&quot;, &quot;amazontrust.com&quot;, &quot;awstrust.com&quot;, &quot;amazonaws.com&quot;, &quot;aws.amazon.com&quot;]):
            families.add(&quot;Amazon&quot;)
        if any(token in normalized for token in [&quot;sectigo.com&quot;, &quot;comodoca.com&quot;, &quot;comodo.com&quot;]):
            families.add(&quot;Sectigo/COMODO&quot;)
        if any(token in normalized for token in [&quot;digicert.com&quot;, &quot;digicert.ne.jp&quot;, &quot;thawte.com&quot;, &quot;geotrust.com&quot;, &quot;rapidssl.com&quot;, &quot;symantec.com&quot;, &quot;quovadisglobal.com&quot;, &quot;digitalcertvalidation.com&quot;]):
            families.add(&quot;DigiCert/QuoVadis&quot;)
        if &quot;pki.goog&quot; in normalized:
            families.add(&quot;Google Trust Services&quot;)
        if &quot;letsencrypt.org&quot; in normalized:
            families.add(&quot;Let&#x27;s Encrypt&quot;)
        if any(token in normalized for token in [&quot;telia.com&quot;, &quot;telia.fi&quot;, &quot;telia.se&quot;]):
            families.add(&quot;Telia&quot;)
    return sorted(families)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_caa_analysis.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Raw CAA rows for one effective policy. &#8594; <strong>allowed_ca_families</strong> &#8594; `build_analysis` uses the normalized families for policy-vs-live comparison.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## issue_values

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def issue_values(caa_rows: list[tuple[int, str, str]], tag: str) -&gt; list[str]:
    return sorted({value for _flag, row_tag, value in caa_rows if row_tag == tag})</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_caa_analysis.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>issue_values</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## build_analysis

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def build_analysis(
    hits: list[ct_scan.CertificateHit],
    configured_domains: list[str],
    cache_dir: Path,
    ttl_seconds: int,
) -&gt; CaaAnalysis:
    names = sorted(
        {
            normalize_dns_name(entry)
            for hit in hits
            for entry in hit.san_entries
            if normalize_dns_name(entry)
        }
    )
    coverage: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for hit in hits:
        family = issuer_family(hit.issuer_names)
        subject_cn = normalize_dns_name(hit.subject_cn)
        for entry in hit.san_entries:
            coverage[normalize_dns_name(entry)].append((subject_cn, family))

    rows: list[CaaNameRow] = []
    for name in names:
        observation = scan_name_cached(name, cache_dir, ttl_seconds)
        allowed_families = allowed_ca_families(observation.caa_rows)
        current_families = sorted({family for _subject, family in coverage[name]})
        mismatch_families = sorted(family for family in current_families if allowed_families and family not in allowed_families)
        rows.append(
            CaaNameRow(
                name=name,
                zone=classify_zone(name, configured_domains),
                source_kind=observation.source_kind,
                effective_rr_owner=observation.effective_rr_owner,
                source_label=observation.source_label,
                aliases_seen=observation.aliases_seen,
                issue_values=issue_values(observation.caa_rows, &quot;issue&quot;),
                issuewild_values=issue_values(observation.caa_rows, &quot;issuewild&quot;),
                iodef_values=issue_values(observation.caa_rows, &quot;iodef&quot;),
                allowed_ca_families=allowed_families,
                current_covering_families=current_families,
                current_covering_subject_cns=sorted({subject for subject, _family in coverage[name]}),
                current_covering_cert_count=len(coverage[name]),
                current_multi_family_overlap=len(current_families) &gt; 1,
                current_policy_mismatch=bool(mismatch_families),
                mismatch_families=mismatch_families,
            )
        )

    return CaaAnalysis(
        generated_at_utc=ct_scan.utc_iso(datetime.now(UTC)),
        configured_domains=sorted(configured_domains),
        total_names=len(rows),
        rows=rows,
        source_kind_counts=Counter(row.source_kind for row in rows),
        zone_counts=Counter(row.zone for row in rows),
        multi_family_overlap_names=sorted(row.name for row in rows if row.current_multi_family_overlap),
        policy_mismatch_names=sorted(row.name for row in rows if row.current_policy_mismatch),
    )</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Runs CAA across the whole SAN namespace and compares policy with live issuance.</p>
<p><strong>Flow arrows</strong></p><p>Current certificate hits and the configured zones. &#8594; <strong>build_analysis</strong> &#8594; The monograph uses this for the CAA chapter and appendix.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## rows_for_zone

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def rows_for_zone(analysis: CaaAnalysis, zone: str) -&gt; list[CaaNameRow]:
    return [row for row in analysis.rows if row.zone == zone]</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Filters the full analysis down to one configured DNS zone.</p>
<p><strong>Flow arrows</strong></p><p>The full CAA analysis bundle. &#8594; <strong>rows_for_zone</strong> &#8594; The monograph uses zone-filtered rows for per-zone policy tables.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## policy_counter

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def policy_counter(rows: list[CaaNameRow]) -&gt; Counter[tuple[str, ...]]:
    counter: Counter[tuple[str, ...]] = Counter()
    for row in rows:
        key = tuple(row.allowed_ca_families) if row.allowed_ca_families else (&quot;UNRESTRICTED&quot;,)
        counter[key] += 1
    return counter</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_caa_analysis.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>policy_counter</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## serialize_analysis

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def serialize_analysis(analysis: CaaAnalysis) -&gt; dict[str, Any]:
    return {
        &quot;generated_at_utc&quot;: analysis.generated_at_utc,
        &quot;configured_domains&quot;: analysis.configured_domains,
        &quot;total_names&quot;: analysis.total_names,
        &quot;rows&quot;: [asdict(row) for row in analysis.rows],
        &quot;source_kind_counts&quot;: dict(analysis.source_kind_counts),
        &quot;zone_counts&quot;: dict(analysis.zone_counts),
        &quot;multi_family_overlap_names&quot;: analysis.multi_family_overlap_names,
        &quot;policy_mismatch_names&quot;: analysis.policy_mismatch_names,
    }</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_caa_analysis.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>serialize_analysis</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

