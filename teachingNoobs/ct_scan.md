# ct_scan.py

Source file: [`ct_scan.py`](../ct_scan.py)

Core Certificate Transparency scanner. This file talks to crt.sh's public database, downloads the real certificate bytes, verifies that they are real leaf certificates, groups them into readable families, and can render the full inventory appendix.

Main flow in one line: `domains file -> raw CT query -> parsed leaf certificates -> CN families -> issuer trust -> appendix reports`

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
import base64
import hashlib
import json
import re
import shutil
import subprocess
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psycopg
from cryptography import x509
from cryptography.x509 import general_name
from cryptography.x509.oid import ExtensionOID
from cryptography.x509.oid import NameOID
from psycopg.rows import dict_row


QUERY_SQL = &quot;&quot;&quot;
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
WHERE ci.not_before &lt;= now() AT TIME ZONE &#x27;UTC&#x27;
  AND ci.not_after &gt;= now() AT TIME ZONE &#x27;UTC&#x27;
  AND cl.certificate_type = &#x27;Certificate&#x27;
ORDER BY cl.first_seen DESC NULLS LAST, ci.id DESC;
&quot;&quot;&quot;


RAW_MATCH_COUNT_SQL = &quot;&quot;&quot;
SELECT count(*)
FROM certificate_and_identities cai
WHERE plainto_tsquery(&#x27;certwatch&#x27;, %(domain)s) @@ identities(cai.certificate)
  AND cai.name_value ILIKE %(name_pattern)s ESCAPE &#x27;\\&#x27;
&quot;&quot;&quot;


REVOCATION_REASONS = {
    1: &quot;keyCompromise&quot;,
    2: &quot;cACompromise&quot;,
    3: &quot;affiliationChanged&quot;,
    4: &quot;superseded&quot;,
    5: &quot;cessationOfOperation&quot;,
    6: &quot;certificateHold&quot;,
    8: &quot;removeFromCRL&quot;,
    9: &quot;privilegeWithdrawn&quot;,
    10: &quot;aACompromise&quot;,
}


PRECERT_POISON_OID = x509.ObjectIdentifier(&quot;1.3.6.1.4.1.11129.2.4.3&quot;)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Imports, SQL, constants, and shared data shapes for the core CT scanner.</p>
<p><strong>Flow arrows</strong></p><p>Nothing yet; this is the starting point. &#8594; <strong>Module setup</strong> &#8594; `connect`, `query_domain`, `build_hits`, and the report renderers use these shared definitions.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## DatabaseRecord

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">@dataclass
class DatabaseRecord:
    domain: str
    certificate_id: int
    issuer_ca_id: int
    issuer_name: str
    common_name: str | None
    subject_dn: str | None
    not_before: datetime
    not_after: datetime
    first_seen: datetime | None
    serial_number: str
    revoked_count: int
    revocation_date: datetime | None
    reason_code: int | None
    last_seen_check_date: datetime | None
    active_crl_count: int
    crl_last_checked: datetime | None
    certificate_der: bytes</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>A raw row as it comes back from the crt.sh database before local cleanup.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>DatabaseRecord</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## CertificateHit

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">@dataclass
class CertificateHit:
    fingerprint_sha256: str
    subject_cn: str
    validity_not_before: datetime
    validity_not_after: datetime
    san_entries: list[str]
    revocation_status: str
    revocation_date: datetime | None
    revocation_reason: str | None
    revocation_note: str | None
    crtsh_crl_timestamp: datetime | None
    matched_domains: set[str] = field(default_factory=set)
    first_seen: datetime | None = None
    crtsh_certificate_ids: set[int] = field(default_factory=set)
    serial_numbers: set[str] = field(default_factory=set)
    issuer_names: set[str] = field(default_factory=set)
    issuer_ca_ids: set[int] = field(default_factory=set)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>The cleaned working object used by the rest of the analytics pipeline.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>CertificateHit</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## VerificationStats

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">@dataclass
class VerificationStats:
    input_rows: int = 0
    unique_leaf_certificates: int = 0
    non_leaf_filtered: int = 0
    precertificate_poison_filtered: int = 0</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>A tiny running counter that proves how many rows were kept or rejected.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>VerificationStats</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## CertificateGroup

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">@dataclass
class CertificateGroup:
    group_id: str
    group_type: str
    member_indices: list[int]
    member_count: int
    distinct_subject_cn_count: int
    distinct_exact_content_count: int
    numbered_cn_patterns: set[str]
    matched_domains: set[str]
    subject_cns: set[str]
    first_seen_min: datetime | None
    first_seen_max: datetime | None
    valid_from_min: datetime
    valid_to_max: datetime
    revocation_counts: Counter</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>One readable family of related certificates after grouping logic runs.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>CertificateGroup</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## ScanStats

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">@dataclass
class ScanStats:
    generated_at_utc: str
    configured_domains: list[str]
    unique_leaf_certificates: int
    groups_total: int
    groups_multi_member: int
    groups_singleton: int
    groups_by_type: dict[str, int]
    verification: VerificationStats</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Top-level summary numbers used in reports.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>ScanStats</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## IssuerTrustInfo

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">@dataclass
class IssuerTrustInfo:
    issuer_name: str
    issuer_ca_ids: set[int]
    server_auth_contexts: set[str]
    major_webpki: bool</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Stores the public-trust picture for one issuer family.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>IssuerTrustInfo</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## load_domains

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def load_domains(path: Path) -&gt; list[str]:
    domains: list[str] = []
    for raw_line in path.read_text(encoding=&quot;utf-8&quot;).splitlines():
        line = raw_line.strip().lower()
        if not line or line.startswith(&quot;#&quot;):
            continue
        if line.startswith(&quot;*.&quot;):
            line = line[2:]
        domains.append(line)
    unique_domains = sorted(set(domains))
    if not unique_domains:
        raise ValueError(f&quot;No domains found in {path}&quot;)
    return unique_domains</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This block loads data from disk, cache, or an earlier stage so later code can work with it.</p>
<p><strong>Flow arrows</strong></p><p>Operator&#x27;s local config file. &#8594; <strong>load_domains</strong> &#8594; `query_domain` and the higher-level loaders use this cleaned domain list.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## escape_like

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def escape_like(value: str) -&gt; str:
    return value.replace(&quot;\\&quot;, &quot;\\\\&quot;).replace(&quot;%&quot;, &quot;\\%&quot;).replace(&quot;_&quot;, &quot;\\_&quot;)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_scan.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>escape_like</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## utc_iso

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def utc_iso(value: datetime | None) -&gt; str:
    if value is None:
        return &quot;n/a&quot;
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    else:
        value = value.astimezone(UTC)
    return value.isoformat(timespec=&quot;seconds&quot;).replace(&quot;+00:00&quot;, &quot;Z&quot;)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This is a small helper that keeps the larger analytical code cleaner and easier to reuse.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>utc_iso</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## serialize_datetime

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def serialize_datetime(value: datetime | None) -&gt; str | None:
    return utc_iso(value) if value is not None else None</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_scan.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>serialize_datetime</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## parse_datetime

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def parse_datetime(value: str | None) -&gt; datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value.replace(&quot;Z&quot;, &quot;+00:00&quot;)).astimezone(UTC).replace(tzinfo=None)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_scan.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>parse_datetime</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## cache_path

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def cache_path(cache_dir: Path, domain: str) -&gt; Path:
    safe_domain = &quot;&quot;.join(ch if ch.isalnum() or ch in &quot;-._&quot; else &quot;_&quot; for ch in domain)
    return cache_dir / f&quot;{safe_domain}.json&quot;</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_scan.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>cache_path</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## record_to_cache_payload

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def record_to_cache_payload(record: DatabaseRecord) -&gt; dict[str, Any]:
    return {
        &quot;domain&quot;: record.domain,
        &quot;certificate_id&quot;: record.certificate_id,
        &quot;issuer_ca_id&quot;: record.issuer_ca_id,
        &quot;issuer_name&quot;: record.issuer_name,
        &quot;common_name&quot;: record.common_name,
        &quot;subject_dn&quot;: record.subject_dn,
        &quot;not_before&quot;: serialize_datetime(record.not_before),
        &quot;not_after&quot;: serialize_datetime(record.not_after),
        &quot;first_seen&quot;: serialize_datetime(record.first_seen),
        &quot;serial_number&quot;: record.serial_number,
        &quot;revoked_count&quot;: record.revoked_count,
        &quot;revocation_date&quot;: serialize_datetime(record.revocation_date),
        &quot;reason_code&quot;: record.reason_code,
        &quot;last_seen_check_date&quot;: serialize_datetime(record.last_seen_check_date),
        &quot;active_crl_count&quot;: record.active_crl_count,
        &quot;crl_last_checked&quot;: serialize_datetime(record.crl_last_checked),
        &quot;certificate_der_b64&quot;: base64.b64encode(record.certificate_der).decode(&quot;ascii&quot;),
    }</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_scan.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>record_to_cache_payload</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## record_from_cache_payload

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def record_from_cache_payload(payload: dict[str, Any]) -&gt; DatabaseRecord:
    return DatabaseRecord(
        domain=payload[&quot;domain&quot;],
        certificate_id=int(payload[&quot;certificate_id&quot;]),
        issuer_ca_id=int(payload[&quot;issuer_ca_id&quot;]),
        issuer_name=payload[&quot;issuer_name&quot;],
        common_name=payload.get(&quot;common_name&quot;),
        subject_dn=payload.get(&quot;subject_dn&quot;),
        not_before=parse_datetime(payload[&quot;not_before&quot;]) or datetime.min,
        not_after=parse_datetime(payload[&quot;not_after&quot;]) or datetime.min,
        first_seen=parse_datetime(payload.get(&quot;first_seen&quot;)),
        serial_number=payload[&quot;serial_number&quot;],
        revoked_count=int(payload[&quot;revoked_count&quot;]),
        revocation_date=parse_datetime(payload.get(&quot;revocation_date&quot;)),
        reason_code=payload.get(&quot;reason_code&quot;),
        last_seen_check_date=parse_datetime(payload.get(&quot;last_seen_check_date&quot;)),
        active_crl_count=int(payload[&quot;active_crl_count&quot;]),
        crl_last_checked=parse_datetime(payload.get(&quot;crl_last_checked&quot;)),
        certificate_der=base64.b64decode(payload[&quot;certificate_der_b64&quot;]),
    )</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_scan.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>record_from_cache_payload</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## load_cached_records

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def load_cached_records(cache_dir: Path, domain: str, ttl_seconds: int, max_candidates: int) -&gt; list[DatabaseRecord] | None:
    path = cache_path(cache_dir, domain)
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding=&quot;utf-8&quot;))
    except (json.JSONDecodeError, OSError):
        return None
    if payload.get(&quot;version&quot;) != 1:
        return None
    if payload.get(&quot;max_candidates&quot;) != max_candidates:
        return None
    cached_at = parse_datetime(payload.get(&quot;cached_at&quot;))
    if cached_at is None:
        return None
    age = time.time() - cached_at.replace(tzinfo=UTC).timestamp()
    if age &gt; ttl_seconds:
        return None
    return [record_from_cache_payload(item) for item in payload.get(&quot;records&quot;, [])]</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This block loads data from disk, cache, or an earlier stage so later code can work with it.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>load_cached_records</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## store_cached_records

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def store_cached_records(cache_dir: Path, domain: str, max_candidates: int, records: list[DatabaseRecord]) -&gt; None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        &quot;version&quot;: 1,
        &quot;cached_at&quot;: utc_iso(datetime.now(UTC)),
        &quot;max_candidates&quot;: max_candidates,
        &quot;records&quot;: [record_to_cache_payload(record) for record in records],
    }
    cache_path(cache_dir, domain).write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding=&quot;utf-8&quot;,
    )</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This block saves an intermediate result so the next run can reuse it instead of recomputing everything.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>store_cached_records</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## connect

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def connect() -&gt; psycopg.Connection:
    return psycopg.connect(
        host=&quot;crt.sh&quot;,
        port=5432,
        dbname=&quot;certwatch&quot;,
        user=&quot;guest&quot;,
        password=&quot;guest&quot;,
        connect_timeout=5,
        sslmode=&quot;disable&quot;,
        autocommit=True,
        application_name=&quot;ct_transparency_search&quot;,
    )</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Opens the direct guest PostgreSQL connection to crt.sh&#x27;s certwatch backend.</p>
<p><strong>Flow arrows</strong></p><p>Called by query functions that need live crt.sh data. &#8594; <strong>connect</strong> &#8594; `query_domain`, `query_raw_match_count`, and issuer-trust lookups all depend on this connection.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## query_domain

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def query_domain(domain: str, max_candidates: int, attempts: int, verbose: bool) -&gt; list[DatabaseRecord]:
    params = {
        &quot;domain&quot;: domain,
        &quot;name_pattern&quot;: f&quot;%{escape_like(domain)}%&quot;,
        &quot;max_candidates&quot;: max_candidates,
    }
    raw_match_count = query_raw_match_count(domain=domain, attempts=attempts, verbose=verbose)
    if raw_match_count &gt; max_candidates:
        raise ValueError(
            f&quot;domain={domain} raw identity matches={raw_match_count} exceed max_candidates={max_candidates}; &quot;
            f&quot;increase --max-candidates-per-domain to at least {raw_match_count} for a complete result set&quot;
        )
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            with connect() as conn, conn.cursor(row_factory=dict_row) as cur:
                cur.execute(QUERY_SQL, params)
                rows = cur.fetchall()
            return [row_to_record(domain, row) for row in rows]
        except Exception as exc:
            last_error = exc
            if attempt == attempts:
                break
            if verbose:
                print(
                    f&quot;[warn] domain={domain} attempt={attempt}/{attempts} failed: {exc}&quot;,
                    file=sys.stderr,
                )
            time.sleep(min(2 ** attempt, 10))
    assert last_error is not None
    raise last_error</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Runs the main certificate query for one search term and refuses silent undercounting.</p>
<p><strong>Flow arrows</strong></p><p>A domain plus the safety cap and retry settings. &#8594; <strong>query_domain</strong> &#8594; `build_hits` receives the raw records returned here.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## query_raw_match_count

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def query_raw_match_count(domain: str, attempts: int, verbose: bool) -&gt; int:
    params = {
        &quot;domain&quot;: domain,
        &quot;name_pattern&quot;: f&quot;%{escape_like(domain)}%&quot;,
    }
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            with connect() as conn, conn.cursor() as cur:
                cur.execute(RAW_MATCH_COUNT_SQL, params)
                row = cur.fetchone()
            return int(row[0])
        except Exception as exc:
            last_error = exc
            if attempt == attempts:
                break
            if verbose:
                print(
                    f&quot;[warn] domain={domain} raw-count attempt={attempt}/{attempts} failed: {exc}&quot;,
                    file=sys.stderr,
                )
            time.sleep(min(2 ** attempt, 10))
    assert last_error is not None
    raise last_error</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Counts how many raw hits exist before the capped query runs.</p>
<p><strong>Flow arrows</strong></p><p>A domain string from the local config. &#8594; <strong>query_raw_match_count</strong> &#8594; `query_domain` uses this count to refuse silent undercounting.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## row_to_record

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def row_to_record(domain: str, row: dict[str, Any]) -&gt; DatabaseRecord:
    return DatabaseRecord(
        domain=domain,
        certificate_id=int(row[&quot;id&quot;]),
        issuer_ca_id=int(row[&quot;issuer_ca_id&quot;]),
        issuer_name=row[&quot;issuer_name&quot;],
        common_name=row[&quot;common_name&quot;],
        subject_dn=row[&quot;subject_dn&quot;],
        not_before=row[&quot;not_before&quot;],
        not_after=row[&quot;not_after&quot;],
        first_seen=row[&quot;first_seen&quot;],
        serial_number=row[&quot;serial_number&quot;],
        revoked_count=int(row[&quot;revoked_count&quot;]),
        revocation_date=row[&quot;revocation_date&quot;],
        reason_code=row[&quot;reason_code&quot;],
        last_seen_check_date=row[&quot;last_seen_check_date&quot;],
        active_crl_count=int(row[&quot;active_crl_count&quot;] or 0),
        crl_last_checked=row[&quot;crl_last_checked&quot;],
        certificate_der=bytes(row[&quot;certificate&quot;]),
    )</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_scan.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>row_to_record</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## extract_san_entries

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def extract_san_entries(cert: x509.Certificate) -&gt; list[str]:
    try:
        extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    entries: list[str] = []
    for name in extension.value:
        entries.append(format_general_name(name))
    return sorted(set(entries), key=str.casefold)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This block pulls one specific piece of information out of a larger object.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>extract_san_entries</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## format_general_name

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def format_general_name(name: general_name.GeneralName) -&gt; str:
    if isinstance(name, x509.DNSName):
        return f&quot;DNS:{name.value}&quot;
    if isinstance(name, x509.RFC822Name):
        return f&quot;EMAIL:{name.value}&quot;
    if isinstance(name, x509.UniformResourceIdentifier):
        return f&quot;URI:{name.value}&quot;
    if isinstance(name, x509.IPAddress):
        return f&quot;IP:{name.value}&quot;
    if isinstance(name, x509.RegisteredID):
        return f&quot;RID:{name.value.dotted_string}&quot;
    if isinstance(name, x509.DirectoryName):
        return f&quot;DIR:{name.value.rfc4514_string()}&quot;
    if isinstance(name, x509.OtherName):
        encoded = base64.b64encode(name.value).decode(&quot;ascii&quot;)
        return f&quot;OTHER:{name.type_id.dotted_string}:{encoded}&quot;
    return str(name)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_scan.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>format_general_name</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
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

## has_precertificate_poison

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def has_precertificate_poison(cert: x509.Certificate) -&gt; bool:
    try:
        cert.extensions.get_extension_for_oid(PRECERT_POISON_OID)
    except x509.ExtensionNotFound:
        return False
    return True</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_scan.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>has_precertificate_poison</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## is_leaf_certificate

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def is_leaf_certificate(cert: x509.Certificate) -&gt; tuple[bool, str]:
    if has_precertificate_poison(cert):
        return (False, &quot;precertificate_poison&quot;)
    try:
        basic_constraints = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        if basic_constraints.ca:
            return (False, &quot;basic_constraints_ca&quot;)
    except x509.ExtensionNotFound:
        pass
    try:
        key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        if key_usage.key_cert_sign:
            return (False, &quot;key_cert_sign&quot;)
    except x509.ExtensionNotFound:
        pass
    return (True, &quot;leaf&quot;)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_scan.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>is_leaf_certificate</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## revocation_fields

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def revocation_fields(record: DatabaseRecord) -&gt; tuple[str, datetime | None, str | None, datetime | None, str | None]:
    if record.revoked_count &gt; 0:
        reason: str | None = None
        if record.reason_code in REVOCATION_REASONS:
            reason = REVOCATION_REASONS[record.reason_code]
        elif record.reason_code not in (None, 0):
            reason = f&quot;unknown({record.reason_code})&quot;
        return (&quot;revoked&quot;, record.revocation_date, reason, record.last_seen_check_date, None)
    if record.active_crl_count &gt; 0:
        return (&quot;not_revoked&quot;, None, None, record.crl_last_checked, None)
    return (&quot;unknown&quot;, None, None, record.crl_last_checked, &quot;no fresh crt.sh CRL data&quot;)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_scan.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>revocation_fields</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## revocation_priority

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def revocation_priority(status: str) -&gt; int:
    return {
        &quot;unknown&quot;: 0,
        &quot;not_revoked&quot;: 1,
        &quot;revoked&quot;: 2,
    }[status]</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_scan.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>revocation_priority</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## build_hits

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def build_hits(records: list[DatabaseRecord]) -&gt; tuple[list[CertificateHit], VerificationStats]:
    verification = VerificationStats(input_rows=len(records))
    hits: dict[str, CertificateHit] = {}
    for record in records:
        cert = x509.load_der_x509_certificate(record.certificate_der)
        is_leaf, reason = is_leaf_certificate(cert)
        if not is_leaf:
            if reason == &quot;precertificate_poison&quot;:
                verification.precertificate_poison_filtered += 1
            else:
                verification.non_leaf_filtered += 1
            continue
        fingerprint_hex = hashlib.sha256(record.certificate_der).hexdigest()
        subject_cn = record.common_name or extract_common_name(cert) or &quot;-&quot;
        revocation_status, revocation_date, revocation_reason, crtsh_crl_timestamp, revocation_note = revocation_fields(record)
        hit = hits.get(fingerprint_hex)
        if hit is None:
            hit = CertificateHit(
                fingerprint_sha256=fingerprint_hex,
                subject_cn=subject_cn,
                validity_not_before=record.not_before,
                validity_not_after=record.not_after,
                san_entries=extract_san_entries(cert),
                revocation_status=revocation_status,
                revocation_date=revocation_date,
                revocation_reason=revocation_reason,
                revocation_note=revocation_note,
                crtsh_crl_timestamp=crtsh_crl_timestamp,
                matched_domains={record.domain},
                first_seen=record.first_seen,
                crtsh_certificate_ids={record.certificate_id},
                serial_numbers={record.serial_number},
                issuer_names={record.issuer_name},
                issuer_ca_ids={record.issuer_ca_id},
            )
            hits[fingerprint_hex] = hit
            continue
        hit.matched_domains.add(record.domain)
        hit.crtsh_certificate_ids.add(record.certificate_id)
        hit.serial_numbers.add(record.serial_number)
        hit.issuer_names.add(record.issuer_name)
        hit.issuer_ca_ids.add(record.issuer_ca_id)
        if hit.first_seen is None or (record.first_seen is not None and record.first_seen &lt; hit.first_seen):
            hit.first_seen = record.first_seen
        if revocation_priority(revocation_status) &gt; revocation_priority(hit.revocation_status):
            hit.revocation_status = revocation_status
            hit.revocation_date = revocation_date
            hit.revocation_reason = revocation_reason
            hit.revocation_note = revocation_note
            hit.crtsh_crl_timestamp = crtsh_crl_timestamp
        elif revocation_status == hit.revocation_status and hit.crtsh_crl_timestamp is not None and crtsh_crl_timestamp is not None:
            if crtsh_crl_timestamp &gt; hit.crtsh_crl_timestamp:
                hit.crtsh_crl_timestamp = crtsh_crl_timestamp
        elif revocation_status == hit.revocation_status and hit.crtsh_crl_timestamp is None:
            hit.crtsh_crl_timestamp = crtsh_crl_timestamp
    ordered_hits = sorted(
        hits.values(),
        key=lambda hit: (
            sorted(hit.matched_domains),
            hit.subject_cn.casefold(),
            hit.validity_not_before,
            hit.fingerprint_sha256,
        ),
    )
    verification.unique_leaf_certificates = len(ordered_hits)
    return (ordered_hits, verification)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Parses certificate bytes, rejects bad objects, and merges duplicate views of the same cert.</p>
<p><strong>Flow arrows</strong></p><p>Raw `DatabaseRecord` rows from crt.sh. &#8594; <strong>build_hits</strong> &#8594; `build_groups`, purpose analysis, DNS analysis, and CAA analysis all consume these cleaned hits.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## canonicalize_subject_cn

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def canonicalize_subject_cn(subject_cn: str) -&gt; str:
    subject_cn = subject_cn.lower()
    if subject_cn.startswith(&quot;www.&quot;):
        return subject_cn[4:]
    return subject_cn</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This block makes values consistent so matching and grouping do not get confused by superficial differences.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>canonicalize_subject_cn</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## normalize_counter_pattern

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def normalize_counter_pattern(hostname: str) -&gt; str | None:
    normalized = re.sub(r&quot;\d+&quot;, &quot;#&quot;, canonicalize_subject_cn(hostname))
    if normalized == canonicalize_subject_cn(hostname):
        return None
    return normalized</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This block makes values consistent so matching and grouping do not get confused by superficial differences.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>normalize_counter_pattern</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## UnionFind

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">class UnionFind:
    def __init__(self, size: int) -&gt; None:
        self.parent = list(range(size))
        self.rank = [0] * size

    def find(self, value: int) -&gt; int:
        while self.parent[value] != value:
            self.parent[value] = self.parent[self.parent[value]]
            value = self.parent[value]
        return value

    def union(self, left: int, right: int) -&gt; None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root == right_root:
            return
        if self.rank[left_root] &lt; self.rank[right_root]:
            left_root, right_root = right_root, left_root
        self.parent[right_root] = left_root
        if self.rank[left_root] == self.rank[right_root]:
            self.rank[left_root] += 1</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This class is a structured container for one piece of data that later code passes around instead of juggling many loose variables.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>UnionFind</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## build_groups

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def build_groups(hits: list[CertificateHit]) -&gt; list[CertificateGroup]:
    if not hits:
        return []
    canonical_cns_by_pattern: dict[str, set[str]] = defaultdict(set)
    for hit in hits:
        pattern = normalize_counter_pattern(hit.subject_cn)
        if pattern is not None:
            canonical_cns_by_pattern[pattern].add(canonicalize_subject_cn(hit.subject_cn))

    qualifying_patterns = {
        pattern
        for pattern, canonical_cns in canonical_cns_by_pattern.items()
        if len(canonical_cns) &gt; 1
    }
    components: dict[tuple[str, str], list[int]] = defaultdict(list)
    for index, hit in enumerate(hits):
        canonical_cn = canonicalize_subject_cn(hit.subject_cn)
        pattern = normalize_counter_pattern(hit.subject_cn)
        if pattern in qualifying_patterns:
            components[(&quot;pattern&quot;, pattern)].append(index)
        else:
            components[(&quot;exact&quot;, canonical_cn)].append(index)

    provisional_groups: list[CertificateGroup] = []
    for (family_kind, family_key), member_indices in components.items():
        member_hits = [hits[index] for index in member_indices]
        subject_cns = {hit.subject_cn for hit in member_hits}
        unique_san_profiles = {tuple(hit.san_entries) for hit in member_hits}
        numbered_patterns = {family_key} if family_kind == &quot;pattern&quot; else set()
        group_type = &quot;numbered_cn_pattern&quot; if family_kind == &quot;pattern&quot; else &quot;exact_endpoint_family&quot;
        first_seen_values = [hit.first_seen for hit in member_hits if hit.first_seen is not None]
        provisional_groups.append(
            CertificateGroup(
                group_id=&quot;&quot;,
                group_type=group_type,
                member_indices=sorted(member_indices),
                member_count=len(member_indices),
                distinct_subject_cn_count=len(subject_cns),
                distinct_exact_content_count=len(unique_san_profiles),
                numbered_cn_patterns=numbered_patterns,
                matched_domains={domain for hit in member_hits for domain in hit.matched_domains},
                subject_cns=subject_cns,
                first_seen_min=min(first_seen_values) if first_seen_values else None,
                first_seen_max=max(first_seen_values) if first_seen_values else None,
                valid_from_min=min(hit.validity_not_before for hit in member_hits),
                valid_to_max=max(hit.validity_not_after for hit in member_hits),
                revocation_counts=Counter(hit.revocation_status for hit in member_hits),
            )
        )

    provisional_groups.sort(
        key=lambda group: (
            -group.member_count,
            group.group_type,
            min(canonicalize_subject_cn(value) for value in group.subject_cns),
        )
    )
    for position, group in enumerate(provisional_groups, start=1):
        group.group_id = f&quot;G{position:04d}&quot;
    return provisional_groups</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Turns a flat certificate list into CN-based families such as exact endpoints or numbered rails.</p>
<p><strong>Flow arrows</strong></p><p>The flat list of `CertificateHit` objects. &#8594; <strong>build_groups</strong> &#8594; The report builders use these groups to turn raw certificate clutter into readable families.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## describe_group_basis

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def describe_group_basis(group: CertificateGroup) -&gt; str:
    if group.group_type == &quot;numbered_cn_pattern&quot;:
        pattern = next(iter(group.numbered_cn_patterns))
        return f&quot;CN pattern with running-number slot: `{pattern}`&quot;
    base = min(canonicalize_subject_cn(value) for value in group.subject_cns)
    return f&quot;Same endpoint CN family (exact CN; `www.` grouped with base name): `{base}`&quot;</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_scan.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>describe_group_basis</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## primary_issuer_name

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def primary_issuer_name(hit: CertificateHit) -&gt; str:
    return sorted(hit.issuer_names)[0]</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_scan.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>primary_issuer_name</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## query_issuer_trust

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def query_issuer_trust(hits: list[CertificateHit]) -&gt; dict[str, IssuerTrustInfo]:
    issuer_name_to_ca_ids: dict[str, set[int]] = defaultdict(set)
    for hit in hits:
        issuer_name_to_ca_ids[primary_issuer_name(hit)].update(hit.issuer_ca_ids)
    all_ca_ids = sorted({ca_id for ca_ids in issuer_name_to_ca_ids.values() for ca_id in ca_ids})
    contexts_by_ca_id: dict[int, set[str]] = defaultdict(set)
    if all_ca_ids:
        query = &quot;&quot;&quot;
        SELECT ctp.ca_id, tc.ctx
        FROM ca_trust_purpose ctp
        JOIN trust_context tc ON tc.id = ctp.trust_context_id
        JOIN trust_purpose tp ON tp.id = ctp.trust_purpose_id
        WHERE ctp.ca_id = ANY(%s)
          AND tp.purpose = &#x27;Server Authentication&#x27;
          AND ctp.is_time_valid = TRUE
          AND ctp.disabled_from IS NULL
        &quot;&quot;&quot;
        with connect() as conn, conn.cursor() as cur:
            cur.execute(query, (all_ca_ids,))
            for ca_id, trust_context in cur.fetchall():
                contexts_by_ca_id[int(ca_id)].add(str(trust_context))
    major_contexts = {&quot;Mozilla&quot;, &quot;Chrome&quot;, &quot;Apple&quot;, &quot;Microsoft&quot;, &quot;Android&quot;}
    results: dict[str, IssuerTrustInfo] = {}
    for issuer_name, ca_ids in issuer_name_to_ca_ids.items():
        merged_contexts = {ctx for ca_id in ca_ids for ctx in contexts_by_ca_id.get(ca_id, set())}
        results[issuer_name] = IssuerTrustInfo(
            issuer_name=issuer_name,
            issuer_ca_ids=set(ca_ids),
            server_auth_contexts=merged_contexts,
            major_webpki=major_contexts.issubset(merged_contexts),
        )
    return results</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Checks which issuers are currently trusted for public TLS in the major WebPKI contexts.</p>
<p><strong>Flow arrows</strong></p><p>The cleaned current certificate hits. &#8594; <strong>query_issuer_trust</strong> &#8594; Report builders use this trust view in the certificate chapters and appendix tables.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## status_marker

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def status_marker(status: str) -&gt; str:
    return {
        &quot;not_revoked&quot;: &quot;OK &quot;,
        &quot;revoked&quot;: &quot;REV&quot;,
        &quot;unknown&quot;: &quot;UNK&quot;,
    }[status]</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_scan.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>status_marker</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## one_line_revocation

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def one_line_revocation(hit: CertificateHit) -&gt; str:
    if hit.revocation_status == &quot;revoked&quot;:
        detail = f&quot;revoked {utc_iso(hit.revocation_date)}&quot; if hit.revocation_date else &quot;revoked&quot;
        if hit.revocation_reason:
            detail += f&quot;, reason={hit.revocation_reason}&quot;
        return detail
    if hit.revocation_status == &quot;unknown&quot;:
        if hit.revocation_note:
            return f&quot;unknown, {hit.revocation_note}&quot;
        return &quot;unknown&quot;
    return &quot;not revoked&quot;</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_scan.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>one_line_revocation</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## san_tail_split

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def san_tail_split(domain: str) -&gt; tuple[list[str], str]:
    labels = domain.split(&quot;.&quot;)
    common_second_level = {&quot;ac&quot;, &quot;co&quot;, &quot;com&quot;, &quot;edu&quot;, &quot;gov&quot;, &quot;net&quot;, &quot;org&quot;}
    suffix_len = 2
    if len(labels) &gt;= 3 and len(labels[-1]) == 2 and labels[-2] in common_second_level:
        suffix_len = 3
    if len(labels) &lt;= suffix_len:
        return ([], domain)
    return (labels[:-suffix_len], &quot;.&quot;.join(labels[-suffix_len:]))</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_scan.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>san_tail_split</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## build_san_tree_lines

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def build_san_tree_lines(san_entries: list[str]) -&gt; list[str]:
    return build_san_tree_lines_with_style(san_entries, ascii_only=False)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This block constructs a richer higher-level result from simpler inputs.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>build_san_tree_lines</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## build_san_tree_units_with_style

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def build_san_tree_units_with_style(san_entries: list[str], ascii_only: bool) -&gt; list[list[str]]:
    dns_entries = sorted({entry[4:] for entry in san_entries if entry.startswith(&quot;DNS:&quot;)})
    other_entries = sorted({entry for entry in san_entries if not entry.startswith(&quot;DNS:&quot;)})
    tree: dict[str, Any] = {}
    for domain in dns_entries:
        prefix_labels, tail = san_tail_split(domain)
        cursor = tree
        for label in prefix_labels:
            cursor = cursor.setdefault(label, {})
        cursor.setdefault(tail, {})

    def render(node: dict[str, Any], prefix: str = &quot;&quot;) -&gt; list[str]:
        lines: list[str] = []
        keys = sorted(node.keys(), key=str.casefold)
        for index, key in enumerate(keys):
            is_last = index == len(keys) - 1
            if ascii_only:
                connector = &quot;`- &quot; if is_last else &quot;|- &quot;
            else:
                connector = &quot;└─ &quot; if is_last else &quot;├─ &quot;
            lines.append(prefix + connector + key)
            child = node[key]
            if ascii_only:
                child_prefix = prefix + (&quot;   &quot; if is_last else &quot;|  &quot;)
            else:
                child_prefix = prefix + (&quot;   &quot; if is_last else &quot;│  &quot;)
            lines.extend(render(child, child_prefix))
        return lines

    units: list[list[str]] = []
    for key in sorted(tree.keys(), key=str.casefold):
        units.append(render({key: tree[key]}))
    for entry in other_entries:
        units.append([f&quot;{&#x27;*&#x27; if ascii_only else &#x27;•&#x27;} {entry}&quot;])
    if not units:
        units.append([f&quot;{&#x27;*&#x27; if ascii_only else &#x27;•&#x27;} -&quot;])
    return units</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This block constructs a richer higher-level result from simpler inputs.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>build_san_tree_units_with_style</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## build_san_tree_chunks_with_style

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def build_san_tree_chunks_with_style(
    san_entries: list[str],
    ascii_only: bool,
    max_lines_per_chunk: int = 24,
) -&gt; list[list[str]]:
    chunks: list[list[str]] = []
    current_chunk: list[str] = []
    current_lines = 0

    def flush_current_chunk() -&gt; None:
        nonlocal current_chunk, current_lines
        if current_chunk:
            chunks.append(current_chunk)
            current_chunk = []
            current_lines = 0

    for unit in build_san_tree_units_with_style(san_entries, ascii_only=ascii_only):
        if len(unit) &gt; max_lines_per_chunk:
            flush_current_chunk()
            for start in range(0, len(unit), max_lines_per_chunk):
                chunks.append(unit[start : start + max_lines_per_chunk])
            continue
        if current_chunk and current_lines + len(unit) &gt; max_lines_per_chunk:
            flush_current_chunk()
        current_chunk.extend(unit)
        current_lines += len(unit)

    flush_current_chunk()
    return chunks</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This block constructs a richer higher-level result from simpler inputs.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>build_san_tree_chunks_with_style</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## build_san_tree_lines_with_style

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def build_san_tree_lines_with_style(san_entries: list[str], ascii_only: bool) -&gt; list[str]:
    lines: list[str] = []
    for chunk in build_san_tree_chunks_with_style(
        san_entries,
        ascii_only=ascii_only,
        max_lines_per_chunk=10_000,
    ):
        lines.extend(chunk)
    return lines</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This block constructs a richer higher-level result from simpler inputs.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>build_san_tree_lines_with_style</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## group_hits_by_issuer

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def group_hits_by_issuer(hits: list[CertificateHit]) -&gt; tuple[dict[str, list[CertificateHit]], list[str]]:
    issuer_hits: dict[str, list[CertificateHit]] = defaultdict(list)
    for hit in hits:
        issuer_hits[primary_issuer_name(hit)].append(hit)
    ordered_issuers = sorted(
        issuer_hits,
        key=lambda issuer_name: (-len(issuer_hits[issuer_name]), issuer_name.casefold()),
    )
    return issuer_hits, ordered_issuers</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This block clusters related items together so later code can analyze them as families instead of as isolated rows.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>group_hits_by_issuer</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## latex_escape

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def latex_escape(value: str) -&gt; str:
    replacements = {
        &quot;\\&quot;: r&quot;\textbackslash{}&quot;,
        &quot;&amp;&quot;: r&quot;\&amp;&quot;,
        &quot;%&quot;: r&quot;\%&quot;,
        &quot;$&quot;: r&quot;\$&quot;,
        &quot;#&quot;: r&quot;\#&quot;,
        &quot;_&quot;: r&quot;\_&quot;,
        &quot;{&quot;: r&quot;\{&quot;,
        &quot;}&quot;: r&quot;\}&quot;,
        &quot;~&quot;: r&quot;\textasciitilde{}&quot;,
        &quot;^&quot;: r&quot;\textasciicircum{}&quot;,
    }
    return &quot;&quot;.join(replacements.get(char, char) for char in value)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_scan.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>latex_escape</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## summarize_san_patterns

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def summarize_san_patterns(san_entries: list[str]) -&gt; dict[str, Any]:
    dns_entries = sorted({entry[4:] for entry in san_entries if entry.startswith(&quot;DNS:&quot;)}, key=str.casefold)
    other_entries = sorted({entry for entry in san_entries if not entry.startswith(&quot;DNS:&quot;)}, key=str.casefold)
    zone_counts: Counter[str] = Counter()
    normalized_pattern_counts: Counter[str] = Counter()
    wildcard_count = 0
    numbered_count = 0
    for domain in dns_entries:
        normalized_domain = domain[2:] if domain.startswith(&quot;*.&quot;) else domain
        if domain.startswith(&quot;*.&quot;):
            wildcard_count += 1
        if re.search(r&quot;\d&quot;, normalized_domain):
            numbered_count += 1
        prefix_labels, tail = san_tail_split(normalized_domain)
        zone_counts[tail] += 1
        normalized_prefix = &quot;.&quot;.join(re.sub(r&quot;\d+&quot;, &quot;#&quot;, label) for label in prefix_labels if label)
        if normalized_prefix:
            normalized_pattern_counts[f&quot;{normalized_prefix}.{tail}&quot;] += 1
        else:
            normalized_pattern_counts[tail] += 1
    repeating_patterns = [
        (pattern, count)
        for pattern, count in normalized_pattern_counts.most_common(6)
        if count &gt; 1
    ]
    return {
        &quot;dns_count&quot;: len(dns_entries),
        &quot;other_count&quot;: len(other_entries),
        &quot;wildcard_count&quot;: wildcard_count,
        &quot;numbered_count&quot;: numbered_count,
        &quot;zone_count&quot;: len(zone_counts),
        &quot;top_zones&quot;: zone_counts.most_common(6),
        &quot;repeating_patterns&quot;: repeating_patterns,
    }</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This block compresses many detailed rows into a smaller, easier-to-read summary.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>summarize_san_patterns</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## latex_status_badge

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def latex_status_badge(status: str) -&gt; str:
    return {
        &quot;not_revoked&quot;: r&quot;\StatusOK{}&quot;,
        &quot;revoked&quot;: r&quot;\StatusREV{}&quot;,
        &quot;unknown&quot;: r&quot;\StatusUNK{}&quot;,
    }[status]</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_scan.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>latex_status_badge</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## latex_webpki_badge

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def latex_webpki_badge(value: bool) -&gt; str:
    return r&quot;\WebPKIYes{}&quot; if value else r&quot;\WebPKINo{}&quot;</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_scan.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>latex_webpki_badge</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## render_markdown_report

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def render_markdown_report(
    path: Path,
    hits: list[CertificateHit],
    groups: list[CertificateGroup],
    stats: ScanStats,
    issuer_trust: dict[str, IssuerTrustInfo],
) -&gt; None:
    path.parent.mkdir(parents=True, exist_ok=True)
    issuer_hits, ordered_issuers = group_hits_by_issuer(hits)
    lines: list[str] = []
    lines.append(&quot;# Certificate CN Family Report&quot;)
    lines.append(&quot;&quot;)
    lines.append(f&quot;Generated: {stats.generated_at_utc}&quot;)
    lines.append(f&quot;Configured domains: {&#x27;, &#x27;.join(stats.configured_domains)}&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;## What This File Contains&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;- Chapters are built from Subject CN construction only.&quot;)
    lines.append(&quot;- If multiple concrete CNs share the same numbered schema, they are grouped together.&quot;)
    lines.append(&quot;- Otherwise the chapter is one endpoint family; `www.` is grouped with the base name as a low-signal convenience.&quot;)
    lines.append(&quot;- SAN entries are shown only inside each Subject CN subsection.&quot;)
    lines.append(&quot;- All certificates shown here are verified leaf certificates.&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;## Issuer Overview&quot;)
    lines.append(&quot;&quot;)
    for issuer_name in ordered_issuers:
        trust = issuer_trust[issuer_name]
        ca_ids = &quot;, &quot;.join(str(value) for value in sorted(trust.issuer_ca_ids))
        trust_label = &quot;YES&quot; if trust.major_webpki else &quot;NO&quot;
        lines.append(
            f&quot;- {issuer_name} | certificates={len(issuer_hits[issuer_name])} | WebPKI server-auth in major stores={trust_label} | ca_id={ca_ids}&quot;
        )
    lines.append(&quot;&quot;)
    lines.append(&quot;## Leaf-Certificate Assurance&quot;)
    lines.append(&quot;&quot;)
    lines.append(&quot;- SQL filter: `certificate_lifecycle.certificate_type = &#x27;Certificate&#x27;`&quot;)
    lines.append(&quot;- Local filter: precertificate poison absent, `BasicConstraints.ca != true`, `KeyUsage.keyCertSign != true`&quot;)
    lines.append(f&quot;- Verified leaf certificates kept: {stats.unique_leaf_certificates}&quot;)
    lines.append(f&quot;- Non-leaf filtered after download: {stats.verification.non_leaf_filtered}&quot;)
    lines.append(f&quot;- Precertificate poison filtered after download: {stats.verification.precertificate_poison_filtered}&quot;)
    lines.append(&quot;&quot;)
    for issuer_position, issuer_name in enumerate(ordered_issuers, start=1):
        trust = issuer_trust[issuer_name]
        issuer_title = f&quot;Issuer {issuer_position:02d}  {issuer_name}&quot;
        lines.append(f&quot;## {issuer_title}&quot;)
        lines.append(&quot;&quot;)
        lines.append(f&quot;- Certificates under issuer: {len(issuer_hits[issuer_name])}&quot;)
        lines.append(
            f&quot;- WebPKI server-auth in major stores (Mozilla, Chrome, Apple, Microsoft, Android): {&#x27;YES&#x27; if trust.major_webpki else &#x27;NO&#x27;}&quot;
        )
        lines.append(
            f&quot;- Server-auth trust contexts seen in crt.sh live trust data: {&#x27;, &#x27;.join(sorted(trust.server_auth_contexts)) if trust.server_auth_contexts else &#x27;none&#x27;}&quot;
        )
        lines.append(f&quot;- Issuer CA IDs: {&#x27;, &#x27;.join(str(value) for value in sorted(trust.issuer_ca_ids))}&quot;)
        lines.append(&quot;&quot;)
        issuer_groups = build_groups(issuer_hits[issuer_name])
        for family_index, group in enumerate(issuer_groups, start=1):
            member_hits = [issuer_hits[issuer_name][index] for index in group.member_indices]
            chapter_title = f&quot;Family {family_index:02d}  {describe_group_basis(group)}&quot;
            lines.append(f&quot;### {chapter_title}&quot;)
            lines.append(&quot;&quot;)
            lines.append(f&quot;- Certificates in chapter: {group.member_count}&quot;)
            lines.append(f&quot;- Concrete Subject CNs: {group.distinct_subject_cn_count}&quot;)
            lines.append(f&quot;- Distinct SAN profiles in chapter: {group.distinct_exact_content_count}&quot;)
            lines.append(f&quot;- Matched domains: {&#x27;, &#x27;.join(sorted(group.matched_domains))}&quot;)
            lines.append(f&quot;- Family validity span: {utc_iso(group.valid_from_min)} -&gt; {utc_iso(group.valid_to_max)}&quot;)
            if group.first_seen_min and group.first_seen_max:
                lines.append(f&quot;- First seen span: {utc_iso(group.first_seen_min)} -&gt; {utc_iso(group.first_seen_max)}&quot;)
            lines.append(f&quot;- Revocation mix: {group.revocation_counts.get(&#x27;revoked&#x27;, 0)} revoked, {group.revocation_counts.get(&#x27;not_revoked&#x27;, 0)} not revoked, {group.revocation_counts.get(&#x27;unknown&#x27;, 0)} unknown&quot;)
            lines.append(&quot;&quot;)

            hits_by_subject: dict[str, list[CertificateHit]] = defaultdict(list)
            for hit in member_hits:
                hits_by_subject[hit.subject_cn].append(hit)

            ordered_subjects = sorted(
                hits_by_subject.keys(),
                key=lambda value: (canonicalize_subject_cn(value), value.casefold()),
            )
            for subject_cn in ordered_subjects:
                subject_hits = sorted(
                    hits_by_subject[subject_cn],
                    key=lambda hit: (hit.validity_not_before, hit.validity_not_after, hit.fingerprint_sha256),
                )
                lines.append(f&quot;#### Subject CN: `{subject_cn}`&quot;)
                lines.append(&quot;&quot;)
                lines.append(f&quot;- Certificates under this CN: {len(subject_hits)}&quot;)
                lines.append(f&quot;- Validity span under this CN: {utc_iso(min(hit.validity_not_before for hit in subject_hits))} -&gt; {utc_iso(max(hit.validity_not_after for hit in subject_hits))}&quot;)
                san_profiles: dict[tuple[str, ...], list[CertificateHit]] = defaultdict(list)
                for hit in subject_hits:
                    san_profiles[tuple(hit.san_entries)].append(hit)
                profile_size_counts = Counter(len(profile) for profile in san_profiles)
                unique_san_entries = sorted({entry for hit in subject_hits for entry in hit.san_entries})
                lines.append(f&quot;- Distinct SAN profiles under this CN: {len(san_profiles)}&quot;)
                lines.append(
                    &quot;- SAN profile sizes seen: &quot;
                    + &quot;, &quot;.join(
                        f&quot;{size} SAN x {count}&quot;
                        for size, count in sorted(profile_size_counts.items())
                    )
                )
                lines.append(&quot;&quot;)
                lines.append(&quot;Validity history&quot;)
                lines.append(&quot;&quot;)

                for hit in subject_hits:
                    crtsh_ids = &quot;, &quot;.join(str(value) for value in sorted(hit.crtsh_certificate_ids))
                    lines.append(
                        f&quot;- [{status_marker(hit.revocation_status)}] {utc_iso(hit.validity_not_before)} -&gt; {utc_iso(hit.validity_not_after)} | SANs={len(hit.san_entries)} | crt.sh={crtsh_ids} | {one_line_revocation(hit)}&quot;
                    )
                lines.append(&quot;&quot;)
                lines.append(&quot;SAN structure&quot;)
                lines.append(&quot;&quot;)
                lines.append(&quot;```text&quot;)
                for tree_line in build_san_tree_lines(unique_san_entries):
                    lines.append(tree_line)
                lines.append(&quot;```&quot;)
                lines.append(&quot;&quot;)

        lines.append(&quot;---&quot;)
        lines.append(&quot;&quot;)

    lines.append(&quot;## Statistics&quot;)
    lines.append(&quot;&quot;)
    lines.append(f&quot;- Unique leaf certificates: {stats.unique_leaf_certificates}&quot;)
    lines.append(f&quot;- CN-family chapters: {stats.groups_total}&quot;)
    lines.append(f&quot;- Chapters with more than one certificate: {stats.groups_multi_member}&quot;)
    lines.append(f&quot;- Single-certificate chapters: {stats.groups_singleton}&quot;)
    lines.append(f&quot;- Numbered CN pattern chapters: {stats.groups_by_type.get(&#x27;numbered_cn_pattern&#x27;, 0)}&quot;)
    lines.append(f&quot;- Exact endpoint chapters: {stats.groups_by_type.get(&#x27;exact_endpoint_family&#x27;, 0)}&quot;)
    lines.append(&quot;&quot;)
    path.write_text(&quot;\n&quot;.join(lines) + &quot;\n&quot;, encoding=&quot;utf-8&quot;)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Writes the raw inventory appendix as readable Markdown.</p>
<p><strong>Flow arrows</strong></p><p>Current hits, groups, and trust data. &#8594; <strong>render_markdown_report</strong> &#8594; Produces the Markdown inventory appendix.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## render_latex_report

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def render_latex_report(
    path: Path,
    hits: list[CertificateHit],
    groups: list[CertificateGroup],
    stats: ScanStats,
    issuer_trust: dict[str, IssuerTrustInfo],
    show_page_numbers: bool = True,
) -&gt; None:
    path.parent.mkdir(parents=True, exist_ok=True)
    issuer_hits, ordered_issuers = group_hits_by_issuer(hits)
    revoked_total = sum(1 for hit in hits if hit.revocation_status == &quot;revoked&quot;)
    unknown_total = sum(1 for hit in hits if hit.revocation_status == &quot;unknown&quot;)
    not_revoked_total = sum(1 for hit in hits if hit.revocation_status == &quot;not_revoked&quot;)

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
        r&quot;\usepackage{titlesec}&quot;,
        r&quot;\usepackage[most]{tcolorbox}&quot;,
        r&quot;\usepackage{fancyvrb}&quot;,
        r&quot;\usepackage{needspace}&quot;,
        r&quot;\defaultfontfeatures{Ligatures=TeX,Scale=MatchLowercase}&quot;,
        r&quot;\definecolor{Ink}{HTML}{17202A}&quot;,
        r&quot;\definecolor{Muted}{HTML}{667085}&quot;,
        r&quot;\definecolor{Line}{HTML}{D0D5DD}&quot;,
        r&quot;\definecolor{Panel}{HTML}{F8FAFC}&quot;,
        r&quot;\definecolor{Accent}{HTML}{0F766E}&quot;,
        r&quot;\definecolor{AccentSoft}{HTML}{E6F4F1}&quot;,
        r&quot;\definecolor{AccentLine}{HTML}{74C4B8}&quot;,
        r&quot;\definecolor{Warn}{HTML}{9A6700}&quot;,
        r&quot;\definecolor{WarnSoft}{HTML}{FFF4DB}&quot;,
        r&quot;\definecolor{Danger}{HTML}{B42318}&quot;,
        r&quot;\definecolor{DangerSoft}{HTML}{FEE4E2}&quot;,
        r&quot;\definecolor{OkText}{HTML}{065F46}&quot;,
        r&quot;\definecolor{OkSoft}{HTML}{DCFCE7}&quot;,
        r&quot;\definecolor{UnknownText}{HTML}{9A6700}&quot;,
        r&quot;\definecolor{UnknownSoft}{HTML}{FEF3C7}&quot;,
        r&quot;\hypersetup{colorlinks=true,linkcolor=Accent,urlcolor=Accent,pdfauthor={CertTransparencySearch},pdftitle={Certificate Transparency Endpoint Atlas}}&quot;,
        r&quot;\setlength{\parindent}{0pt}&quot;,
        r&quot;\setlength{\parskip}{6pt}&quot;,
        r&quot;\setlength{\emergencystretch}{3em}&quot;,
        r&quot;\setlength{\footskip}{24pt}&quot;,
        r&quot;\setlength{\tabcolsep}{4.2pt}&quot;,
        r&quot;\renewcommand{\arraystretch}{1.12}&quot;,
        r&quot;\raggedbottom&quot;,
        r&quot;\setcounter{tocdepth}{2}&quot;,
        rf&quot;\pagestyle{{{&#x27;plain&#x27; if show_page_numbers else &#x27;empty&#x27;}}}&quot;,
        r&quot;\titleformat{\section}{\sffamily\bfseries\LARGE\color{Ink}\raggedright}{\thesection}{0.8em}{}&quot;,
        r&quot;\titleformat{\subsection}{\sffamily\bfseries\Large\color{Ink}\raggedright}{\thesubsection}{0.8em}{}&quot;,
        r&quot;\titleformat{\subsubsection}{\sffamily\bfseries\normalsize\color{Ink}\raggedright}{\thesubsubsection}{0.8em}{}&quot;,
        r&quot;\tcbset{&quot;,
        r&quot;  panel/.style={enhanced,breakable,boxrule=0.55pt,arc=3pt,left=9pt,right=9pt,top=8pt,bottom=8pt,colback=white,colframe=Line},&quot;,
        r&quot;  hero/.style={panel,colback=Ink,colframe=Ink,left=14pt,right=14pt,top=14pt,bottom=14pt},&quot;,
        r&quot;  summary/.style={panel,colback=Panel,colframe=Line},&quot;,
        r&quot;  issuerpanel/.style={panel,colback=Panel,colframe=Ink!45},&quot;,
        r&quot;  familypanel/.style={panel,colback=AccentSoft,colframe=AccentLine},&quot;,
        r&quot;  subjectpanel/.style={panel,colback=white,colframe=Line},&quot;,
        r&quot;  treepanel/.style={enhanced,boxrule=0.55pt,arc=3pt,left=9pt,right=9pt,top=8pt,bottom=8pt,colback=Panel,colframe=AccentLine},&quot;,
        r&quot;}&quot;,
        r&quot;\newcommand{\DomainChip}[1]{\tcbox[on line,boxrule=0pt,arc=3pt,left=5pt,right=5pt,top=2pt,bottom=2pt,colback=AccentSoft]{\sffamily\footnotesize\texttt{#1}}}&quot;,
        r&quot;\newcommand{\MetricChip}[2]{\tcbox[on line,boxrule=0pt,arc=3pt,left=6pt,right=6pt,top=3pt,bottom=3pt,colback=Panel]{\sffamily\footnotesize\textcolor{Muted}{#1}\hspace{0.45em}\textbf{#2}}}&quot;,
        r&quot;\newcommand{\StatusOK}{\tcbox[on line,boxrule=0pt,arc=3pt,left=5pt,right=5pt,top=2pt,bottom=2pt,colback=OkSoft]{\sffamily\bfseries\footnotesize\textcolor{OkText}{OK}}}&quot;,
        r&quot;\newcommand{\StatusREV}{\tcbox[on line,boxrule=0pt,arc=3pt,left=5pt,right=5pt,top=2pt,bottom=2pt,colback=DangerSoft]{\sffamily\bfseries\footnotesize\textcolor{Danger}{REV}}}&quot;,
        r&quot;\newcommand{\StatusUNK}{\tcbox[on line,boxrule=0pt,arc=3pt,left=5pt,right=5pt,top=2pt,bottom=2pt,colback=UnknownSoft]{\sffamily\bfseries\footnotesize\textcolor{UnknownText}{UNK}}}&quot;,
        r&quot;\newcommand{\WebPKIYes}{\tcbox[on line,boxrule=0pt,arc=3pt,left=5pt,right=5pt,top=2pt,bottom=2pt,colback=OkSoft]{\sffamily\bfseries\footnotesize\textcolor{OkText}{WebPKI: YES}}}&quot;,
        r&quot;\newcommand{\WebPKINo}{\tcbox[on line,boxrule=0pt,arc=3pt,left=5pt,right=5pt,top=2pt,bottom=2pt,colback=DangerSoft]{\sffamily\bfseries\footnotesize\textcolor{Danger}{WebPKI: NO}}}&quot;,
        r&quot;\begin{document}&quot;,
        r&quot;\begin{titlepage}&quot;,
        r&quot;\thispagestyle{empty}&quot;,
        r&quot;\vspace*{20mm}&quot;,
        r&quot;\begin{tcolorbox}[hero]&quot;,
        r&quot;{\color{white}\sffamily\bfseries\fontsize{24}{28}\selectfont Certificate Transparency Endpoint Atlas\par}&quot;,
        r&quot;\vspace{4pt}&quot;,
        r&quot;{\color{white}\Large Currently valid leaf certificates matching the configured domains\par}&quot;,
        r&quot;\vspace{12pt}&quot;,
        r&quot;{\color{white}\sffamily\small This artefact is optimized for review: issuer-first navigation, CN-family grouping, certificate timelines, and SAN structure blocks designed to be read rather than decoded.}&quot;,
        r&quot;\end{tcolorbox}&quot;,
        r&quot;\vspace{10mm}&quot;,
        r&quot;\begin{tcolorbox}[summary]&quot;,
        rf&quot;\textbf{{Generated}}: {latex_escape(stats.generated_at_utc)}\par&quot;,
        r&quot;\textbf{Configured domains}: &quot; + &quot; &quot;.join(
            rf&quot;\DomainChip{{{latex_escape(domain)}}}&quot; for domain in stats.configured_domains
        ),
        r&quot;\par\medskip&quot;,
        r&quot;\MetricChip{Leaf certificates}{&quot; + str(stats.unique_leaf_certificates) + r&quot;}&quot; + &quot; &quot;
        + r&quot;\MetricChip{CN families}{&quot; + str(stats.groups_total) + r&quot;}&quot; + &quot; &quot;
        + r&quot;\MetricChip{Numbered families}{&quot; + str(stats.groups_by_type.get(&quot;numbered_cn_pattern&quot;, 0)) + r&quot;}&quot; + &quot; &quot;
        + r&quot;\MetricChip{Exact families}{&quot; + str(stats.groups_by_type.get(&quot;exact_endpoint_family&quot;, 0)) + r&quot;}&quot;,
        r&quot;\par\medskip&quot;,
        r&quot;\MetricChip{Not revoked}{&quot; + str(not_revoked_total) + r&quot;}&quot; + &quot; &quot;
        + r&quot;\MetricChip{Revoked}{&quot; + str(revoked_total) + r&quot;}&quot; + &quot; &quot;
        + r&quot;\MetricChip{Unknown}{&quot; + str(unknown_total) + r&quot;}&quot;,
        r&quot;\end{tcolorbox}&quot;,
        r&quot;\vfill&quot;,
        r&quot;{\sffamily\small\textcolor{Muted}{Same scan, three outputs: Markdown for editor preview, LaTeX for source control, PDF for distribution.}}&quot;,
        r&quot;\end{titlepage}&quot;,
        r&quot;\tableofcontents&quot;,
        r&quot;\clearpage&quot;,
        r&quot;\section*{Executive Summary}&quot;,
        r&quot;\addcontentsline{toc}{section}{Executive Summary}&quot;,
        r&quot;\begin{tcolorbox}[summary]&quot;,
        r&quot;\textbf{Reading guide}\par&quot;,
        r&quot;Major chapters are exact issuer names. Inside each issuer, families are derived only from the construction of the Subject CN. Each concrete Subject CN then gets its own certificate timeline and a SAN structure panel.\par&quot;,
        r&quot;\medskip&quot;,
        r&quot;\textbf{Leaf-only assurance}\par&quot;,
        r&quot;SQL excludes entries whose lifecycle type is not \texttt{Certificate}. Local parsing then rejects any artifact with precertificate poison, \texttt{BasicConstraints.ca = true}, or \texttt{KeyUsage.keyCertSign = true}.&quot;,
        r&quot;\end{tcolorbox}&quot;,
        r&quot;\begin{tcolorbox}[summary]&quot;,
        r&quot;\textbf{Issuer landscape}\par&quot;,
        r&quot;\medskip&quot;,
        r&quot;\begin{tabularx}{\linewidth}{&gt;{\raggedright\arraybackslash}X &gt;{\raggedleft\arraybackslash}p{1.7cm} &gt;{\raggedleft\arraybackslash}p{1.9cm} &gt;{\raggedleft\arraybackslash}p{2.0cm}}&quot;,
        r&quot;\toprule&quot;,
        r&quot;Issuer &amp; Certificates &amp; Share &amp; WebPKI \\&quot;,
        r&quot;\midrule&quot;,
    ]

    total_hits = len(hits) if hits else 1
    for issuer_name in ordered_issuers:
        issuer_count = len(issuer_hits[issuer_name])
        share = f&quot;{issuer_count / total_hits:.1%}&quot;
        lines.append(
            rf&quot;{latex_escape(issuer_name)} &amp; {issuer_count} &amp; {latex_escape(share)} &amp; {latex_webpki_badge(issuer_trust[issuer_name].major_webpki)} \\&quot;
        )
    lines.extend(
        [
            r&quot;\bottomrule&quot;,
            r&quot;\end{tabularx}&quot;,
            r&quot;\end{tcolorbox}&quot;,
        ]
    )

    for issuer_position, issuer_name in enumerate(ordered_issuers, start=1):
        trust = issuer_trust[issuer_name]
        issuer_groups = build_groups(issuer_hits[issuer_name])
        lines.extend(
            [
                r&quot;\clearpage&quot;,
                rf&quot;\section{{Issuer {issuer_position:02d}: {latex_escape(issuer_name)}}}&quot;,
                r&quot;\begin{tcolorbox}[issuerpanel]&quot;,
                r&quot;\MetricChip{Certificates}{&quot; + str(len(issuer_hits[issuer_name])) + r&quot;}&quot; + &quot; &quot;
                + r&quot;\MetricChip{Families}{&quot; + str(len(issuer_groups)) + r&quot;}&quot; + &quot; &quot;
                + latex_webpki_badge(trust.major_webpki),
                r&quot;\par\medskip&quot;,
                rf&quot;\textbf{{Trust contexts seen in crt.sh live data}}: {latex_escape(&#x27;, &#x27;.join(sorted(trust.server_auth_contexts)) if trust.server_auth_contexts else &#x27;none&#x27;)}\par&quot;,
                rf&quot;\textbf{{Issuer CA IDs}}: {latex_escape(&#x27;, &#x27;.join(str(value) for value in sorted(trust.issuer_ca_ids)))}&quot;,
                r&quot;\end{tcolorbox}&quot;,
            ]
        )
        for family_index, group in enumerate(issuer_groups, start=1):
            member_hits = [issuer_hits[issuer_name][index] for index in group.member_indices]
            lines.extend(
                [
                    r&quot;\Needspace{14\baselineskip}&quot;,
                    rf&quot;\subsection{{Family {family_index:02d}: {latex_escape(describe_group_basis(group).replace(&#x27;`&#x27;, &#x27;&#x27;))}}}&quot;,
                    r&quot;\begin{tcolorbox}[familypanel]&quot;,
                    r&quot;\MetricChip{Certificates}{&quot; + str(group.member_count) + r&quot;}&quot; + &quot; &quot;
                    + r&quot;\MetricChip{Concrete CNs}{&quot; + str(group.distinct_subject_cn_count) + r&quot;}&quot; + &quot; &quot;
                    + r&quot;\MetricChip{Distinct SAN profiles}{&quot; + str(group.distinct_exact_content_count) + r&quot;}&quot;,
                    r&quot;\par\medskip&quot;,
                    rf&quot;\textbf{{Matched domains}}: {&#x27; &#x27;.join(rf&#x27;\DomainChip{{{latex_escape(domain)}}}&#x27; for domain in sorted(group.matched_domains))}\par&quot;,
                    rf&quot;\textbf{{Family validity span}}: \texttt{{{latex_escape(utc_iso(group.valid_from_min))}}} to \texttt{{{latex_escape(utc_iso(group.valid_to_max))}}}\par&quot;,
                    (
                        rf&quot;\textbf{{First seen span}}: \texttt{{{latex_escape(utc_iso(group.first_seen_min))}}} to \texttt{{{latex_escape(utc_iso(group.first_seen_max))}}}\par&quot;
                        if group.first_seen_min and group.first_seen_max
                        else &quot;&quot;
                    ),
                    rf&quot;\textbf{{Revocation mix}}: {group.revocation_counts.get(&#x27;revoked&#x27;, 0)} revoked, {group.revocation_counts.get(&#x27;not_revoked&#x27;, 0)} not revoked, {group.revocation_counts.get(&#x27;unknown&#x27;, 0)} unknown&quot;,
                    r&quot;\end{tcolorbox}&quot;,
                ]
            )

            hits_by_subject: dict[str, list[CertificateHit]] = defaultdict(list)
            for hit in member_hits:
                hits_by_subject[hit.subject_cn].append(hit)
            ordered_subjects = sorted(
                hits_by_subject.keys(),
                key=lambda value: (canonicalize_subject_cn(value), value.casefold()),
            )
            for subject_cn in ordered_subjects:
                subject_hits = sorted(
                    hits_by_subject[subject_cn],
                    key=lambda hit: (hit.validity_not_before, hit.validity_not_after, hit.fingerprint_sha256),
                )
                san_summary = summarize_san_patterns(sorted({entry for hit in subject_hits for entry in hit.san_entries}))
                unique_san_entries = sorted({entry for hit in subject_hits for entry in hit.san_entries})
                lines.extend(
                    [
                        r&quot;\Needspace{18\baselineskip}&quot;,
                        rf&quot;\subsubsection{{Subject CN: {latex_escape(subject_cn)}}}&quot;,
                        r&quot;\begin{tcolorbox}[subjectpanel]&quot;,
                        r&quot;\MetricChip{Certificates under this CN}{&quot; + str(len(subject_hits)) + r&quot;}&quot; + &quot; &quot;
                        + r&quot;\MetricChip{Distinct SAN profiles}{&quot; + str(len({tuple(hit.san_entries) for hit in subject_hits})) + r&quot;}&quot; + &quot; &quot;
                        + r&quot;\MetricChip{Unique SAN entries}{&quot; + str(len(unique_san_entries)) + r&quot;}&quot;,
                        r&quot;\par\medskip&quot;,
                        rf&quot;\textbf{{Validity span under this CN}}: \texttt{{{latex_escape(utc_iso(min(hit.validity_not_before for hit in subject_hits)))}}} to \texttt{{{latex_escape(utc_iso(max(hit.validity_not_after for hit in subject_hits)))}}}&quot;,
                        r&quot;\par\medskip&quot;,
                        r&quot;\textbf{Certificate timeline}&quot;,
                        r&quot;\begin{itemize}[leftmargin=1.4em,itemsep=0.55em,topsep=0.4em]&quot;,
                    ]
                )
                for hit in subject_hits:
                    crtsh_ids = &quot;, &quot;.join(str(value) for value in sorted(hit.crtsh_certificate_ids))
                    lines.extend(
                        [
                            r&quot;\item &quot;
                            + latex_status_badge(hit.revocation_status)
                            + &quot; &quot;
                            + rf&quot;\texttt{{{latex_escape(utc_iso(hit.validity_not_before))}}} to \texttt{{{latex_escape(utc_iso(hit.validity_not_after))}}}&quot;,
                            rf&quot;\newline \textcolor{{Muted}}{{SANs: {len(hit.san_entries)} \quad crt.sh: {latex_escape(crtsh_ids)} \quad {latex_escape(one_line_revocation(hit))}}}&quot;,
                        ]
                    )
                tree_chunks = build_san_tree_chunks_with_style(
                    unique_san_entries,
                    ascii_only=True,
                    max_lines_per_chunk=24,
                )
                lines.extend(
                    [
                        r&quot;\end{itemize}&quot;,
                        r&quot;\medskip&quot;,
                        r&quot;\textbf{SAN pattern snapshot}&quot;,
                        r&quot;\par\medskip&quot;,
                        r&quot;\MetricChip{DNS SANs}{&quot; + str(san_summary[&quot;dns_count&quot;]) + r&quot;}&quot; + &quot; &quot;
                        + r&quot;\MetricChip{Other SANs}{&quot; + str(san_summary[&quot;other_count&quot;]) + r&quot;}&quot; + &quot; &quot;
                        + r&quot;\MetricChip{Wildcard SANs}{&quot; + str(san_summary[&quot;wildcard_count&quot;]) + r&quot;}&quot; + &quot; &quot;
                        + r&quot;\MetricChip{Numbered SANs}{&quot; + str(san_summary[&quot;numbered_count&quot;]) + r&quot;}&quot; + &quot; &quot;
                        + r&quot;\MetricChip{DNS zones}{&quot; + str(san_summary[&quot;zone_count&quot;]) + r&quot;}&quot;,
                        r&quot;\par\medskip&quot;,
                        rf&quot;\textbf{{Dominant zones}}: {latex_escape(&#x27;, &#x27;.join(f&#x27;{zone} ({count})&#x27; for zone, count in san_summary[&#x27;top_zones&#x27;]) if san_summary[&#x27;top_zones&#x27;] else &#x27;none&#x27;)}&quot;,
                        r&quot;\par&quot;,
                        rf&quot;\textbf{{Repeating host schemas}}: {latex_escape(&#x27;, &#x27;.join(f&#x27;{pattern} ({count})&#x27; for pattern, count in san_summary[&#x27;repeating_patterns&#x27;]) if san_summary[&#x27;repeating_patterns&#x27;] else &#x27;mostly one-off SAN hostnames&#x27;)}&quot;,
                        (
                            rf&quot;\par\medskip\textcolor{{Muted}}{{The SAN structure below is shown in {len(tree_chunks)} intact panels so the visual grouping is not broken across a page.}}&quot;
                            if len(tree_chunks) &gt; 1
                            else &quot;&quot;
                        ),
                        r&quot;\end{tcolorbox}&quot;,
                    ]
                )
                for tree_chunk_index, tree_lines in enumerate(tree_chunks, start=1):
                    tree_title = (
                        &quot;SAN Structure&quot;
                        if len(tree_chunks) == 1
                        else f&quot;SAN Structure ({tree_chunk_index}/{len(tree_chunks)})&quot;
                    )
                    tree_needspace = max(12, min(len(tree_lines) + 7, 32))
                    lines.extend(
                        [
                            rf&quot;\Needspace{{{tree_needspace}\baselineskip}}&quot;,
                            rf&quot;\begin{{tcolorbox}}[treepanel,title={{{latex_escape(tree_title)}}}]&quot;,
                            r&quot;\begin{Verbatim}[fontsize=\footnotesize]&quot;,
                        ]
                    )
                    lines.extend(tree_lines)
                    lines.extend(
                        [
                            r&quot;\end{Verbatim}&quot;,
                            r&quot;\end{tcolorbox}&quot;,
                        ]
                    )

    lines.extend(
        [
            r&quot;\clearpage&quot;,
            r&quot;\section*{Statistics}&quot;,
            r&quot;\addcontentsline{toc}{section}{Statistics}&quot;,
            r&quot;\begin{tcolorbox}[summary]&quot;,
            r&quot;\MetricChip{Unique leaf certificates}{&quot; + str(stats.unique_leaf_certificates) + r&quot;}&quot; + &quot; &quot;
            + r&quot;\MetricChip{CN-family chapters}{&quot; + str(stats.groups_total) + r&quot;}&quot; + &quot; &quot;
            + r&quot;\MetricChip{Multi-certificate chapters}{&quot; + str(stats.groups_multi_member) + r&quot;}&quot; + &quot; &quot;
            + r&quot;\MetricChip{Singleton chapters}{&quot; + str(stats.groups_singleton) + r&quot;}&quot;,
            r&quot;\par\medskip&quot;,
            r&quot;\MetricChip{Numbered CN patterns}{&quot; + str(stats.groups_by_type.get(&quot;numbered_cn_pattern&quot;, 0)) + r&quot;}&quot; + &quot; &quot;
            + r&quot;\MetricChip{Exact endpoint families}{&quot; + str(stats.groups_by_type.get(&quot;exact_endpoint_family&quot;, 0)) + r&quot;}&quot; + &quot; &quot;
            + r&quot;\MetricChip{Non-leaf filtered}{&quot; + str(stats.verification.non_leaf_filtered) + r&quot;}&quot; + &quot; &quot;
            + r&quot;\MetricChip{Precert poison filtered}{&quot; + str(stats.verification.precertificate_poison_filtered) + r&quot;}&quot;,
            r&quot;\end{tcolorbox}&quot;,
            r&quot;\end{document}&quot;,
        ]
    )
    path.write_text(&quot;\n&quot;.join(line for line in lines if line != &quot;&quot;) + &quot;\n&quot;, encoding=&quot;utf-8&quot;)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Writes the raw inventory appendix as LaTeX for PDF assembly.</p>
<p><strong>Flow arrows</strong></p><p>Current hits, groups, and trust data. &#8594; <strong>render_latex_report</strong> &#8594; Produces the LaTeX appendix source that later becomes PDF.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## cleanup_latex_auxiliary_files

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def cleanup_latex_auxiliary_files(tex_path: Path, pdf_output: Path) -&gt; None:
    generated_base = pdf_output.parent / tex_path.stem
    for suffix in (&quot;.aux&quot;, &quot;.log&quot;, &quot;.out&quot;, &quot;.toc&quot;):
        candidate = generated_base.with_suffix(suffix)
        if candidate.exists():
            candidate.unlink()</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>This function is one of the building blocks inside `ct_scan.py`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine.</p>
<p><strong>Flow arrows</strong></p><p>Earlier blocks or operator input feed this block. &#8594; <strong>cleanup_latex_auxiliary_files</strong> &#8594; Later blocks in the same file or in the next analytical stage consume its output.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

## compile_latex_to_pdf

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def compile_latex_to_pdf(tex_path: Path, pdf_output: Path, engine: str) -&gt; None:
    engine_path = shutil.which(engine)
    if engine_path is None:
        raise RuntimeError(f&quot;LaTeX engine not found: {engine}&quot;)
    tex_path = tex_path.resolve()
    pdf_output = pdf_output.resolve()
    pdf_output.parent.mkdir(parents=True, exist_ok=True)
    compile_cmd = [
        engine_path,
        &quot;-interaction=nonstopmode&quot;,
        &quot;-halt-on-error&quot;,
        &quot;-output-directory&quot;,
        str(pdf_output.parent),
        str(tex_path),
    ]
    for _ in range(2):
        result = subprocess.run(
            compile_cmd,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            message = (result.stdout + &quot;\n&quot; + result.stderr).strip()
            raise RuntimeError(
                &quot;LaTeX compilation failed.\n&quot;
                + &quot;\n&quot;.join(message.splitlines()[-40:])
            )
    generated_pdf = pdf_output.parent / f&quot;{tex_path.stem}.pdf&quot;
    if generated_pdf != pdf_output:
        generated_pdf.replace(pdf_output)
    cleanup_latex_auxiliary_files(tex_path, pdf_output)</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>Hands LaTeX to XeLaTeX and turns it into a finished PDF file.</p>
<p><strong>Flow arrows</strong></p><p>A finished `.tex` file. &#8594; <strong>compile_latex_to_pdf</strong> &#8594; Produces the human-readable PDF artifact.</p>
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
        description=&quot;Search crt.sh for currently valid certificates matching configured domain fragments.&quot;,
    )
    parser.add_argument(
        &quot;--domains-file&quot;,
        type=Path,
        default=Path(&quot;domains.local.txt&quot;),
        help=&quot;Text file containing one domain fragment per line.&quot;,
    )
    parser.add_argument(
        &quot;--output&quot;,
        type=Path,
        default=Path(&quot;output/current-valid-certificates.md&quot;),
        help=&quot;Readable single-file markdown report to write.&quot;,
    )
    parser.add_argument(
        &quot;--latex-output&quot;,
        type=Path,
        default=Path(&quot;output/current-valid-certificates.tex&quot;),
        help=&quot;Readable single-file LaTeX report to write.&quot;,
    )
    parser.add_argument(
        &quot;--pdf-output&quot;,
        type=Path,
        default=Path(&quot;output/current-valid-certificates.pdf&quot;),
        help=&quot;Compiled PDF report to write.&quot;,
    )
    parser.add_argument(
        &quot;--pdf-engine&quot;,
        default=&quot;xelatex&quot;,
        help=&quot;LaTeX engine used to compile the PDF report.&quot;,
    )
    parser.add_argument(
        &quot;--skip-pdf&quot;,
        action=&quot;store_true&quot;,
        help=&quot;Write Markdown and LaTeX outputs but skip PDF compilation.&quot;,
    )
    parser.add_argument(
        &quot;--cache-dir&quot;,
        type=Path,
        default=Path(&quot;.cache/ct-search&quot;),
        help=&quot;Directory for cached per-domain query results.&quot;,
    )
    parser.add_argument(
        &quot;--cache-ttl-seconds&quot;,
        type=int,
        default=900,
        help=&quot;Reuse cached database results younger than this many seconds.&quot;,
    )
    parser.add_argument(
        &quot;--max-candidates-per-domain&quot;,
        type=int,
        default=10000,
        help=&quot;Maximum raw crt.sh identity rows to inspect per domain fragment.&quot;,
    )
    parser.add_argument(
        &quot;--retries&quot;,
        type=int,
        default=3,
        help=&quot;Retry count for replica/recovery conflicts from crt.sh.&quot;,
    )
    parser.add_argument(
        &quot;--quiet&quot;,
        action=&quot;store_true&quot;,
        help=&quot;Suppress progress output.&quot;,
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

## main

<table style="width:100%; table-layout:fixed; border-collapse:collapse;">
<tr>
<td style="width:50%; vertical-align:top; padding:8px;">
<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; line-height:1.45;"><code class="language-python">def main() -&gt; int:
    args = parse_args()
    domains = load_domains(args.domains_file)
    all_records: list[DatabaseRecord] = []
    for domain in domains:
        cached = load_cached_records(
            cache_dir=args.cache_dir,
            domain=domain,
            ttl_seconds=args.cache_ttl_seconds,
            max_candidates=args.max_candidates_per_domain,
        )
        if cached is not None:
            if not args.quiet:
                print(f&quot;[cache] domain={domain} records={len(cached)}&quot;, file=sys.stderr)
            all_records.extend(cached)
            continue
        if not args.quiet:
            print(f&quot;[query] domain={domain}&quot;, file=sys.stderr)
        records = query_domain(
            domain=domain,
            max_candidates=args.max_candidates_per_domain,
            attempts=args.retries,
            verbose=not args.quiet,
        )
        if not args.quiet:
            print(f&quot;[done] domain={domain} records={len(records)}&quot;, file=sys.stderr)
        store_cached_records(args.cache_dir, domain, args.max_candidates_per_domain, records)
        all_records.extend(records)
    hits, verification = build_hits(all_records)
    groups = build_groups(hits)
    scan_stats = ScanStats(
        generated_at_utc=utc_iso(datetime.now(UTC)),
        configured_domains=domains,
        unique_leaf_certificates=len(hits),
        groups_total=len(groups),
        groups_multi_member=sum(1 for group in groups if group.member_count &gt; 1),
        groups_singleton=sum(1 for group in groups if group.member_count == 1),
        groups_by_type=dict(Counter(group.group_type for group in groups)),
        verification=verification,
    )
    issuer_trust = query_issuer_trust(hits)
    render_markdown_report(args.output, hits, groups, scan_stats, issuer_trust)
    render_latex_report(args.latex_output, hits, groups, scan_stats, issuer_trust)
    if not args.skip_pdf:
        compile_latex_to_pdf(args.latex_output, args.pdf_output, args.pdf_engine)
    if not args.quiet:
        print(
            f&quot;[report] hits={len(hits)} groups={len(groups)} markdown={args.output} latex={args.latex_output}&quot;
            + (&quot;&quot; if args.skip_pdf else f&quot; pdf={args.pdf_output}&quot;),
            file=sys.stderr,
        )
    return 0</code></pre>
</td>
<td style="width:50%; vertical-align:top; padding:8px;">
<p><strong>What this block is doing</strong></p><p>The standalone command-line entrypoint for the inventory scanner.</p>
<p><strong>Flow arrows</strong></p><p>CLI arguments from the operator. &#8594; <strong>main</strong> &#8594; Runs the whole scanner end to end.</p>
<p><strong>How to think about it</strong></p><p>Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?</p>
</td>
</tr>
</table>

