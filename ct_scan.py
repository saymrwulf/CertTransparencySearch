#!/usr/bin/env python3

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


QUERY_SQL = """
WITH ci AS (
    SELECT
        min(sub.certificate_id) AS id,
        min(sub.issuer_ca_id) AS issuer_ca_id,
        x509_commonName(sub.certificate) AS common_name,
        x509_subjectName(sub.certificate) AS subject_dn,
        x509_notBefore(sub.certificate) AS not_before,
        x509_notAfter(sub.certificate) AS not_after,
        encode(x509_serialNumber(sub.certificate), 'hex') AS serial_number,
        sub.certificate AS certificate
    FROM (
        SELECT cai.*
        FROM certificate_and_identities cai
        WHERE plainto_tsquery('certwatch', %(domain)s) @@ identities(cai.certificate)
          AND cai.name_value ILIKE %(name_pattern)s ESCAPE '\\'
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
      AND cr.serial_number = decode(ci.serial_number, 'hex')
    ORDER BY cr.last_seen_check_date DESC NULLS LAST
    LIMIT 1
) rev ON TRUE
LEFT JOIN LATERAL (
    SELECT
        count(*) FILTER (
            WHERE crl.error_message IS NULL
              AND crl.next_update > now() AT TIME ZONE 'UTC'
        ) AS active_crl_count,
        max(crl.last_checked) AS last_checked
    FROM crl
    WHERE crl.ca_id = ci.issuer_ca_id
) crl_state ON TRUE
WHERE ci.not_before <= now() AT TIME ZONE 'UTC'
  AND ci.not_after >= now() AT TIME ZONE 'UTC'
  AND cl.certificate_type = 'Certificate'
ORDER BY cl.first_seen DESC NULLS LAST, ci.id DESC;
"""


RAW_MATCH_COUNT_SQL = """
SELECT count(*)
FROM certificate_and_identities cai
WHERE plainto_tsquery('certwatch', %(domain)s) @@ identities(cai.certificate)
  AND cai.name_value ILIKE %(name_pattern)s ESCAPE '\\'
"""


REVOCATION_REASONS = {
    1: "keyCompromise",
    2: "cACompromise",
    3: "affiliationChanged",
    4: "superseded",
    5: "cessationOfOperation",
    6: "certificateHold",
    8: "removeFromCRL",
    9: "privilegeWithdrawn",
    10: "aACompromise",
}


PRECERT_POISON_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.3")


@dataclass
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
    certificate_der: bytes


@dataclass
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
    issuer_ca_ids: set[int] = field(default_factory=set)


@dataclass
class VerificationStats:
    input_rows: int = 0
    unique_leaf_certificates: int = 0
    non_leaf_filtered: int = 0
    precertificate_poison_filtered: int = 0


@dataclass
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
    revocation_counts: Counter


@dataclass
class ScanStats:
    generated_at_utc: str
    configured_domains: list[str]
    unique_leaf_certificates: int
    groups_total: int
    groups_multi_member: int
    groups_singleton: int
    groups_by_type: dict[str, int]
    verification: VerificationStats


@dataclass
class IssuerTrustInfo:
    issuer_name: str
    issuer_ca_ids: set[int]
    server_auth_contexts: set[str]
    major_webpki: bool


def load_domains(path: Path) -> list[str]:
    domains: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip().lower()
        if not line or line.startswith("#"):
            continue
        if line.startswith("*."):
            line = line[2:]
        domains.append(line)
    unique_domains = sorted(set(domains))
    if not unique_domains:
        raise ValueError(f"No domains found in {path}")
    return unique_domains


def escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def utc_iso(value: datetime | None) -> str:
    if value is None:
        return "n/a"
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    else:
        value = value.astimezone(UTC)
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def serialize_datetime(value: datetime | None) -> str | None:
    return utc_iso(value) if value is not None else None


def parse_datetime(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC).replace(tzinfo=None)


def cache_path(cache_dir: Path, domain: str) -> Path:
    safe_domain = "".join(ch if ch.isalnum() or ch in "-._" else "_" for ch in domain)
    return cache_dir / f"{safe_domain}.json"


def record_to_cache_payload(record: DatabaseRecord) -> dict[str, Any]:
    return {
        "domain": record.domain,
        "certificate_id": record.certificate_id,
        "issuer_ca_id": record.issuer_ca_id,
        "issuer_name": record.issuer_name,
        "common_name": record.common_name,
        "subject_dn": record.subject_dn,
        "not_before": serialize_datetime(record.not_before),
        "not_after": serialize_datetime(record.not_after),
        "first_seen": serialize_datetime(record.first_seen),
        "serial_number": record.serial_number,
        "revoked_count": record.revoked_count,
        "revocation_date": serialize_datetime(record.revocation_date),
        "reason_code": record.reason_code,
        "last_seen_check_date": serialize_datetime(record.last_seen_check_date),
        "active_crl_count": record.active_crl_count,
        "crl_last_checked": serialize_datetime(record.crl_last_checked),
        "certificate_der_b64": base64.b64encode(record.certificate_der).decode("ascii"),
    }


def record_from_cache_payload(payload: dict[str, Any]) -> DatabaseRecord:
    return DatabaseRecord(
        domain=payload["domain"],
        certificate_id=int(payload["certificate_id"]),
        issuer_ca_id=int(payload["issuer_ca_id"]),
        issuer_name=payload["issuer_name"],
        common_name=payload.get("common_name"),
        subject_dn=payload.get("subject_dn"),
        not_before=parse_datetime(payload["not_before"]) or datetime.min,
        not_after=parse_datetime(payload["not_after"]) or datetime.min,
        first_seen=parse_datetime(payload.get("first_seen")),
        serial_number=payload["serial_number"],
        revoked_count=int(payload["revoked_count"]),
        revocation_date=parse_datetime(payload.get("revocation_date")),
        reason_code=payload.get("reason_code"),
        last_seen_check_date=parse_datetime(payload.get("last_seen_check_date")),
        active_crl_count=int(payload["active_crl_count"]),
        crl_last_checked=parse_datetime(payload.get("crl_last_checked")),
        certificate_der=base64.b64decode(payload["certificate_der_b64"]),
    )


def load_cached_records(cache_dir: Path, domain: str, ttl_seconds: int, max_candidates: int) -> list[DatabaseRecord] | None:
    path = cache_path(cache_dir, domain)
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    if payload.get("version") != 1:
        return None
    if payload.get("max_candidates") != max_candidates:
        return None
    cached_at = parse_datetime(payload.get("cached_at"))
    if cached_at is None:
        return None
    age = time.time() - cached_at.replace(tzinfo=UTC).timestamp()
    if age > ttl_seconds:
        return None
    return [record_from_cache_payload(item) for item in payload.get("records", [])]


def store_cached_records(cache_dir: Path, domain: str, max_candidates: int, records: list[DatabaseRecord]) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": 1,
        "cached_at": utc_iso(datetime.now(UTC)),
        "max_candidates": max_candidates,
        "records": [record_to_cache_payload(record) for record in records],
    }
    cache_path(cache_dir, domain).write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def connect() -> psycopg.Connection:
    return psycopg.connect(
        host="crt.sh",
        port=5432,
        dbname="certwatch",
        user="guest",
        password="guest",
        connect_timeout=5,
        sslmode="disable",
        autocommit=True,
        application_name="ct_transparency_search",
    )


def query_domain(domain: str, max_candidates: int, attempts: int, verbose: bool) -> list[DatabaseRecord]:
    params = {
        "domain": domain,
        "name_pattern": f"%{escape_like(domain)}%",
        "max_candidates": max_candidates,
    }
    raw_match_count = query_raw_match_count(domain=domain, attempts=attempts, verbose=verbose)
    if raw_match_count > max_candidates:
        raise ValueError(
            f"domain={domain} raw identity matches={raw_match_count} exceed max_candidates={max_candidates}; "
            f"increase --max-candidates-per-domain to at least {raw_match_count} for a complete result set"
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
                    f"[warn] domain={domain} attempt={attempt}/{attempts} failed: {exc}",
                    file=sys.stderr,
                )
            time.sleep(min(2 ** attempt, 10))
    assert last_error is not None
    raise last_error


def query_raw_match_count(domain: str, attempts: int, verbose: bool) -> int:
    params = {
        "domain": domain,
        "name_pattern": f"%{escape_like(domain)}%",
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
                    f"[warn] domain={domain} raw-count attempt={attempt}/{attempts} failed: {exc}",
                    file=sys.stderr,
                )
            time.sleep(min(2 ** attempt, 10))
    assert last_error is not None
    raise last_error


def row_to_record(domain: str, row: dict[str, Any]) -> DatabaseRecord:
    return DatabaseRecord(
        domain=domain,
        certificate_id=int(row["id"]),
        issuer_ca_id=int(row["issuer_ca_id"]),
        issuer_name=row["issuer_name"],
        common_name=row["common_name"],
        subject_dn=row["subject_dn"],
        not_before=row["not_before"],
        not_after=row["not_after"],
        first_seen=row["first_seen"],
        serial_number=row["serial_number"],
        revoked_count=int(row["revoked_count"]),
        revocation_date=row["revocation_date"],
        reason_code=row["reason_code"],
        last_seen_check_date=row["last_seen_check_date"],
        active_crl_count=int(row["active_crl_count"] or 0),
        crl_last_checked=row["crl_last_checked"],
        certificate_der=bytes(row["certificate"]),
    )


def extract_san_entries(cert: x509.Certificate) -> list[str]:
    try:
        extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    entries: list[str] = []
    for name in extension.value:
        entries.append(format_general_name(name))
    return sorted(set(entries), key=str.casefold)


def format_general_name(name: general_name.GeneralName) -> str:
    if isinstance(name, x509.DNSName):
        return f"DNS:{name.value}"
    if isinstance(name, x509.RFC822Name):
        return f"EMAIL:{name.value}"
    if isinstance(name, x509.UniformResourceIdentifier):
        return f"URI:{name.value}"
    if isinstance(name, x509.IPAddress):
        return f"IP:{name.value}"
    if isinstance(name, x509.RegisteredID):
        return f"RID:{name.value.dotted_string}"
    if isinstance(name, x509.DirectoryName):
        return f"DIR:{name.value.rfc4514_string()}"
    if isinstance(name, x509.OtherName):
        encoded = base64.b64encode(name.value).decode("ascii")
        return f"OTHER:{name.type_id.dotted_string}:{encoded}"
    return str(name)


def extract_common_name(cert: x509.Certificate) -> str | None:
    attributes = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attributes:
        return None
    return attributes[0].value


def has_precertificate_poison(cert: x509.Certificate) -> bool:
    try:
        cert.extensions.get_extension_for_oid(PRECERT_POISON_OID)
    except x509.ExtensionNotFound:
        return False
    return True


def is_leaf_certificate(cert: x509.Certificate) -> tuple[bool, str]:
    if has_precertificate_poison(cert):
        return (False, "precertificate_poison")
    try:
        basic_constraints = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        if basic_constraints.ca:
            return (False, "basic_constraints_ca")
    except x509.ExtensionNotFound:
        pass
    try:
        key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        if key_usage.key_cert_sign:
            return (False, "key_cert_sign")
    except x509.ExtensionNotFound:
        pass
    return (True, "leaf")


def revocation_fields(record: DatabaseRecord) -> tuple[str, datetime | None, str | None, datetime | None, str | None]:
    if record.revoked_count > 0:
        reason: str | None = None
        if record.reason_code in REVOCATION_REASONS:
            reason = REVOCATION_REASONS[record.reason_code]
        elif record.reason_code not in (None, 0):
            reason = f"unknown({record.reason_code})"
        return ("revoked", record.revocation_date, reason, record.last_seen_check_date, None)
    if record.active_crl_count > 0:
        return ("not_revoked", None, None, record.crl_last_checked, None)
    return ("unknown", None, None, record.crl_last_checked, "no fresh crt.sh CRL data")


def revocation_priority(status: str) -> int:
    return {
        "unknown": 0,
        "not_revoked": 1,
        "revoked": 2,
    }[status]


def build_hits(records: list[DatabaseRecord]) -> tuple[list[CertificateHit], VerificationStats]:
    verification = VerificationStats(input_rows=len(records))
    hits: dict[str, CertificateHit] = {}
    for record in records:
        cert = x509.load_der_x509_certificate(record.certificate_der)
        is_leaf, reason = is_leaf_certificate(cert)
        if not is_leaf:
            if reason == "precertificate_poison":
                verification.precertificate_poison_filtered += 1
            else:
                verification.non_leaf_filtered += 1
            continue
        fingerprint_hex = hashlib.sha256(record.certificate_der).hexdigest()
        subject_cn = record.common_name or extract_common_name(cert) or "-"
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
        if hit.first_seen is None or (record.first_seen is not None and record.first_seen < hit.first_seen):
            hit.first_seen = record.first_seen
        if revocation_priority(revocation_status) > revocation_priority(hit.revocation_status):
            hit.revocation_status = revocation_status
            hit.revocation_date = revocation_date
            hit.revocation_reason = revocation_reason
            hit.revocation_note = revocation_note
            hit.crtsh_crl_timestamp = crtsh_crl_timestamp
        elif revocation_status == hit.revocation_status and hit.crtsh_crl_timestamp is not None and crtsh_crl_timestamp is not None:
            if crtsh_crl_timestamp > hit.crtsh_crl_timestamp:
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
    return (ordered_hits, verification)


def canonicalize_subject_cn(subject_cn: str) -> str:
    subject_cn = subject_cn.lower()
    if subject_cn.startswith("www."):
        return subject_cn[4:]
    return subject_cn


def normalize_counter_pattern(hostname: str) -> str | None:
    normalized = re.sub(r"\d+", "#", canonicalize_subject_cn(hostname))
    if normalized == canonicalize_subject_cn(hostname):
        return None
    return normalized


class UnionFind:
    def __init__(self, size: int) -> None:
        self.parent = list(range(size))
        self.rank = [0] * size

    def find(self, value: int) -> int:
        while self.parent[value] != value:
            self.parent[value] = self.parent[self.parent[value]]
            value = self.parent[value]
        return value

    def union(self, left: int, right: int) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root == right_root:
            return
        if self.rank[left_root] < self.rank[right_root]:
            left_root, right_root = right_root, left_root
        self.parent[right_root] = left_root
        if self.rank[left_root] == self.rank[right_root]:
            self.rank[left_root] += 1


def build_groups(hits: list[CertificateHit]) -> list[CertificateGroup]:
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
        if len(canonical_cns) > 1
    }
    components: dict[tuple[str, str], list[int]] = defaultdict(list)
    for index, hit in enumerate(hits):
        canonical_cn = canonicalize_subject_cn(hit.subject_cn)
        pattern = normalize_counter_pattern(hit.subject_cn)
        if pattern in qualifying_patterns:
            components[("pattern", pattern)].append(index)
        else:
            components[("exact", canonical_cn)].append(index)

    provisional_groups: list[CertificateGroup] = []
    for (family_kind, family_key), member_indices in components.items():
        member_hits = [hits[index] for index in member_indices]
        subject_cns = {hit.subject_cn for hit in member_hits}
        unique_san_profiles = {tuple(hit.san_entries) for hit in member_hits}
        numbered_patterns = {family_key} if family_kind == "pattern" else set()
        group_type = "numbered_cn_pattern" if family_kind == "pattern" else "exact_endpoint_family"
        first_seen_values = [hit.first_seen for hit in member_hits if hit.first_seen is not None]
        provisional_groups.append(
            CertificateGroup(
                group_id="",
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
        group.group_id = f"G{position:04d}"
    return provisional_groups


def describe_group_basis(group: CertificateGroup) -> str:
    if group.group_type == "numbered_cn_pattern":
        pattern = next(iter(group.numbered_cn_patterns))
        return f"CN pattern with running-number slot: `{pattern}`"
    base = min(canonicalize_subject_cn(value) for value in group.subject_cns)
    return f"Same endpoint CN family (exact CN; `www.` grouped with base name): `{base}`"


def primary_issuer_name(hit: CertificateHit) -> str:
    return sorted(hit.issuer_names)[0]


def query_issuer_trust(hits: list[CertificateHit]) -> dict[str, IssuerTrustInfo]:
    issuer_name_to_ca_ids: dict[str, set[int]] = defaultdict(set)
    for hit in hits:
        issuer_name_to_ca_ids[primary_issuer_name(hit)].update(hit.issuer_ca_ids)
    all_ca_ids = sorted({ca_id for ca_ids in issuer_name_to_ca_ids.values() for ca_id in ca_ids})
    contexts_by_ca_id: dict[int, set[str]] = defaultdict(set)
    if all_ca_ids:
        query = """
        SELECT ctp.ca_id, tc.ctx
        FROM ca_trust_purpose ctp
        JOIN trust_context tc ON tc.id = ctp.trust_context_id
        JOIN trust_purpose tp ON tp.id = ctp.trust_purpose_id
        WHERE ctp.ca_id = ANY(%s)
          AND tp.purpose = 'Server Authentication'
          AND ctp.is_time_valid = TRUE
          AND ctp.disabled_from IS NULL
        """
        with connect() as conn, conn.cursor() as cur:
            cur.execute(query, (all_ca_ids,))
            for ca_id, trust_context in cur.fetchall():
                contexts_by_ca_id[int(ca_id)].add(str(trust_context))
    major_contexts = {"Mozilla", "Chrome", "Apple", "Microsoft", "Android"}
    results: dict[str, IssuerTrustInfo] = {}
    for issuer_name, ca_ids in issuer_name_to_ca_ids.items():
        merged_contexts = {ctx for ca_id in ca_ids for ctx in contexts_by_ca_id.get(ca_id, set())}
        results[issuer_name] = IssuerTrustInfo(
            issuer_name=issuer_name,
            issuer_ca_ids=set(ca_ids),
            server_auth_contexts=merged_contexts,
            major_webpki=major_contexts.issubset(merged_contexts),
        )
    return results


def status_marker(status: str) -> str:
    return {
        "not_revoked": "OK ",
        "revoked": "REV",
        "unknown": "UNK",
    }[status]


def one_line_revocation(hit: CertificateHit) -> str:
    if hit.revocation_status == "revoked":
        detail = f"revoked {utc_iso(hit.revocation_date)}" if hit.revocation_date else "revoked"
        if hit.revocation_reason:
            detail += f", reason={hit.revocation_reason}"
        return detail
    if hit.revocation_status == "unknown":
        if hit.revocation_note:
            return f"unknown, {hit.revocation_note}"
        return "unknown"
    return "not revoked"


def san_tail_split(domain: str) -> tuple[list[str], str]:
    labels = domain.split(".")
    common_second_level = {"ac", "co", "com", "edu", "gov", "net", "org"}
    suffix_len = 2
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in common_second_level:
        suffix_len = 3
    if len(labels) <= suffix_len:
        return ([], domain)
    return (labels[:-suffix_len], ".".join(labels[-suffix_len:]))


def build_san_tree_lines(san_entries: list[str]) -> list[str]:
    return build_san_tree_lines_with_style(san_entries, ascii_only=False)


def build_san_tree_lines_with_style(san_entries: list[str], ascii_only: bool) -> list[str]:
    dns_entries = sorted({entry[4:] for entry in san_entries if entry.startswith("DNS:")})
    other_entries = sorted({entry for entry in san_entries if not entry.startswith("DNS:")})
    tree: dict[str, Any] = {}
    for domain in dns_entries:
        prefix_labels, tail = san_tail_split(domain)
        cursor = tree
        for label in prefix_labels:
            cursor = cursor.setdefault(label, {})
        cursor.setdefault(tail, {})

    def render(node: dict[str, Any], prefix: str = "") -> list[str]:
        lines: list[str] = []
        keys = sorted(node.keys(), key=str.casefold)
        for index, key in enumerate(keys):
            is_last = index == len(keys) - 1
            if ascii_only:
                connector = "`- " if is_last else "|- "
            else:
                connector = "└─ " if is_last else "├─ "
            lines.append(prefix + connector + key)
            child = node[key]
            if ascii_only:
                child_prefix = prefix + ("   " if is_last else "|  ")
            else:
                child_prefix = prefix + ("   " if is_last else "│  ")
            lines.extend(render(child, child_prefix))
        return lines

    lines = render(tree)
    for entry in other_entries:
        lines.append(f"{'*' if ascii_only else '•'} {entry}")
    if not lines:
        lines.append(f"{'*' if ascii_only else '•'} -")
    return lines


def group_hits_by_issuer(hits: list[CertificateHit]) -> tuple[dict[str, list[CertificateHit]], list[str]]:
    issuer_hits: dict[str, list[CertificateHit]] = defaultdict(list)
    for hit in hits:
        issuer_hits[primary_issuer_name(hit)].append(hit)
    ordered_issuers = sorted(
        issuer_hits,
        key=lambda issuer_name: (-len(issuer_hits[issuer_name]), issuer_name.casefold()),
    )
    return issuer_hits, ordered_issuers


def latex_escape(value: str) -> str:
    replacements = {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }
    return "".join(replacements.get(char, char) for char in value)


def summarize_san_patterns(san_entries: list[str]) -> dict[str, Any]:
    dns_entries = sorted({entry[4:] for entry in san_entries if entry.startswith("DNS:")}, key=str.casefold)
    other_entries = sorted({entry for entry in san_entries if not entry.startswith("DNS:")}, key=str.casefold)
    zone_counts: Counter[str] = Counter()
    normalized_pattern_counts: Counter[str] = Counter()
    wildcard_count = 0
    numbered_count = 0
    for domain in dns_entries:
        normalized_domain = domain[2:] if domain.startswith("*.") else domain
        if domain.startswith("*."):
            wildcard_count += 1
        if re.search(r"\d", normalized_domain):
            numbered_count += 1
        prefix_labels, tail = san_tail_split(normalized_domain)
        zone_counts[tail] += 1
        normalized_prefix = ".".join(re.sub(r"\d+", "#", label) for label in prefix_labels if label)
        if normalized_prefix:
            normalized_pattern_counts[f"{normalized_prefix}.{tail}"] += 1
        else:
            normalized_pattern_counts[tail] += 1
    repeating_patterns = [
        (pattern, count)
        for pattern, count in normalized_pattern_counts.most_common(6)
        if count > 1
    ]
    return {
        "dns_count": len(dns_entries),
        "other_count": len(other_entries),
        "wildcard_count": wildcard_count,
        "numbered_count": numbered_count,
        "zone_count": len(zone_counts),
        "top_zones": zone_counts.most_common(6),
        "repeating_patterns": repeating_patterns,
    }


def latex_status_badge(status: str) -> str:
    return {
        "not_revoked": r"\StatusOK{}",
        "revoked": r"\StatusREV{}",
        "unknown": r"\StatusUNK{}",
    }[status]


def latex_webpki_badge(value: bool) -> str:
    return r"\WebPKIYes{}" if value else r"\WebPKINo{}"


def render_markdown_report(
    path: Path,
    hits: list[CertificateHit],
    groups: list[CertificateGroup],
    stats: ScanStats,
    issuer_trust: dict[str, IssuerTrustInfo],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    issuer_hits, ordered_issuers = group_hits_by_issuer(hits)
    lines: list[str] = []
    lines.append("# Certificate CN Family Report")
    lines.append("")
    lines.append(f"Generated: {stats.generated_at_utc}")
    lines.append(f"Configured domains: {', '.join(stats.configured_domains)}")
    lines.append("")
    lines.append("## What This File Contains")
    lines.append("")
    lines.append("- Chapters are built from Subject CN construction only.")
    lines.append("- If multiple concrete CNs share the same numbered schema, they are grouped together.")
    lines.append("- Otherwise the chapter is one endpoint family; `www.` is grouped with the base name as a low-signal convenience.")
    lines.append("- SAN entries are shown only inside each Subject CN subsection.")
    lines.append("- All certificates shown here are verified leaf certificates.")
    lines.append("")
    lines.append("## Issuer Overview")
    lines.append("")
    for issuer_name in ordered_issuers:
        trust = issuer_trust[issuer_name]
        ca_ids = ", ".join(str(value) for value in sorted(trust.issuer_ca_ids))
        trust_label = "YES" if trust.major_webpki else "NO"
        lines.append(
            f"- {issuer_name} | certificates={len(issuer_hits[issuer_name])} | WebPKI server-auth in major stores={trust_label} | ca_id={ca_ids}"
        )
    lines.append("")
    lines.append("## Leaf-Certificate Assurance")
    lines.append("")
    lines.append("- SQL filter: `certificate_lifecycle.certificate_type = 'Certificate'`")
    lines.append("- Local filter: precertificate poison absent, `BasicConstraints.ca != true`, `KeyUsage.keyCertSign != true`")
    lines.append(f"- Verified leaf certificates kept: {stats.unique_leaf_certificates}")
    lines.append(f"- Non-leaf filtered after download: {stats.verification.non_leaf_filtered}")
    lines.append(f"- Precertificate poison filtered after download: {stats.verification.precertificate_poison_filtered}")
    lines.append("")
    for issuer_position, issuer_name in enumerate(ordered_issuers, start=1):
        trust = issuer_trust[issuer_name]
        issuer_title = f"Issuer {issuer_position:02d}  {issuer_name}"
        lines.append(f"## {issuer_title}")
        lines.append("")
        lines.append(f"- Certificates under issuer: {len(issuer_hits[issuer_name])}")
        lines.append(
            f"- WebPKI server-auth in major stores (Mozilla, Chrome, Apple, Microsoft, Android): {'YES' if trust.major_webpki else 'NO'}"
        )
        lines.append(
            f"- Server-auth trust contexts seen in crt.sh live trust data: {', '.join(sorted(trust.server_auth_contexts)) if trust.server_auth_contexts else 'none'}"
        )
        lines.append(f"- Issuer CA IDs: {', '.join(str(value) for value in sorted(trust.issuer_ca_ids))}")
        lines.append("")
        issuer_groups = build_groups(issuer_hits[issuer_name])
        for family_index, group in enumerate(issuer_groups, start=1):
            member_hits = [issuer_hits[issuer_name][index] for index in group.member_indices]
            chapter_title = f"Family {family_index:02d}  {describe_group_basis(group)}"
            lines.append(f"### {chapter_title}")
            lines.append("")
            lines.append(f"- Certificates in chapter: {group.member_count}")
            lines.append(f"- Concrete Subject CNs: {group.distinct_subject_cn_count}")
            lines.append(f"- Distinct SAN profiles in chapter: {group.distinct_exact_content_count}")
            lines.append(f"- Matched domains: {', '.join(sorted(group.matched_domains))}")
            lines.append(f"- Family validity span: {utc_iso(group.valid_from_min)} -> {utc_iso(group.valid_to_max)}")
            if group.first_seen_min and group.first_seen_max:
                lines.append(f"- First seen span: {utc_iso(group.first_seen_min)} -> {utc_iso(group.first_seen_max)}")
            lines.append(f"- Revocation mix: {group.revocation_counts.get('revoked', 0)} revoked, {group.revocation_counts.get('not_revoked', 0)} not revoked, {group.revocation_counts.get('unknown', 0)} unknown")
            lines.append("")

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
                lines.append(f"#### Subject CN: `{subject_cn}`")
                lines.append("")
                lines.append(f"- Certificates under this CN: {len(subject_hits)}")
                lines.append(f"- Validity span under this CN: {utc_iso(min(hit.validity_not_before for hit in subject_hits))} -> {utc_iso(max(hit.validity_not_after for hit in subject_hits))}")
                san_profiles: dict[tuple[str, ...], list[CertificateHit]] = defaultdict(list)
                for hit in subject_hits:
                    san_profiles[tuple(hit.san_entries)].append(hit)
                profile_size_counts = Counter(len(profile) for profile in san_profiles)
                unique_san_entries = sorted({entry for hit in subject_hits for entry in hit.san_entries})
                lines.append(f"- Distinct SAN profiles under this CN: {len(san_profiles)}")
                lines.append(
                    "- SAN profile sizes seen: "
                    + ", ".join(
                        f"{size} SAN x {count}"
                        for size, count in sorted(profile_size_counts.items())
                    )
                )
                lines.append("")
                lines.append("Validity history")
                lines.append("")

                for hit in subject_hits:
                    crtsh_ids = ", ".join(str(value) for value in sorted(hit.crtsh_certificate_ids))
                    lines.append(
                        f"- [{status_marker(hit.revocation_status)}] {utc_iso(hit.validity_not_before)} -> {utc_iso(hit.validity_not_after)} | SANs={len(hit.san_entries)} | crt.sh={crtsh_ids} | {one_line_revocation(hit)}"
                    )
                lines.append("")
                lines.append("SAN structure")
                lines.append("")
                lines.append("```text")
                for tree_line in build_san_tree_lines(unique_san_entries):
                    lines.append(tree_line)
                lines.append("```")
                lines.append("")

        lines.append("---")
        lines.append("")

    lines.append("## Statistics")
    lines.append("")
    lines.append(f"- Unique leaf certificates: {stats.unique_leaf_certificates}")
    lines.append(f"- CN-family chapters: {stats.groups_total}")
    lines.append(f"- Chapters with more than one certificate: {stats.groups_multi_member}")
    lines.append(f"- Single-certificate chapters: {stats.groups_singleton}")
    lines.append(f"- Numbered CN pattern chapters: {stats.groups_by_type.get('numbered_cn_pattern', 0)}")
    lines.append(f"- Exact endpoint chapters: {stats.groups_by_type.get('exact_endpoint_family', 0)}")
    lines.append("")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def render_latex_report(
    path: Path,
    hits: list[CertificateHit],
    groups: list[CertificateGroup],
    stats: ScanStats,
    issuer_trust: dict[str, IssuerTrustInfo],
    show_page_numbers: bool = True,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    issuer_hits, ordered_issuers = group_hits_by_issuer(hits)
    revoked_total = sum(1 for hit in hits if hit.revocation_status == "revoked")
    unknown_total = sum(1 for hit in hits if hit.revocation_status == "unknown")
    not_revoked_total = sum(1 for hit in hits if hit.revocation_status == "not_revoked")

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
        r"\usepackage{titlesec}",
        r"\usepackage[most]{tcolorbox}",
        r"\usepackage{fancyvrb}",
        r"\usepackage{needspace}",
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
        r"\definecolor{AccentLine}{HTML}{74C4B8}",
        r"\definecolor{Warn}{HTML}{9A6700}",
        r"\definecolor{WarnSoft}{HTML}{FFF4DB}",
        r"\definecolor{Danger}{HTML}{B42318}",
        r"\definecolor{DangerSoft}{HTML}{FEE4E2}",
        r"\definecolor{OkText}{HTML}{065F46}",
        r"\definecolor{OkSoft}{HTML}{DCFCE7}",
        r"\definecolor{UnknownText}{HTML}{9A6700}",
        r"\definecolor{UnknownSoft}{HTML}{FEF3C7}",
        r"\hypersetup{colorlinks=true,linkcolor=Accent,urlcolor=Accent,pdfauthor={CertTransparencySearch},pdftitle={Certificate Transparency Endpoint Atlas}}",
        r"\setlength{\parindent}{0pt}",
        r"\setlength{\parskip}{6pt}",
        r"\setlength{\emergencystretch}{3em}",
        r"\setlength{\footskip}{24pt}",
        r"\setlength{\tabcolsep}{4.2pt}",
        r"\renewcommand{\arraystretch}{1.12}",
        r"\raggedbottom",
        r"\setcounter{tocdepth}{2}",
        rf"\pagestyle{{{'plain' if show_page_numbers else 'empty'}}}",
        r"\titleformat{\section}{\sffamily\bfseries\LARGE\color{Ink}\raggedright}{\thesection}{0.8em}{}",
        r"\titleformat{\subsection}{\sffamily\bfseries\Large\color{Ink}\raggedright}{\thesubsection}{0.8em}{}",
        r"\titleformat{\subsubsection}{\sffamily\bfseries\normalsize\color{Ink}\raggedright}{\thesubsubsection}{0.8em}{}",
        r"\tcbset{",
        r"  panel/.style={enhanced,breakable,boxrule=0.55pt,arc=3pt,left=9pt,right=9pt,top=8pt,bottom=8pt,colback=white,colframe=Line},",
        r"  hero/.style={panel,colback=Ink,colframe=Ink,left=14pt,right=14pt,top=14pt,bottom=14pt},",
        r"  summary/.style={panel,colback=Panel,colframe=Line},",
        r"  issuerpanel/.style={panel,colback=Panel,colframe=Ink!45},",
        r"  familypanel/.style={panel,colback=AccentSoft,colframe=AccentLine},",
        r"  subjectpanel/.style={panel,colback=white,colframe=Line},",
        r"  treepanel/.style={panel,colback=Panel,colframe=AccentLine},",
        r"}",
        r"\newcommand{\DomainChip}[1]{\tcbox[on line,boxrule=0pt,arc=3pt,left=5pt,right=5pt,top=2pt,bottom=2pt,colback=AccentSoft]{\sffamily\footnotesize\texttt{#1}}}",
        r"\newcommand{\MetricChip}[2]{\tcbox[on line,boxrule=0pt,arc=3pt,left=6pt,right=6pt,top=3pt,bottom=3pt,colback=Panel]{\sffamily\footnotesize\textcolor{Muted}{#1}\hspace{0.45em}\textbf{#2}}}",
        r"\newcommand{\StatusOK}{\tcbox[on line,boxrule=0pt,arc=3pt,left=5pt,right=5pt,top=2pt,bottom=2pt,colback=OkSoft]{\sffamily\bfseries\footnotesize\textcolor{OkText}{OK}}}",
        r"\newcommand{\StatusREV}{\tcbox[on line,boxrule=0pt,arc=3pt,left=5pt,right=5pt,top=2pt,bottom=2pt,colback=DangerSoft]{\sffamily\bfseries\footnotesize\textcolor{Danger}{REV}}}",
        r"\newcommand{\StatusUNK}{\tcbox[on line,boxrule=0pt,arc=3pt,left=5pt,right=5pt,top=2pt,bottom=2pt,colback=UnknownSoft]{\sffamily\bfseries\footnotesize\textcolor{UnknownText}{UNK}}}",
        r"\newcommand{\WebPKIYes}{\tcbox[on line,boxrule=0pt,arc=3pt,left=5pt,right=5pt,top=2pt,bottom=2pt,colback=OkSoft]{\sffamily\bfseries\footnotesize\textcolor{OkText}{WebPKI: YES}}}",
        r"\newcommand{\WebPKINo}{\tcbox[on line,boxrule=0pt,arc=3pt,left=5pt,right=5pt,top=2pt,bottom=2pt,colback=DangerSoft]{\sffamily\bfseries\footnotesize\textcolor{Danger}{WebPKI: NO}}}",
        r"\begin{document}",
        r"\begin{titlepage}",
        r"\thispagestyle{empty}",
        r"\vspace*{20mm}",
        r"\begin{tcolorbox}[hero]",
        r"{\color{white}\sffamily\bfseries\fontsize{24}{28}\selectfont Certificate Transparency Endpoint Atlas\par}",
        r"\vspace{4pt}",
        r"{\color{white}\Large Currently valid leaf certificates matching the configured domains\par}",
        r"\vspace{12pt}",
        r"{\color{white}\sffamily\small This artefact is optimized for review: issuer-first navigation, CN-family grouping, certificate timelines, and SAN structure blocks designed to be read rather than decoded.}",
        r"\end{tcolorbox}",
        r"\vspace{10mm}",
        r"\begin{tcolorbox}[summary]",
        rf"\textbf{{Generated}}: {latex_escape(stats.generated_at_utc)}\par",
        r"\textbf{Configured domains}: " + " ".join(
            rf"\DomainChip{{{latex_escape(domain)}}}" for domain in stats.configured_domains
        ),
        r"\par\medskip",
        r"\MetricChip{Leaf certificates}{" + str(stats.unique_leaf_certificates) + r"}" + " "
        + r"\MetricChip{CN families}{" + str(stats.groups_total) + r"}" + " "
        + r"\MetricChip{Numbered families}{" + str(stats.groups_by_type.get("numbered_cn_pattern", 0)) + r"}" + " "
        + r"\MetricChip{Exact families}{" + str(stats.groups_by_type.get("exact_endpoint_family", 0)) + r"}",
        r"\par\medskip",
        r"\MetricChip{Not revoked}{" + str(not_revoked_total) + r"}" + " "
        + r"\MetricChip{Revoked}{" + str(revoked_total) + r"}" + " "
        + r"\MetricChip{Unknown}{" + str(unknown_total) + r"}",
        r"\end{tcolorbox}",
        r"\vfill",
        r"{\sffamily\small\textcolor{Muted}{Same scan, three outputs: Markdown for editor preview, LaTeX for source control, PDF for distribution.}}",
        r"\end{titlepage}",
        r"\tableofcontents",
        r"\clearpage",
        r"\section*{Executive Summary}",
        r"\addcontentsline{toc}{section}{Executive Summary}",
        r"\begin{tcolorbox}[summary]",
        r"\textbf{Reading guide}\par",
        r"Major chapters are exact issuer names. Inside each issuer, families are derived only from the construction of the Subject CN. Each concrete Subject CN then gets its own certificate timeline and a SAN structure panel.\par",
        r"\medskip",
        r"\textbf{Leaf-only assurance}\par",
        r"SQL excludes entries whose lifecycle type is not \texttt{Certificate}. Local parsing then rejects any artifact with precertificate poison, \texttt{BasicConstraints.ca = true}, or \texttt{KeyUsage.keyCertSign = true}.",
        r"\end{tcolorbox}",
        r"\begin{tcolorbox}[summary]",
        r"\textbf{Issuer landscape}\par",
        r"\medskip",
        r"\begin{tabularx}{\linewidth}{>{\raggedright\arraybackslash}X >{\raggedleft\arraybackslash}p{1.7cm} >{\raggedleft\arraybackslash}p{1.9cm} >{\raggedleft\arraybackslash}p{2.0cm}}",
        r"\toprule",
        r"Issuer & Certificates & Share & WebPKI \\",
        r"\midrule",
    ]

    total_hits = len(hits) if hits else 1
    for issuer_name in ordered_issuers:
        issuer_count = len(issuer_hits[issuer_name])
        share = f"{issuer_count / total_hits:.1%}"
        lines.append(
            rf"{latex_escape(issuer_name)} & {issuer_count} & {latex_escape(share)} & {latex_webpki_badge(issuer_trust[issuer_name].major_webpki)} \\"
        )
    lines.extend(
        [
            r"\bottomrule",
            r"\end{tabularx}",
            r"\end{tcolorbox}",
        ]
    )

    for issuer_position, issuer_name in enumerate(ordered_issuers, start=1):
        trust = issuer_trust[issuer_name]
        issuer_groups = build_groups(issuer_hits[issuer_name])
        lines.extend(
            [
                r"\clearpage",
                rf"\section{{Issuer {issuer_position:02d}: {latex_escape(issuer_name)}}}",
                r"\begin{tcolorbox}[issuerpanel]",
                r"\MetricChip{Certificates}{" + str(len(issuer_hits[issuer_name])) + r"}" + " "
                + r"\MetricChip{Families}{" + str(len(issuer_groups)) + r"}" + " "
                + latex_webpki_badge(trust.major_webpki),
                r"\par\medskip",
                rf"\textbf{{Trust contexts seen in crt.sh live data}}: {latex_escape(', '.join(sorted(trust.server_auth_contexts)) if trust.server_auth_contexts else 'none')}\par",
                rf"\textbf{{Issuer CA IDs}}: {latex_escape(', '.join(str(value) for value in sorted(trust.issuer_ca_ids)))}",
                r"\end{tcolorbox}",
            ]
        )
        for family_index, group in enumerate(issuer_groups, start=1):
            member_hits = [issuer_hits[issuer_name][index] for index in group.member_indices]
            lines.extend(
                [
                    r"\Needspace{14\baselineskip}",
                    rf"\subsection{{Family {family_index:02d}: {latex_escape(describe_group_basis(group).replace('`', ''))}}}",
                    r"\begin{tcolorbox}[familypanel]",
                    r"\MetricChip{Certificates}{" + str(group.member_count) + r"}" + " "
                    + r"\MetricChip{Concrete CNs}{" + str(group.distinct_subject_cn_count) + r"}" + " "
                    + r"\MetricChip{Distinct SAN profiles}{" + str(group.distinct_exact_content_count) + r"}",
                    r"\par\medskip",
                    rf"\textbf{{Matched domains}}: {' '.join(rf'\DomainChip{{{latex_escape(domain)}}}' for domain in sorted(group.matched_domains))}\par",
                    rf"\textbf{{Family validity span}}: \texttt{{{latex_escape(utc_iso(group.valid_from_min))}}} to \texttt{{{latex_escape(utc_iso(group.valid_to_max))}}}\par",
                    (
                        rf"\textbf{{First seen span}}: \texttt{{{latex_escape(utc_iso(group.first_seen_min))}}} to \texttt{{{latex_escape(utc_iso(group.first_seen_max))}}}\par"
                        if group.first_seen_min and group.first_seen_max
                        else ""
                    ),
                    rf"\textbf{{Revocation mix}}: {group.revocation_counts.get('revoked', 0)} revoked, {group.revocation_counts.get('not_revoked', 0)} not revoked, {group.revocation_counts.get('unknown', 0)} unknown",
                    r"\end{tcolorbox}",
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
                        r"\Needspace{18\baselineskip}",
                        rf"\subsubsection{{Subject CN: {latex_escape(subject_cn)}}}",
                        r"\begin{tcolorbox}[subjectpanel]",
                        r"\MetricChip{Certificates under this CN}{" + str(len(subject_hits)) + r"}" + " "
                        + r"\MetricChip{Distinct SAN profiles}{" + str(len({tuple(hit.san_entries) for hit in subject_hits})) + r"}" + " "
                        + r"\MetricChip{Unique SAN entries}{" + str(len(unique_san_entries)) + r"}",
                        r"\par\medskip",
                        rf"\textbf{{Validity span under this CN}}: \texttt{{{latex_escape(utc_iso(min(hit.validity_not_before for hit in subject_hits)))}}} to \texttt{{{latex_escape(utc_iso(max(hit.validity_not_after for hit in subject_hits)))}}}",
                        r"\par\medskip",
                        r"\textbf{Certificate timeline}",
                        r"\begin{itemize}[leftmargin=1.4em,itemsep=0.55em,topsep=0.4em]",
                    ]
                )
                for hit in subject_hits:
                    crtsh_ids = ", ".join(str(value) for value in sorted(hit.crtsh_certificate_ids))
                    lines.extend(
                        [
                            r"\item "
                            + latex_status_badge(hit.revocation_status)
                            + " "
                            + rf"\texttt{{{latex_escape(utc_iso(hit.validity_not_before))}}} to \texttt{{{latex_escape(utc_iso(hit.validity_not_after))}}}",
                            rf"\newline \textcolor{{Muted}}{{SANs: {len(hit.san_entries)} \quad crt.sh: {latex_escape(crtsh_ids)} \quad {latex_escape(one_line_revocation(hit))}}}",
                        ]
                    )
                lines.extend(
                    [
                        r"\end{itemize}",
                        r"\medskip",
                        r"\textbf{SAN pattern snapshot}",
                        r"\par\medskip",
                        r"\MetricChip{DNS SANs}{" + str(san_summary["dns_count"]) + r"}" + " "
                        + r"\MetricChip{Other SANs}{" + str(san_summary["other_count"]) + r"}" + " "
                        + r"\MetricChip{Wildcard SANs}{" + str(san_summary["wildcard_count"]) + r"}" + " "
                        + r"\MetricChip{Numbered SANs}{" + str(san_summary["numbered_count"]) + r"}" + " "
                        + r"\MetricChip{DNS zones}{" + str(san_summary["zone_count"]) + r"}",
                        r"\par\medskip",
                        rf"\textbf{{Dominant zones}}: {latex_escape(', '.join(f'{zone} ({count})' for zone, count in san_summary['top_zones']) if san_summary['top_zones'] else 'none')}",
                        r"\par",
                        rf"\textbf{{Repeating host schemas}}: {latex_escape(', '.join(f'{pattern} ({count})' for pattern, count in san_summary['repeating_patterns']) if san_summary['repeating_patterns'] else 'mostly one-off SAN hostnames')}",
                        r"\end{tcolorbox}",
                        r"\begin{tcolorbox}[treepanel,title={SAN Structure}]",
                        r"\begin{Verbatim}[fontsize=\footnotesize]",
                    ]
                )
                lines.extend(build_san_tree_lines_with_style(unique_san_entries, ascii_only=True))
                lines.extend(
                    [
                        r"\end{Verbatim}",
                        r"\end{tcolorbox}",
                    ]
                )

    lines.extend(
        [
            r"\clearpage",
            r"\section*{Statistics}",
            r"\addcontentsline{toc}{section}{Statistics}",
            r"\begin{tcolorbox}[summary]",
            r"\MetricChip{Unique leaf certificates}{" + str(stats.unique_leaf_certificates) + r"}" + " "
            + r"\MetricChip{CN-family chapters}{" + str(stats.groups_total) + r"}" + " "
            + r"\MetricChip{Multi-certificate chapters}{" + str(stats.groups_multi_member) + r"}" + " "
            + r"\MetricChip{Singleton chapters}{" + str(stats.groups_singleton) + r"}",
            r"\par\medskip",
            r"\MetricChip{Numbered CN patterns}{" + str(stats.groups_by_type.get("numbered_cn_pattern", 0)) + r"}" + " "
            + r"\MetricChip{Exact endpoint families}{" + str(stats.groups_by_type.get("exact_endpoint_family", 0)) + r"}" + " "
            + r"\MetricChip{Non-leaf filtered}{" + str(stats.verification.non_leaf_filtered) + r"}" + " "
            + r"\MetricChip{Precert poison filtered}{" + str(stats.verification.precertificate_poison_filtered) + r"}",
            r"\end{tcolorbox}",
            r"\end{document}",
        ]
    )
    path.write_text("\n".join(line for line in lines if line != "") + "\n", encoding="utf-8")


def cleanup_latex_auxiliary_files(tex_path: Path, pdf_output: Path) -> None:
    generated_base = pdf_output.parent / tex_path.stem
    for suffix in (".aux", ".log", ".out", ".toc"):
        candidate = generated_base.with_suffix(suffix)
        if candidate.exists():
            candidate.unlink()


def compile_latex_to_pdf(tex_path: Path, pdf_output: Path, engine: str) -> None:
    engine_path = shutil.which(engine)
    if engine_path is None:
        raise RuntimeError(f"LaTeX engine not found: {engine}")
    tex_path = tex_path.resolve()
    pdf_output = pdf_output.resolve()
    pdf_output.parent.mkdir(parents=True, exist_ok=True)
    compile_cmd = [
        engine_path,
        "-interaction=nonstopmode",
        "-halt-on-error",
        "-output-directory",
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
            message = (result.stdout + "\n" + result.stderr).strip()
            raise RuntimeError(
                "LaTeX compilation failed.\n"
                + "\n".join(message.splitlines()[-40:])
            )
    generated_pdf = pdf_output.parent / f"{tex_path.stem}.pdf"
    if generated_pdf != pdf_output:
        generated_pdf.replace(pdf_output)
    cleanup_latex_auxiliary_files(tex_path, pdf_output)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Search crt.sh for currently valid certificates matching configured domain fragments.",
    )
    parser.add_argument(
        "--domains-file",
        type=Path,
        default=Path("domains.local.txt"),
        help="Text file containing one domain fragment per line.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("output/current-valid-certificates.md"),
        help="Readable single-file markdown report to write.",
    )
    parser.add_argument(
        "--latex-output",
        type=Path,
        default=Path("output/current-valid-certificates.tex"),
        help="Readable single-file LaTeX report to write.",
    )
    parser.add_argument(
        "--pdf-output",
        type=Path,
        default=Path("output/current-valid-certificates.pdf"),
        help="Compiled PDF report to write.",
    )
    parser.add_argument(
        "--pdf-engine",
        default="xelatex",
        help="LaTeX engine used to compile the PDF report.",
    )
    parser.add_argument(
        "--skip-pdf",
        action="store_true",
        help="Write Markdown and LaTeX outputs but skip PDF compilation.",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=Path(".cache/ct-search"),
        help="Directory for cached per-domain query results.",
    )
    parser.add_argument(
        "--cache-ttl-seconds",
        type=int,
        default=900,
        help="Reuse cached database results younger than this many seconds.",
    )
    parser.add_argument(
        "--max-candidates-per-domain",
        type=int,
        default=10000,
        help="Maximum raw crt.sh identity rows to inspect per domain fragment.",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=3,
        help="Retry count for replica/recovery conflicts from crt.sh.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress output.",
    )
    return parser.parse_args()


def main() -> int:
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
                print(f"[cache] domain={domain} records={len(cached)}", file=sys.stderr)
            all_records.extend(cached)
            continue
        if not args.quiet:
            print(f"[query] domain={domain}", file=sys.stderr)
        records = query_domain(
            domain=domain,
            max_candidates=args.max_candidates_per_domain,
            attempts=args.retries,
            verbose=not args.quiet,
        )
        if not args.quiet:
            print(f"[done] domain={domain} records={len(records)}", file=sys.stderr)
        store_cached_records(args.cache_dir, domain, args.max_candidates_per_domain, records)
        all_records.extend(records)
    hits, verification = build_hits(all_records)
    groups = build_groups(hits)
    scan_stats = ScanStats(
        generated_at_utc=utc_iso(datetime.now(UTC)),
        configured_domains=domains,
        unique_leaf_certificates=len(hits),
        groups_total=len(groups),
        groups_multi_member=sum(1 for group in groups if group.member_count > 1),
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
            f"[report] hits={len(hits)} groups={len(groups)} markdown={args.output} latex={args.latex_output}"
            + ("" if args.skip_pdf else f" pdf={args.pdf_output}"),
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
