#!/usr/bin/env python3

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
    "alpha",
    "beta",
    "dev",
    "qa",
    "uat",
    "sit",
    "stage",
    "stg",
    "preprod",
    "prod",
    "release",
    "squads",
    "sandbox",
}

VENDOR_HINTS = {
    "vendor",
    "external",
    "hoster",
    "product",
    "mitek",
    "scrive",
    "pega",
}

IDENTITY_HINTS = {
    "id",
    "idp",
    "identity",
    "auth",
    "sso",
    "online",
    "mail",
    "email",
    "secmail",
    "chat",
    "appointment",
    "appointments",
}

CUSTOMER_HINTS = {
    "brand",
    "branding",
    "campaign",
    "experience",
    "welcome",
    "thankyou",
    "gifts",
    "investment",
    "client",
    "customers",
    "information",
    "club",
    "risk",
}


@dataclass
class FocusSubject:
    subject_cn: str
    analyst_note: str


@dataclass
class FocusSubjectDetail:
    subject_cn: str
    analyst_note: str
    analyst_theme: str
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
    max_direct_to_carrier_overlap_days: int
    carrier_subjects: str
    current_red_flags: str
    past_red_flags: str


@dataclass
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
    notables: list[FocusSubjectDetail]
    transition_rows: list[FocusSubjectDetail]


def load_focus_subjects(path: Path) -> list[FocusSubject]:
    if not path.exists():
        return []
    subjects: list[FocusSubject] = []
    seen: set[str] = set()
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^(?P<cn>[^()]+?)(?:\s*\((?P<meta>.*)\))?$", line)
        if not match:
            continue
        subject_cn = match.group("cn").strip().lower()
        if subject_cn in seen:
            continue
        seen.add(subject_cn)
        subjects.append(
            FocusSubject(
                subject_cn=subject_cn,
                analyst_note=(match.group("meta") or "").strip(),
            )
        )
    return subjects


def dns_names(san_entries: list[str]) -> set[str]:
    return {entry[4:].lower() for entry in san_entries if entry.startswith("DNS:")}


def overlap_days(
    left_start,
    left_end,
    right_start,
    right_end,
) -> int:
    start = max(left_start, right_start)
    end = min(left_end, right_end)
    if end <= start:
        return 0
    return max(1, (end - start).days)


def pct(count: int, total: int) -> str:
    if total <= 0:
        return "0.0%"
    return f"{(count / total) * 100:.1f}%"


def short_issuer_family(issuer_name: str) -> str:
    lowered = issuer_name.lower()
    if "amazon" in lowered:
        return "Amazon"
    if "sectigo" in lowered or "comodo" in lowered:
        return "Sectigo/COMODO"
    if "google trust services" in lowered or "cn=we1" in lowered:
        return "Google Trust Services"
    return "Other"


def median_int(values: list[int]) -> int:
    if not values:
        return 0
    return int(median(values))


def average_text(values: list[int]) -> str:
    if not values:
        return "0.0"
    return f"{(sum(values) / len(values)):.1f}"


def san_size_span(current_hits: list[ct_scan.CertificateHit]) -> str:
    sizes = sorted({len(hit.san_entries) for hit in current_hits})
    if not sizes:
        return "-"
    if len(sizes) == 1:
        return str(sizes[0])
    return ", ".join(str(value) for value in sizes[:4]) + ("" if len(sizes) <= 4 else f", ... (+{len(sizes) - 4} more)")


def summarize_names(values: set[str], limit: int = 4) -> str:
    if not values:
        return "-"
    ordered = sorted(values, key=str.casefold)
    if len(ordered) <= limit:
        return ", ".join(ordered)
    return ", ".join(ordered[:limit]) + f", ... (+{len(ordered) - limit} more)"


def analyst_theme(subject: FocusSubject) -> str:
    tokens = set(re.findall(r"[a-z0-9]+", f"{subject.subject_cn} {subject.analyst_note}".lower()))
    if ENVIRONMENT_HINTS & tokens:
        return "environment or platform anchor"
    if VENDOR_HINTS & tokens:
        return "vendor or product integration"
    if IDENTITY_HINTS & tokens:
        return "identity, messaging, or service front"
    if CUSTOMER_HINTS & tokens:
        return "customer proposition or campaign front"
    left_label = subject.subject_cn.split(".")[0].lower()
    if re.fullmatch(r"\d+", left_label) or re.fullmatch(r"[a-z]{2,6}\d{1,4}", left_label):
        return "opaque or legacy label"
    return "human-named branded or service endpoint"


def observed_role(
    subject: FocusSubject,
    current_hits: list[ct_scan.CertificateHit],
    current_carriers: list[ct_scan.CertificateHit],
    historical_carriers: list[ct_lineage_report.HistoricalCertificate],
    observation: ct_dns_utils.DnsObservation,
) -> str:
    tokens = set(re.findall(r"[a-z0-9]+", f"{subject.subject_cn} {subject.analyst_note}".lower()))
    if not current_hits and current_carriers:
        return "carried today inside another certificate"
    if not current_hits and historical_carriers:
        return "historical carried alias or retired passenger"
    if not current_hits:
        return "not seen in the CT corpus"
    max_san_entries = max(len(hit.san_entries) for hit in current_hits)
    if max_san_entries >= 20 or (ENVIRONMENT_HINTS & tokens):
        return "platform matrix or environment anchor"
    revoked = sum(1 for hit in current_hits if hit.revocation_status == "revoked")
    if revoked >= 3:
        return "high-churn direct service front"
    if VENDOR_HINTS & tokens:
        return "direct vendor or product integration front"
    if IDENTITY_HINTS & tokens:
        return "direct service or identity front"
    if CUSTOMER_HINTS & tokens:
        return "direct branded or customer proposition front"
    if observation.classification in {"direct_address", "cname_to_address"}:
        return "direct standalone service front"
    return "standalone branded or service endpoint"


def basket_status(
    current_hits: list[ct_scan.CertificateHit],
    current_carriers: list[ct_scan.CertificateHit],
    historical_hits: list[ct_lineage_report.HistoricalCertificate],
    historical_carriers: list[ct_lineage_report.HistoricalCertificate],
) -> str:
    if current_hits and current_carriers:
        return "current direct-and-carried overlap"
    if current_hits:
        return "current direct subject certificate"
    if current_carriers:
        return "current SAN passenger only"
    if historical_hits and historical_carriers:
        return "historical direct-and-carried only"
    if historical_hits:
        return "historical direct only"
    if historical_carriers:
        return "historical SAN passenger only"
    return "not seen"


def red_flag_text(row_lookup: dict[str, str], subject_cn: str) -> str:
    return row_lookup.get(subject_cn.lower(), "-")


def build_analysis(
    subjects: list[FocusSubject],
    report: dict[str, object],
    assessment: ct_lineage_report.HistoricalAssessment,
    dns_cache_dir: Path,
    dns_cache_ttl_seconds: int,
) -> FocusCohortAnalysis | None:
    if not subjects:
        return None
    focus_set = {subject.subject_cn for subject in subjects}

    current_hits = report["hits"]
    current_by_cn: dict[str, list[ct_scan.CertificateHit]] = {}
    for hit in current_hits:
        current_by_cn.setdefault(hit.subject_cn.lower(), []).append(hit)

    historical_by_cn: dict[str, list[ct_lineage_report.HistoricalCertificate]] = {}
    for certificate in assessment.certificates:
        historical_by_cn.setdefault(certificate.subject_cn.lower(), []).append(certificate)

    non_focus_current = [hit for hit in current_hits if hit.subject_cn.lower() not in focus_set]
    non_focus_historical = [certificate for certificate in assessment.certificates if certificate.subject_cn.lower() not in focus_set]

    observation_by_name = report["observation_by_name"]
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
        detail = FocusSubjectDetail(
            subject_cn=subject.subject_cn,
            analyst_note=subject.analyst_note or "-",
            analyst_theme=analyst_theme(subject),
            observed_role=observed_role(subject, current_direct, current_carriers, historical_carriers, observation),
            basket_status=basket_status(current_direct, current_carriers, historical_direct, historical_carriers),
            current_direct_certificates=len(current_direct),
            historical_direct_certificates=len(historical_direct),
            current_non_focus_san_carriers=len(current_carriers),
            historical_non_focus_san_carriers=len(historical_carriers),
            current_revoked_certificates=sum(1 for hit in current_direct if hit.revocation_status == "revoked"),
            current_not_revoked_certificates=sum(1 for hit in current_direct if hit.revocation_status == "not_revoked"),
            current_dns_outcome=observation.stack_signature,
            current_dns_classification=observation.classification,
            current_issuer_families=", ".join(
                f"{name} ({count})"
                for name, count in current_issuer_families.most_common()
            ) or "-",
            historical_issuer_families=", ".join(
                f"{name} ({count})"
                for name, count in historical_issuer_families.most_common()
            ) or "-",
            current_san_size_span=san_size_span(current_direct),
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

    def zone_count(hit: ct_scan.CertificateHit) -> int:
        return len({ct_scan.san_tail_split(entry[4:])[1] for entry in hit.san_entries if entry.startswith("DNS:")})

    focus_current_subject_names = sorted({hit.subject_cn.lower() for hit in focus_current_hits})
    rest_current_subject_names = sorted({hit.subject_cn.lower() for hit in rest_current_hits})

    def observation_for_subject(name: str) -> ct_dns_utils.DnsObservation:
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
            -(
                (item.current_revoked_certificates > 0)
                + (item.current_non_focus_san_carriers > 0)
                + (item.historical_non_focus_san_carriers > 0)
                + (item.current_red_flags != "-")
                + (item.past_red_flags != "-")
            ),
            -item.current_direct_certificates,
            item.subject_cn,
        ),
    )[:10]

    return FocusCohortAnalysis(
        focus_subjects=subjects,
        details=sorted(detail_rows, key=lambda item: item.subject_cn.casefold()),
        provided_subjects_count=len(subjects),
        historically_seen_subjects_count=sum(
            1
            for item in detail_rows
            if item.historical_direct_certificates > 0 or item.historical_non_focus_san_carriers > 0
        ),
        current_direct_subjects_count=sum(1 for item in detail_rows if item.current_direct_certificates > 0),
        current_carried_only_subjects_count=sum(
            1
            for item in detail_rows
            if item.current_direct_certificates == 0 and item.current_non_focus_san_carriers > 0
        ),
        historical_non_focus_carried_subjects_count=sum(
            1
            for item in detail_rows
            if item.historical_non_focus_san_carriers > 0
        ),
        unseen_subjects=[item.subject_cn for item in detail_rows if item.basket_status == "not seen"],
        current_focus_certificate_count=len(focus_current_hits),
        current_rest_certificate_count=len(rest_current_hits),
        focus_revoked_current_count=sum(1 for hit in focus_current_hits if hit.revocation_status == "revoked"),
        focus_not_revoked_current_count=sum(1 for hit in focus_current_hits if hit.revocation_status == "not_revoked"),
        rest_revoked_current_count=sum(1 for hit in rest_current_hits if hit.revocation_status == "revoked"),
        rest_not_revoked_current_count=sum(1 for hit in rest_current_hits if hit.revocation_status == "not_revoked"),
        focus_revoked_share=pct(
            sum(1 for hit in focus_current_hits if hit.revocation_status == "revoked"),
            len(focus_current_hits),
        ),
        rest_revoked_share=pct(
            sum(1 for hit in rest_current_hits if hit.revocation_status == "revoked"),
            len(rest_current_hits),
        ),
        focus_median_san_entries=median_int([len(hit.san_entries) for hit in focus_current_hits]),
        focus_average_san_entries=average_text([len(hit.san_entries) for hit in focus_current_hits]),
        rest_median_san_entries=median_int([len(hit.san_entries) for hit in rest_current_hits]),
        rest_average_san_entries=average_text([len(hit.san_entries) for hit in rest_current_hits]),
        focus_multi_zone_certificate_count=sum(1 for hit in focus_current_hits if zone_count(hit) > 1),
        rest_multi_zone_certificate_count=sum(1 for hit in rest_current_hits if zone_count(hit) > 1),
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
        notables=notables,
        transition_rows=sorted(
            transition_rows,
            key=lambda item: (
                -(item.current_non_focus_san_carriers + item.historical_non_focus_san_carriers),
                -item.max_direct_to_carrier_overlap_days,
                item.subject_cn.casefold(),
            ),
        ),
    )
