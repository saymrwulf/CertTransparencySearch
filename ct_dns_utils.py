#!/usr/bin/env python3

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

import ct_scan


@dataclass
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
    provider_hints: list[str]


def normalize_name(name: str) -> str:
    return name.rstrip(".").lower()


def cache_key(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
    slug = re.sub(r"[^a-z0-9.-]+", "-", value.lower()).strip("-")
    slug = slug[:80] or "item"
    return f"v1-{slug}-{digest}.json"


def load_json_cache(cache_dir: Path, key: str, ttl_seconds: int) -> dict[str, Any] | None:
    path = cache_dir / key
    if not path.exists():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    cached_at = datetime.fromisoformat(payload["cached_at"].replace("Z", "+00:00"))
    age = time.time() - cached_at.astimezone(UTC).timestamp()
    if age > ttl_seconds:
        return None
    return payload


def store_json_cache(cache_dir: Path, key: str, payload: dict[str, Any]) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    enriched = dict(payload)
    enriched["cached_at"] = ct_scan.utc_iso(datetime.now(UTC))
    (cache_dir / key).write_text(json.dumps(enriched, indent=2, sort_keys=True), encoding="utf-8")


def run_dig(name: str, rrtype: str, short: bool) -> str:
    cmd = ["dig", "+time=2", "+tries=1"]
    if short:
        cmd.append("+short")
    else:
        cmd.extend(["+noall", "+comments", "+answer"])
    cmd.extend([name, rrtype])
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return result.stdout


def dig_status(name: str, rrtype: str = "A") -> str:
    output = run_dig(name, rrtype, short=False)
    match = re.search(r"status:\s*([A-Z]+)", output)
    if match:
        return match.group(1)
    if output.strip():
        return "NOERROR"
    return "UNKNOWN"


def dig_short(name: str, rrtype: str) -> list[str]:
    output = run_dig(name, rrtype, short=True)
    return [normalize_name(line) for line in output.splitlines() if line.strip()]


def parse_answer_section(output: str) -> list[tuple[str, str]]:
    in_answer = False
    parsed: list[tuple[str, str]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith(";; ANSWER SECTION:"):
            in_answer = True
            continue
        if not in_answer or line.startswith(";;"):
            continue
        match = re.match(r"^\S+\s+\d+\s+IN\s+(\S+)\s+(.+)$", line)
        if not match:
            continue
        rrtype, rdata = match.groups()
        parsed.append((rrtype.upper(), normalize_name(rdata)))
    return parsed


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def classify_observation(chain: list[str], terminal_status: str, a_records: list[str], aaaa_records: list[str]) -> str:
    has_addresses = bool(a_records or aaaa_records)
    if chain and has_addresses:
        return "cname_to_address"
    if chain and not has_addresses:
        return "dangling_cname"
    if has_addresses:
        return "direct_address"
    if terminal_status == "NXDOMAIN":
        return "nxdomain"
    if terminal_status == "NOERROR":
        return "no_data"
    return "other"


def infer_provider_hints(observation: DnsObservation) -> list[str]:
    text = " ".join(
        [
            observation.original_name,
            *observation.cname_chain,
            observation.terminal_name,
            *observation.ptr_records,
        ]
    ).lower()
    hints: list[str] = []
    if "campaign.adobe.com" in text:
        hints.append("Adobe Campaign")
    if "cloudfront.net" in text:
        hints.append("AWS CloudFront")
    if "elb.amazonaws.com" in text or "compute.amazonaws.com" in text:
        hints.append("AWS")
    if "apigee.net" in text or "googleusercontent.com" in text:
        hints.append("Google Apigee")
    if "pegacloud.net" in text or ".pega.net" in text:
        hints.append("Pega Cloud")
    if "useinfinite.io" in text:
        hints.append("Infinite / agency alias")
    if any(ip.startswith("13.107.") for ip in observation.a_records) or any(ip.startswith("2620:1ec:") for ip in observation.aaaa_records):
        hints.append("Microsoft Edge")
    if not hints:
        hints.append("Unclassified")
    return hints


def infer_stack_signature(observation: DnsObservation) -> str:
    hints = infer_provider_hints(observation)
    if observation.classification == "nxdomain":
        return "No public DNS (NXDOMAIN)"
    if observation.classification == "no_data":
        return "No public address data"
    if "Adobe Campaign" in hints and "AWS CloudFront" in hints:
        return "Adobe Campaign -> AWS CloudFront"
    if "Adobe Campaign" in hints and "AWS" in hints:
        return "Adobe Campaign -> AWS ALB"
    if "Adobe Campaign" in hints and observation.a_records:
        return "Adobe Campaign direct IP"
    if "AWS CloudFront" in hints:
        return "AWS CloudFront"
    if "Google Apigee" in hints:
        return "Google Apigee"
    if "Pega Cloud" in hints and "AWS" in hints:
        return "Pega Cloud -> AWS ALB"
    if "Infinite / agency alias" in hints and observation.classification == "dangling_cname":
        return "Dangling agency alias"
    if "Microsoft Edge" in hints:
        return "Direct Microsoft edge"
    if "AWS" in hints:
        return "Direct AWS"
    if observation.classification == "direct_address":
        return "Direct address (provider unclear)"
    if observation.classification == "cname_to_address":
        return "CNAME to address (provider unclear)"
    return hints[0]


def scan_name_live(name: str) -> DnsObservation:
    name = normalize_name(name)
    a_output = run_dig(name, "A", short=False)
    aaaa_output = run_dig(name, "AAAA", short=False)
    original_status = dig_status(name, "A")
    a_answers = parse_answer_section(a_output)
    aaaa_answers = parse_answer_section(aaaa_output)
    chain: list[str] = []
    for rrtype, rdata in a_answers + aaaa_answers:
        if rrtype == "CNAME" and rdata not in chain:
            chain.append(rdata)
    a_records = sorted({rdata for rrtype, rdata in a_answers if rrtype == "A" and is_ip_address(rdata)})
    aaaa_records = sorted({rdata for rrtype, rdata in aaaa_answers if rrtype == "AAAA" and is_ip_address(rdata)})
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
        stack_signature="",
        provider_hints=[],
    )
    observation.provider_hints = infer_provider_hints(observation)
    observation.stack_signature = infer_stack_signature(observation)
    return observation


def scan_name_cached(name: str, cache_dir: Path, ttl_seconds: int) -> DnsObservation:
    key = cache_key(name)
    cached = load_json_cache(cache_dir, key, ttl_seconds)
    if cached is not None:
        payload = dict(cached)
        payload.pop("cached_at", None)
        return DnsObservation(**payload)
    observation = scan_name_live(name)
    store_json_cache(cache_dir, key, asdict(observation))
    return observation


def ptr_lookup(ip: str, cache_dir: Path, ttl_seconds: int) -> list[str]:
    key = cache_key(f"ptr-{ip}")
    cached = load_json_cache(cache_dir, key, ttl_seconds)
    if cached is not None:
        return list(cached.get("answers", []))
    output = subprocess.run(
        ["dig", "+time=2", "+tries=1", "+short", "-x", ip, "PTR"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    answers = [normalize_name(line) for line in output.splitlines() if line.strip()]
    store_json_cache(cache_dir, key, {"answers": answers})
    return answers


def provider_explanations() -> dict[str, str]:
    return {
        "Adobe Campaign": "A marketing and communication platform often used to send customer messages, email journeys, and campaign traffic. In DNS terms, it can sit in front of cloud infrastructure rather than hosting the final application by itself.",
        "AWS": "Amazon Web Services, a large public cloud platform. In this report it usually means the endpoint ultimately lands on Amazon-hosted compute or load-balancing infrastructure.",
        "AWS ALB": "AWS Application Load Balancer. A traffic-distribution front door that sends incoming web requests to one or more backend services.",
        "AWS CloudFront": "Amazon's global content-delivery and edge network. It is often used to front websites, APIs, and static assets close to users.",
        "Google Apigee": "An API gateway and API-management layer. If a hostname lands here, it usually means the public endpoint is being governed as an API product rather than being exposed directly from an application server.",
        "Pega Cloud": "A managed hosting platform for Pega applications and workflow systems. It often fronts case-management or process-heavy applications.",
        "Microsoft Edge": "Microsoft-operated edge infrastructure. In DNS this usually means the public name lands on Microsoft's front-door network rather than directly on a private application host.",
        "Infinite / agency alias": "A third-party aliasing pattern typically used by an agency or service intermediary. It points traffic onward to the actual delivery platform.",
        "CNAME": "A DNS alias record. It says one hostname is really another hostname, rather than directly mapping to an IP address.",
        "A record": "A DNS record that maps a hostname to an IPv4 address.",
        "AAAA record": "A DNS record that maps a hostname to an IPv6 address.",
        "PTR record": "A reverse-DNS record. It maps an IP address back to a hostname and is useful as a provider clue, not as proof of ownership.",
        "NXDOMAIN": "A DNS response meaning the name does not exist publicly.",
    }
