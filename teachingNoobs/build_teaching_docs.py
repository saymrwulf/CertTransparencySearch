#!/usr/bin/env python3

from __future__ import annotations

import ast
import html
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "teachingNoobs"

SOURCE_FILES = [
    "ct_scan.py",
    "ct_dns_utils.py",
    "ct_usage_assessment.py",
    "ct_lineage_report.py",
    "ct_caa_analysis.py",
    "ct_focus_subjects.py",
    "ct_master_report.py",
    "ct_monograph_report.py",
]

FILE_INTROS = {
    "ct_scan.py": (
        "Core Certificate Transparency scanner. This file talks to crt.sh's public "
        "database, downloads the real certificate bytes, verifies that they are real "
        "leaf certificates, groups them into readable families, and can render the "
        "full inventory appendix."
    ),
    "ct_dns_utils.py": (
        "Public DNS scanner. This file runs dig, follows alias chains, finds public "
        "addresses, and collapses raw DNS evidence into readable delivery labels."
    ),
    "ct_usage_assessment.py": (
        "Certificate-purpose analyzer. This file looks at EKU and KeyUsage to decide "
        "what each certificate is technically allowed to do."
    ),
    "ct_lineage_report.py": (
        "Historical analyzer. This file studies expired plus current certificates to "
        "find renewals, overlap, drift, and issuance bursts over time."
    ),
    "ct_caa_analysis.py": (
        "CAA analyzer. This file resolves live DNS issuance policy and compares it "
        "against the public CA families that are actually covering the names today."
    ),
    "ct_focus_subjects.py": (
        "Focused-cohort analyzer. This file takes your special hand-picked Subject CN "
        "list and compares it against the wider certificate and DNS estate."
    ),
    "ct_master_report.py": (
        "Current-state synthesizer. This file combines certificate facts, DNS facts, "
        "purpose classification, grouping, and curated examples into one report bundle."
    ),
    "ct_monograph_report.py": (
        "Publication builder. This file takes all analytical layers and turns them into "
        "the final monograph in Markdown, LaTeX, and PDF."
    ),
}

FILE_FLOW_STRIPS = {
    "ct_scan.py": "domains file -> raw CT query -> parsed leaf certificates -> CN families -> issuer trust -> appendix reports",
    "ct_dns_utils.py": "DNS name -> dig answers -> normalized observation -> provider hints -> delivery label",
    "ct_usage_assessment.py": "certificate bytes -> EKU and KeyUsage -> purpose label -> summary counts",
    "ct_lineage_report.py": "historical CT rows -> historical certificates -> grouped by Subject CN -> overlap and drift checks -> red flags",
    "ct_caa_analysis.py": "DNS name -> effective CAA lookup -> allowed CA families -> compare with live cert families",
    "ct_focus_subjects.py": "focus-subject file -> cohort entries -> compare against current and historical estate -> bucketed cohort explanation",
    "ct_master_report.py": "current CT facts + DNS facts + usage facts -> one current-state report bundle",
    "ct_monograph_report.py": "current-state bundle + history + CAA + focused cohort -> Markdown/LaTeX/PDF monograph",
}

BLOCK_NOTES = {
    "ct_scan.py": {
        "__module__": "Imports, SQL, constants, and shared data shapes for the core CT scanner.",
        "DatabaseRecord": "A raw row as it comes back from the crt.sh database before local cleanup.",
        "CertificateHit": "The cleaned working object used by the rest of the analytics pipeline.",
        "VerificationStats": "A tiny running counter that proves how many rows were kept or rejected.",
        "CertificateGroup": "One readable family of related certificates after grouping logic runs.",
        "ScanStats": "Top-level summary numbers used in reports.",
        "IssuerTrustInfo": "Stores the public-trust picture for one issuer family.",
        "connect": "Opens the direct guest PostgreSQL connection to crt.sh's certwatch backend.",
        "query_domain": "Runs the main certificate query for one search term and refuses silent undercounting.",
        "query_raw_match_count": "Counts how many raw hits exist before the capped query runs.",
        "build_hits": "Parses certificate bytes, rejects bad objects, and merges duplicate views of the same cert.",
        "build_groups": "Turns a flat certificate list into CN-based families such as exact endpoints or numbered rails.",
        "query_issuer_trust": "Checks which issuers are currently trusted for public TLS in the major WebPKI contexts.",
        "render_markdown_report": "Writes the raw inventory appendix as readable Markdown.",
        "render_latex_report": "Writes the raw inventory appendix as LaTeX for PDF assembly.",
        "compile_latex_to_pdf": "Hands LaTeX to XeLaTeX and turns it into a finished PDF file.",
        "main": "The standalone command-line entrypoint for the inventory scanner.",
    },
    "ct_dns_utils.py": {
        "__module__": "Shared DNS scanning helpers, cache helpers, and the logic that turns raw DNS answers into platform clues.",
        "DnsObservation": "One complete DNS observation for one hostname.",
        "scan_name_live": "Runs the live DNS walk for one hostname.",
        "scan_name_cached": "Reuses a recent DNS result if possible, otherwise performs the live scan.",
        "infer_provider_hints": "Reads the raw DNS trail and pulls out likely platform or vendor clues.",
        "infer_stack_signature": "Collapses several low-level DNS clues into one human-readable delivery label.",
        "provider_explanations": "Supplies the glossary text used later in the reports.",
    },
    "ct_usage_assessment.py": {
        "__module__": "Purpose-analysis constants and small data shapes for EKU and KeyUsage classification.",
        "PurposeClassification": "One certificate plus the usage label assigned to it.",
        "AssessmentSummary": "The roll-up numbers that power the purpose chapter.",
        "build_classifications": "Walks through all current certificates and labels them by intended usage.",
        "summarize": "Compresses the per-certificate labels into counts, templates, and issuer breakdowns.",
        "render_markdown": "Writes the standalone purpose report.",
        "main": "The standalone command-line entrypoint for the purpose analyzer.",
    },
    "ct_lineage_report.py": {
        "__module__": "Historical query logic, data structures, and red-flag rules for certificate lifecycle analysis.",
        "HistoricalCertificate": "One certificate in the full time-based dataset, including expired ones.",
        "CnCollisionRow": "A table row for Subject-DN drift or issuer drift under the same Subject CN.",
        "SanChangeRow": "A table row that describes SAN-profile change for one Subject CN.",
        "OverlapRow": "A table row describing long predecessor/successor overlap.",
        "RedFlagRow": "A compact summary row for names worth attention.",
        "HistoricalAssessment": "The full historical analysis bundle used by the monograph.",
        "query_historical_domain": "Fetches the wider historical corpus for one search term.",
        "build_certificates": "Converts raw DB rows into historical working objects.",
        "dn_change_rows": "Finds names whose formal Subject DN changed over time.",
        "issuer_change_rows": "Finds names whose issuing CA family changed over time.",
        "san_change_rows": "Finds names whose SAN bundle changed over time.",
        "overlap_rows": "Finds predecessor/successor pairs that overlap too long.",
        "build_assessment": "Runs the full historical workflow and returns the finished analytical bundle.",
        "render_markdown": "Writes the standalone historical report in Markdown.",
        "render_latex": "Writes the standalone historical report in LaTeX.",
        "main": "The standalone command-line entrypoint for the historical analyzer.",
    },
    "ct_caa_analysis.py": {
        "__module__": "Data structures and lookup logic for effective CAA policy analysis.",
        "CaaObservation": "One resolved CAA result before it is merged with certificate coverage data.",
        "CaaNameRow": "One final row that compares DNS policy with current live certificate families.",
        "CaaAnalysis": "The full CAA analysis bundle used by the monograph.",
        "relevant_caa_live": "Finds the effective live CAA for one name, including inheritance and alias behavior.",
        "build_analysis": "Runs CAA across the whole SAN namespace and compares policy with live issuance.",
        "rows_for_zone": "Filters the full analysis down to one configured DNS zone.",
    },
    "ct_focus_subjects.py": {
        "__module__": "Rules and data shapes for analyzing the special hand-picked Subject-CN cohort.",
        "FocusSubject": "One line from the local focus-subject file.",
        "FocusSubjectDetail": "One detailed analytical row for one focused Subject CN.",
        "FocusCohortAnalysis": "The full cohort comparison bundle used in the monograph.",
        "load_focus_subjects": "Reads the local focus-subject list and any analyst notes attached to it.",
        "classify_taxonomy_bucket": "Places a name into the direct-front, platform-anchor, or ambiguous bucket.",
        "observed_role": "Tries to describe what role the name appears to play in the public estate.",
        "build_analysis": "Runs the full comparison between the focused cohort and the rest of the estate.",
    },
    "ct_master_report.py": {
        "__module__": "Current-state report assembly code that sits above the low-level scanners.",
        "ExampleBlock": "A small narrative evidence block used in the naming chapter.",
        "load_records": "Loads current CT records for all configured search terms.",
        "enrich_dns": "Adds DNS observations and provider clues to the raw SAN-name list.",
        "pick_examples": "Chooses a few representative examples that make the naming and DNS story understandable.",
        "build_group_digest": "Builds a compact family catalogue used in reports.",
        "summarize_for_report": "Creates the big current-state dictionary consumed by the monograph builder.",
        "render_markdown": "Writes the shorter consolidated report in Markdown.",
        "render_latex": "Writes the shorter consolidated report in LaTeX.",
        "main": "The standalone command-line entrypoint for the consolidated current-state report.",
    },
    "ct_monograph_report.py": {
        "__module__": "The orchestration and publishing layer that turns all analytical modules into one publication.",
        "render_appendix_inventory": "Generates the hidden full inventory appendix before the main monograph is assembled.",
        "append_longtable": "Shared LaTeX helper for readable multi-page tables.",
        "render_markdown": "Writes the narrative monograph in Markdown.",
        "render_latex": "Writes the narrative monograph in LaTeX.",
        "main": "The top-level command-line entrypoint for the complete monograph build.",
    },
}

BLOCK_FLOWS = {
    "ct_scan.py": {
        "Module setup": ("Nothing yet; this is the starting point.", "`connect`, `query_domain`, `build_hits`, and the report renderers use these shared definitions."),
        "load_domains": ("Operator's local config file.", "`query_domain` and the higher-level loaders use this cleaned domain list."),
        "connect": ("Called by query functions that need live crt.sh data.", "`query_domain`, `query_raw_match_count`, and issuer-trust lookups all depend on this connection."),
        "query_raw_match_count": ("A domain string from the local config.", "`query_domain` uses this count to refuse silent undercounting."),
        "query_domain": ("A domain plus the safety cap and retry settings.", "`build_hits` receives the raw records returned here."),
        "build_hits": ("Raw `DatabaseRecord` rows from crt.sh.", "`build_groups`, purpose analysis, DNS analysis, and CAA analysis all consume these cleaned hits."),
        "build_groups": ("The flat list of `CertificateHit` objects.", "The report builders use these groups to turn raw certificate clutter into readable families."),
        "query_issuer_trust": ("The cleaned current certificate hits.", "Report builders use this trust view in the certificate chapters and appendix tables."),
        "render_markdown_report": ("Current hits, groups, and trust data.", "Produces the Markdown inventory appendix."),
        "render_latex_report": ("Current hits, groups, and trust data.", "Produces the LaTeX appendix source that later becomes PDF."),
        "compile_latex_to_pdf": ("A finished `.tex` file.", "Produces the human-readable PDF artifact."),
        "main": ("CLI arguments from the operator.", "Runs the whole scanner end to end."),
    },
    "ct_dns_utils.py": {
        "Module setup": ("Nothing yet; this is the starting point.", "The later DNS helpers all reuse these imports and small shared helpers."),
        "run_dig": ("A hostname and record type.", "`scan_name_live`, `dig_status`, `dig_short`, and `ptr_lookup` all rely on this."),
        "scan_name_live": ("One DNS name from a SAN entry.", "`scan_name_cached` returns this result shape to higher-level analytics."),
        "scan_name_cached": ("A DNS name plus cache settings.", "`ct_master_report.enrich_dns` uses this for every SAN name in the current corpus."),
        "infer_provider_hints": ("One normalized DNS observation.", "`infer_stack_signature` and the report layers use the hints it produces."),
        "infer_stack_signature": ("One DNS observation plus provider clues.", "`ct_master_report` uses the resulting label in naming and DNS chapters."),
        "provider_explanations": ("The delivery labels used by the report.", "The monograph glossary uses these explanations directly."),
    },
    "ct_usage_assessment.py": {
        "extract_eku_oids": ("One certificate object.", "`classify_purpose` uses these OIDs to decide the category."),
        "extract_key_usage_flags": ("One certificate object.", "`build_classifications` stores these flags as supporting evidence."),
        "classify_purpose": ("The EKU OID list from one certificate.", "`build_classifications` turns that decision into a per-certificate record."),
        "build_classifications": ("The cleaned current hits plus raw records.", "`summarize` compresses these rows into report-level counts."),
        "summarize": ("The per-certificate purpose labels.", "Current-state and monograph chapters use the summary counts and templates."),
        "main": ("CLI arguments from the operator.", "Runs the standalone purpose analysis end to end."),
    },
    "ct_lineage_report.py": {
        "query_historical_domain": ("A configured search domain.", "`load_records` uses it to build the wider historical corpus."),
        "build_certificates": ("Historical `DatabaseRecord` rows.", "`group_by_subject_cn` and all drift checks consume these normalized historical certificates."),
        "group_by_subject_cn": ("Historical certificates.", "`dn_change_rows`, `issuer_change_rows`, `san_change_rows`, and `overlap_rows` all work off this grouping."),
        "dn_change_rows": ("CN-grouped historical certificates.", "`build_assessment` uses these rows for Subject-DN drift sections."),
        "issuer_change_rows": ("CN-grouped historical certificates.", "`build_assessment` uses these rows for CA-family drift sections."),
        "san_change_rows": ("CN-grouped historical certificates.", "`build_assessment` uses these rows for SAN-drift sections."),
        "overlap_rows": ("CN-grouped historical certificates.", "`build_assessment` turns these into current and past overlap red flags."),
        "build_assessment": ("Historical records from all configured domains.", "The monograph and standalone historical reports consume this one big bundle."),
        "main": ("CLI arguments from the operator.", "Runs the standalone historical analysis end to end."),
    },
    "ct_caa_analysis.py": {
        "relevant_caa_live": ("One DNS name from the SAN universe.", "`build_analysis` uses this to learn the effective issuance policy per name."),
        "allowed_ca_families": ("Raw CAA rows for one effective policy.", "`build_analysis` uses the normalized families for policy-vs-live comparison."),
        "build_analysis": ("Current certificate hits and the configured zones.", "The monograph uses this for the CAA chapter and appendix."),
        "rows_for_zone": ("The full CAA analysis bundle.", "The monograph uses zone-filtered rows for per-zone policy tables."),
    },
    "ct_focus_subjects.py": {
        "load_focus_subjects": ("The local focus-subject file.", "`build_analysis` uses these parsed cohort entries."),
        "classify_taxonomy_bucket": ("One focused Subject CN plus surrounding evidence.", "`build_analysis` uses the bucket label in the focused-cohort chapter."),
        "observed_role": ("One focused Subject CN plus public evidence.", "`build_analysis` stores the plain-English role description."),
        "build_analysis": ("The focus-subject list, current-state report, and historical assessment.", "The monograph uses the resulting bundle for Chapter 8 and Appendix D."),
    },
    "ct_master_report.py": {
        "load_records": ("Configured domains from the local file.", "`summarize_for_report` uses the returned CT rows as its starting point."),
        "enrich_dns": ("The unique SAN DNS names from current hits.", "`summarize_for_report` uses the enriched observations for DNS chapters and examples."),
        "pick_examples": ("Current hits, groups, and DNS observations.", "`summarize_for_report` stores the chosen examples for the naming chapter."),
        "build_group_digest": ("Current groups plus DNS observations.", "Report builders use the digest in appendices and summary tables."),
        "summarize_for_report": ("Current CT rows, DNS observations, issuer trust, and usage facts.", "`ct_monograph_report.main` consumes this as the main current-state input."),
        "main": ("CLI arguments from the operator.", "Runs the shorter consolidated current-state report end to end."),
    },
    "ct_monograph_report.py": {
        "render_appendix_inventory": ("The current-state report bundle.", "Creates the hidden appendix files that are later embedded into the monograph."),
        "render_markdown": ("Current-state facts, history, CAA, and focused-cohort analysis.", "Produces the main Markdown monograph."),
        "render_latex": ("Current-state facts, history, CAA, and focused-cohort analysis.", "Produces the main LaTeX monograph source."),
        "main": ("CLI arguments from the operator.", "Runs the full publication pipeline from raw analytics to finished PDF."),
    },
}

CURRICULUM = """# teachingNoobs Curriculum

Open each file in VS Code and use Markdown Preview. The intended order is:

1. [ct_scan.md](./ct_scan.md)
   Why first: this is the core analytics engine. If you understand this file, you understand where the certificate facts come from.
2. [ct_dns_utils.md](./ct_dns_utils.md)
   Why second: this explains how the DNS side was scanned and interpreted.
3. [ct_usage_assessment.md](./ct_usage_assessment.md)
   Why third: this explains how certificate purpose was classified from EKU and KeyUsage.
4. [ct_lineage_report.md](./ct_lineage_report.md)
   Why fourth: this adds historical time and red-flag logic.
5. [ct_caa_analysis.md](./ct_caa_analysis.md)
   Why fifth: this adds the DNS-side issuance-policy layer.
6. [ct_focus_subjects.md](./ct_focus_subjects.md)
   Why sixth: this explains the special hand-picked Subject-CN cohort logic.
7. [ct_master_report.md](./ct_master_report.md)
   Why seventh: this shows how the current-state analytical layers are stitched into one coherent bundle.
8. [ct_monograph_report.md](./ct_monograph_report.md)
   Why last: this is the publishing layer. Read it last because it is about presentation and assembly, not fact extraction.

Suggested reading method:

- Keep the Markdown preview open.
- For each page, read the explanation on the right first.
- Then look left at the code block and see how the explanation maps onto the exact lines.
- Do not try to memorize every helper function on first pass. Focus on the few blocks that move real data from one stage to the next.
- Pay special attention to the new `Flow arrows` panel on the right side. That panel tells you where the block's output goes next.

What matters most:

- In `ct_scan.py`: how raw database rows become verified leaf certificates.
- In `ct_dns_utils.py`: how raw DNS answers become delivery clues.
- In `ct_lineage_report.py`: how the code decides what is a normal renewal versus a red flag.
- In `ct_caa_analysis.py`: how live DNS policy is compared with live certificate coverage.
- In `ct_master_report.py`: how the current-state pieces are combined.

What matters less on first read:

- tiny formatting helpers
- string-wrapping helpers
- Markdown/LaTeX table plumbing

Those are still useful, but they are support code, not the heart of the analytics.
"""


def block_span(node: ast.AST, next_node: ast.AST | None, total_lines: int) -> tuple[int, int]:
    start = min((item.lineno for item in getattr(node, "decorator_list", []) if hasattr(item, "lineno")), default=node.lineno)
    end = getattr(node, "end_lineno", None) or total_lines
    return start, end


def fallback_explanation(file_name: str, block_name: str, kind: str) -> str:
    lower = block_name.lower()
    if kind == "class":
        return "This class is a structured container for one piece of data that later code passes around instead of juggling many loose variables."
    if lower == "parse_args":
        return "This block defines the command-line knobs for the file: input paths, cache settings, output paths, and other runtime switches."
    if lower == "main":
        return "This is the file's entrypoint. It glues the earlier helper blocks together into one end-to-end run."
    if lower.startswith("load_"):
        return "This block loads data from disk, cache, or an earlier stage so later code can work with it."
    if lower.startswith("store_"):
        return "This block saves an intermediate result so the next run can reuse it instead of recomputing everything."
    if lower.startswith("query_"):
        return "This block asks an external source for data and returns it in a shape the rest of the file can use."
    if lower.startswith("extract_"):
        return "This block pulls one specific piece of information out of a larger object."
    if lower.startswith("build_"):
        return "This block constructs a richer higher-level result from simpler inputs."
    if lower.startswith("render_"):
        return "This block turns structured analysis data into human-readable output."
    if lower.startswith("classify_"):
        return "This block applies rules and chooses a category label."
    if lower.startswith("summarize_") or lower == "summarize":
        return "This block compresses many detailed rows into a smaller, easier-to-read summary."
    if lower.startswith("compile_"):
        return "This block hands an intermediate artifact to an external tool so it becomes a finished output file."
    if lower.startswith("group_"):
        return "This block clusters related items together so later code can analyze them as families instead of as isolated rows."
    if lower.startswith("normalize_") or lower.startswith("canonicalize_"):
        return "This block makes values consistent so matching and grouping do not get confused by superficial differences."
    if lower.startswith("pct") or lower in {"utc_iso", "truncate_text", "first_list_item"}:
        return "This is a small helper that keeps the larger analytical code cleaner and easier to reuse."
    return f"This {kind} is one of the building blocks inside `{file_name}`. It exists so the file can do one narrow job at a time instead of one giant unreadable routine."


def explain_block(file_name: str, block_name: str, kind: str) -> str:
    specific = BLOCK_NOTES.get(file_name, {}).get(block_name)
    if specific:
        return specific
    return fallback_explanation(file_name, block_name, kind)


def code_panel(code: str, language: str = "python") -> str:
    escaped = html.escape(code.rstrip())
    return (
        '<pre style="margin:0; padding:14px; overflow-x:auto; background:#111827; '
        'color:#e5e7eb; border-radius:10px; border:1px solid #374151; font-size:12px; '
        'line-height:1.45;"><code class="language-'
        + language
        + '">'
        + escaped
        + "</code></pre>"
    )


def explanation_panel(title: str, text: str) -> str:
    return (
        f"<p><strong>{html.escape(title)}</strong></p>"
        f"<p>{html.escape(text)}</p>"
    )


def flow_panel(file_name: str, block_name: str) -> str:
    upstream, downstream = BLOCK_FLOWS.get(file_name, {}).get(
        block_name,
        (
            "Earlier blocks or operator input feed this block.",
            "Later blocks in the same file or in the next analytical stage consume its output.",
        ),
    )
    return (
        "<p><strong>Flow arrows</strong></p>"
        f"<p>{html.escape(upstream)} &#8594; <strong>{html.escape(block_name)}</strong> &#8594; {html.escape(downstream)}</p>"
    )


def make_doc_for_file(file_name: str) -> str:
    path = ROOT / file_name
    source = path.read_text(encoding="utf-8")
    lines = source.splitlines()
    tree = ast.parse(source, filename=file_name)
    top_nodes = [node for node in tree.body if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))]

    blocks: list[tuple[str, str, str]] = []
    if top_nodes:
        first_start = min(
            (item.lineno for item in getattr(top_nodes[0], "decorator_list", []) if hasattr(item, "lineno")),
            default=top_nodes[0].lineno,
        )
        preamble_end = first_start - 1
        if preamble_end >= 1:
            preamble_code = "\n".join(lines[:preamble_end]).rstrip()
            if preamble_code:
                blocks.append(("Module setup", "module", preamble_code))

    for index, node in enumerate(top_nodes):
        next_node = top_nodes[index + 1] if index + 1 < len(top_nodes) else None
        start, end = block_span(node, next_node, len(lines))
        code = "\n".join(lines[start - 1 : end]).rstrip()
        kind = "class" if isinstance(node, ast.ClassDef) else "function"
        blocks.append((node.name, kind, code))

    page_lines = [
        f"# {file_name}",
        "",
        f"Source file: [`{file_name}`](../{file_name})",
        "",
        FILE_INTROS[file_name],
        "",
        f"Main flow in one line: `{FILE_FLOW_STRIPS[file_name]}`",
        "",
        "How to read this page:",
        "",
        "- left side: the actual source code block",
        "- right side: a plain-English explanation for a beginner",
        "- read from top to bottom because later blocks depend on earlier ones",
        "",
    ]

    for title, kind, code in blocks:
        explanation = explain_block(file_name, "__module__" if kind == "module" else title, kind)
        page_lines.extend(
            [
                f"## {title}",
                "",
                '<table style="width:100%; table-layout:fixed; border-collapse:collapse;">',
                "<tr>",
                '<td style="width:50%; vertical-align:top; padding:8px;">',
                code_panel(code),
                "</td>",
                '<td style="width:50%; vertical-align:top; padding:8px;">',
                explanation_panel("What this block is doing", explanation),
                flow_panel(file_name, title),
                explanation_panel(
                    "How to think about it",
                    "Treat this block as one small station in a pipeline. Ask: what comes in here, what gets changed here, and what comes out for the next block?",
                ),
                "</td>",
                "</tr>",
                "</table>",
                "",
            ]
        )

    return "\n".join(page_lines) + "\n"


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for file_name in SOURCE_FILES:
        doc_path = OUT_DIR / file_name.replace(".py", ".md")
        doc_path.write_text(make_doc_for_file(file_name), encoding="utf-8")
    (OUT_DIR / "CURRICULUM.md").write_text(CURRICULUM, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
