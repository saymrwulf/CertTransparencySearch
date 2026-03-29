# Certificate Transparency Search

This project scans Certificate Transparency for currently valid leaf certificates whose SAN sets contain configured search terms, verifies the certificates locally, inspects revocation state, classifies intended usage from EKU and KeyUsage, and scans the public DNS names exposed by the certificate corpus.

The repository is designed for public source control:

- real search terms live only in `domains.local.txt`
- generated artefacts live only in `output/`
- caches live only in `.cache/`

None of those paths should be committed.

## Setup

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
cp domains.example.txt domains.local.txt
```

Edit `domains.local.txt` with the real search terms you want to scan.

## Safety Against Silent Undercounts

The scanner now refuses to run if the configured per-domain candidate cap is lower than the live raw match count from crt.sh. This prevents silent truncation when the raw identity set is larger than the cap.

## Core Inventory Report

```bash
.venv/bin/python ct_scan.py \
  --domains-file domains.local.txt \
  --cache-ttl-seconds 0 \
  --output output/current-valid-certificates.md \
  --latex-output output/current-valid-certificates.tex \
  --pdf-output output/current-valid-certificates.pdf
```

This report is the issuer-first inventory view.

## Purpose Assessment

```bash
.venv/bin/python ct_usage_assessment.py \
  --domains-file domains.local.txt \
  --cache-ttl-seconds 0 \
  --markdown-output output/certificate-purpose-assessment.md \
  --json-output output/certificate-purpose-assessment.json
```

This assessment classifies the current corpus into:

- TLS server only
- TLS server and client auth
- client auth only
- S/MIME only
- code signing only

## Monograph Report

```bash
.venv/bin/python ct_monograph_report.py \
  --domains-file domains.local.txt \
  --cache-ttl-seconds 0 \
  --dns-cache-ttl-seconds 86400 \
  --markdown-output output/corpus/monograph.md \
  --latex-output output/corpus/monograph.tex \
  --pdf-output output/corpus/monograph.pdf
```

This is the main publication-grade document for readers. It combines:

- data-integrity and completeness proof
- certificate inventory and issuer analysis
- purpose assessment
- naming-pattern interpretation
- public DNS delivery analysis
- crosswalk between certificate structure and DNS structure
- confidence and limit statements
- a full issuer-first inventory appendix embedded into the final PDF

The monograph also emits a standalone appendix inventory in the same output area:

- `output/corpus/appendix-inventory.md`
- `output/corpus/appendix-inventory.tex`
- `output/corpus/appendix-inventory.pdf`

## Short Consolidated Report

If you still want the shorter executive version, use:

```bash
.venv/bin/python ct_master_report.py \
  --domains-file domains.local.txt \
  --cache-ttl-seconds 0 \
  --dns-cache-ttl-seconds 86400 \
  --markdown-output output/corpus/consolidated-corpus-report.md \
  --latex-output output/corpus/consolidated-corpus-report.tex \
  --pdf-output output/corpus/consolidated-corpus-report.pdf
```

## Public Repo Rules

- Keep `domains.local.txt` local only.
- Never commit `output/`.
- Never commit `.cache/`.
- If you need a sample config in git, update `domains.example.txt`, not `domains.local.txt`.
