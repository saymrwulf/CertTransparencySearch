# Certificate Transparency Search

This project builds a publication-grade monograph from Certificate Transparency and public DNS:

- it finds currently valid leaf certificates whose SAN values contain configured search terms
- it verifies locally that the certificates are real leaf certificates rather than CA certificates or precertificates
- it assesses intended usage from EKU and KeyUsage
- it scans the DNS names exposed by the SAN corpus
- it produces one primary readable output set: a monograph in Markdown, LaTeX, and PDF

The project is designed for public source control:

- real search terms live only in `domains.local.txt`
- generated artefacts live only in `output/`
- caches live only in `.cache/`

None of those paths should be committed.

## What You Need On A Fresh Machine

### Required software

- `git`
- `python3`
- `make`
- `dig`
- `xelatex`

### What each dependency is for

- `python3`: runs the scanners and report generators
- `make`: gives you short repeatable commands instead of long manual command lines
- `dig`: performs the live DNS scan
- `xelatex`: compiles the PDF reports

If `xelatex` is missing, the Markdown and LaTeX outputs can still be generated, but the PDF targets will fail.

## Fresh Install On Another Computer

Clone the repository from your chosen remote and enter the directory:

```bash
git clone <repository-url>
cd CertTransparencySearch
```

Create the local Python environment and install dependencies:

```bash
make bootstrap
```

Create the local-only search-term file:

```bash
make init-config
```

Then edit `domains.local.txt` and replace the placeholder values with the real search terms you want to scan.

## Local Search Terms

The tracked file is:

- `domains.example.txt`

The local-only file is:

- `domains.local.txt`

Rules:

- keep real search terms only in `domains.local.txt`
- do not rename that file unless you also pass `DOMAINS=...` to `make`
- do not commit it

## One-Command Runs

### Main publication

This is the single canonical publication. The appendices are embedded into the same monograph, so you do not need to manage separate visible appendix artefacts:

```bash
make monograph
```

Outputs:

- `output/corpus/monograph.md`
- `output/corpus/monograph.tex`
- `output/corpus/monograph.pdf`

Internal helper artefacts used during PDF assembly are written only under `.cache/monograph-temp/`.

### Supporting purpose assessment

This is optional. Its findings are already woven into the monograph, but the standalone output can still be useful during development:

```bash
make purpose
```

Outputs:

- `output/corpus/certificate-purpose-assessment.md`
- `output/corpus/certificate-purpose-assessment.json`

### Historical lineage analysis

This is optional. Its findings are already woven into the monograph, but the standalone output can still be useful during development:

This report extends the analysis across current and expired certificates to study:

- repeated issuance under the same Subject CN
- Subject CN with different Subject DN over time
- Subject CN with different issuing CA or vendor over time
- Subject CN with different SAN profiles over time
- issuance bursts and step-change start dates

```bash
make lineage
```

Outputs:

- `output/corpus/certificate-lineage-report.md`
- `output/corpus/certificate-lineage-report.tex`
- `output/corpus/certificate-lineage-report.pdf`

### Shorter executive report

```bash
make consolidated
```

Outputs:

- `output/corpus/consolidated-corpus-report.md`
- `output/corpus/consolidated-corpus-report.tex`
- `output/corpus/consolidated-corpus-report.pdf`

### Full operator run

This creates the local config if missing, then builds the full monograph:

```bash
make all
```

## Reproducibility And Run Behaviour

The default `Makefile` values are:

- `DOMAINS=domains.local.txt`
- `CACHE_TTL=0`
- `DNS_CACHE_TTL=86400`
- `MAX_CANDIDATES=10000`

This means:

- Certificate Transparency is refreshed live on every normal run.
- DNS results are reused for up to one day unless you override the DNS cache TTL.
- The query cap is high enough for the current corpus and the scanner will refuse to run if the live raw match count exceeds the cap.

If you want to override values:

```bash
make monograph CACHE_TTL=86400 DNS_CACHE_TTL=86400
```

Or:

```bash
make monograph DOMAINS=/path/to/other.local.txt
```

## Manual Commands

If you do not want to use `make`, the equivalent commands are:

### Inventory appendix source

This is only needed if you want the raw family inventory outside the monograph:

```bash
.venv/bin/python ct_scan.py \
  --domains-file domains.local.txt \
  --cache-ttl-seconds 0 \
  --max-candidates-per-domain 10000 \
  --output output/corpus/current-valid-certificates.md \
  --latex-output output/corpus/current-valid-certificates.tex \
  --pdf-output output/corpus/current-valid-certificates.pdf
```

### Purpose assessment

```bash
.venv/bin/python ct_usage_assessment.py \
  --domains-file domains.local.txt \
  --cache-ttl-seconds 0 \
  --max-candidates 10000 \
  --markdown-output output/corpus/certificate-purpose-assessment.md \
  --json-output output/corpus/certificate-purpose-assessment.json
```

### Consolidated report

```bash
.venv/bin/python ct_master_report.py \
  --domains-file domains.local.txt \
  --cache-ttl-seconds 0 \
  --dns-cache-ttl-seconds 86400 \
  --max-candidates-per-domain 10000 \
  --markdown-output output/corpus/consolidated-corpus-report.md \
  --latex-output output/corpus/consolidated-corpus-report.tex \
  --pdf-output output/corpus/consolidated-corpus-report.pdf
```

### Historical lineage report

```bash
.venv/bin/python ct_lineage_report.py \
  --domains-file domains.local.txt \
  --cache-ttl-seconds 0 \
  --max-candidates-per-domain 10000 \
  --markdown-output output/corpus/certificate-lineage-report.md \
  --latex-output output/corpus/certificate-lineage-report.tex \
  --pdf-output output/corpus/certificate-lineage-report.pdf
```

### Full monograph

```bash
.venv/bin/python ct_monograph_report.py \
  --domains-file domains.local.txt \
  --cache-ttl-seconds 0 \
  --dns-cache-ttl-seconds 86400 \
  --max-candidates-per-domain 10000 \
  --markdown-output output/corpus/monograph.md \
  --latex-output output/corpus/monograph.tex \
  --pdf-output output/corpus/monograph.pdf
```

## Project Structure

- `ct_scan.py`: core CT scan, leaf verification, grouping, and detailed inventory report
- `ct_usage_assessment.py`: EKU and KeyUsage assessment
- `ct_lineage_report.py`: historical Subject CN, Subject DN, issuer, SAN, and issuance-burst analysis
- `ct_dns_utils.py`: DNS scanning and provider-signature logic
- `ct_master_report.py`: shorter consolidated report
- `ct_monograph_report.py`: publication-grade monograph with embedded appendices
- `Makefile`: reproducible operator workflow

## Safety Against Silent Undercounts

The scanner checks the live raw identity-row count before it executes the capped query. If the configured cap is too low, it stops with an error instead of silently returning an incomplete corpus.

## Public Repo Rules

- keep `domains.local.txt` local only
- never commit `output/`
- never commit `.cache/`
- if you need a sample config in git, update `domains.example.txt`, not `domains.local.txt`
