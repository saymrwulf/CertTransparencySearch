PYTHON := .venv/bin/python
PIP := .venv/bin/pip
DOMAINS ?= domains.local.txt
CACHE_TTL ?= 0
DNS_CACHE_TTL ?= 86400
MAX_CANDIDATES ?= 10000

.PHONY: bootstrap install init-config inventory purpose lineage consolidated monograph all

bootstrap:
	python3 -m venv .venv
	$(PIP) install -r requirements.txt

install: bootstrap

init-config:
	test -f $(DOMAINS) || cp domains.example.txt $(DOMAINS)

inventory:
	$(PYTHON) ct_scan.py \
		--domains-file $(DOMAINS) \
		--cache-ttl-seconds $(CACHE_TTL) \
		--max-candidates-per-domain $(MAX_CANDIDATES) \
		--output output/corpus/current-valid-certificates.md \
		--latex-output output/corpus/current-valid-certificates.tex \
		--pdf-output output/corpus/current-valid-certificates.pdf

purpose:
	$(PYTHON) ct_usage_assessment.py \
		--domains-file $(DOMAINS) \
		--cache-ttl-seconds $(CACHE_TTL) \
		--max-candidates $(MAX_CANDIDATES) \
		--markdown-output output/corpus/certificate-purpose-assessment.md \
		--json-output output/corpus/certificate-purpose-assessment.json

lineage:
	$(PYTHON) ct_lineage_report.py \
		--domains-file $(DOMAINS) \
		--cache-ttl-seconds $(CACHE_TTL) \
		--max-candidates-per-domain $(MAX_CANDIDATES) \
		--markdown-output output/corpus/certificate-lineage-report.md \
		--latex-output output/corpus/certificate-lineage-report.tex \
		--pdf-output output/corpus/certificate-lineage-report.pdf

consolidated:
	$(PYTHON) ct_master_report.py \
		--domains-file $(DOMAINS) \
		--cache-ttl-seconds $(CACHE_TTL) \
		--dns-cache-ttl-seconds $(DNS_CACHE_TTL) \
		--max-candidates-per-domain $(MAX_CANDIDATES) \
		--markdown-output output/corpus/consolidated-corpus-report.md \
		--latex-output output/corpus/consolidated-corpus-report.tex \
		--pdf-output output/corpus/consolidated-corpus-report.pdf

monograph:
	$(PYTHON) ct_monograph_report.py \
		--domains-file $(DOMAINS) \
		--cache-ttl-seconds $(CACHE_TTL) \
		--dns-cache-ttl-seconds $(DNS_CACHE_TTL) \
		--max-candidates-per-domain $(MAX_CANDIDATES) \
		--markdown-output output/corpus/monograph.md \
		--latex-output output/corpus/monograph.tex \
		--pdf-output output/corpus/monograph.pdf \
		--appendix-markdown-output output/corpus/appendix-inventory.md \
		--appendix-latex-output output/corpus/appendix-inventory.tex \
		--appendix-pdf-output output/corpus/appendix-inventory.pdf

all: init-config purpose lineage monograph
