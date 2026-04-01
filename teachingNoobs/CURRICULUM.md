# teachingNoobs Curriculum

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
