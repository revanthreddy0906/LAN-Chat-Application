# Preparing this paper for arXiv

Files: `survey_paper.tex` (single file: figures are TikZ, the bibliography is inline, no external files), `survey_paper.pdf` (compiled), `survey_paper_original.*` (the earlier version, kept for reference). Compile check: `tectonic survey_paper.tex` (or `pdflatex` twice).

## Metadata to paste into the arXiv form

- **Title:** TCP-Based Multi-Client LAN Messaging: A Survey of Transport, Framing, Concurrency and Security, and LANChat-H, an Implemented and Measured Dependency-Light Reference Design
- **Authors:** Harish Goud B; Revanth Reddy Lingala; Saarthak Manocha
- **Primary category:** cs.NI (Networking and Internet Architecture). **Cross-lists:** cs.CR (Cryptography and Security), cs.DC (Distributed, Parallel, and Cluster Computing)
- **Comments:** 10 pages, 9 tables, 2 figures. Code and benchmark scripts: https://github.com/revanthreddy0906/LAN-Chat-Application
- **License:** your choice at submission; CC BY 4.0 is the usual one for papers.
- **Abstract:** copy the text of the abstract in the .tex (remove the LaTeX; there is no maths in it).

## Before you submit

1. **Push the code to the repository** (https://github.com/revanthreddy0906/LAN-Chat-Application) before submitting, so the link in the paper works. Do not commit `accounts.db`, `accounts_files/` or any `*.key`: the `.gitignore` in the project excludes them; check with `git status` first. Add a `LICENSE` file (for example MIT) so others know how they may reuse it. For a citable DOI, archive a release on Zenodo.
2. **arXiv's rule for survey papers (checked against the arXiv blog post of 31 Oct 2025, "Attention authors: updated practice for review articles and position papers in arXiv CS category").** Review/survey articles and position papers in cs must already be **accepted at a journal or a conference after peer review**; workshop review does not count. Non-compliant submissions will likely be rejected and not appear, and you should **not resubmit** a rejected one without an accepted appeal (appeals are for after peer review is complete). Research papers are not affected. This paper's current title and abstract present it as a survey ("A Survey of ... ", "This paper surveys"), so a moderator could treat it as a review article. Options: (a) get it accepted at a journal or conference first, then submit with the journal reference and DOI; (b) if you believe its main contribution is the system and its measurements, retitle and rewrite the abstract and introduction honestly as a systems paper with the survey as related work, and accept that the moderators decide; (c) post it somewhere else first (for example Zenodo for a DOI, or TechRxiv; check each site's rules).
3. **Endorsement:** first-time submitters in a category may need an endorser. Ask a faculty member who has posted in cs.NI or cs.CR.
4. **Names and affiliations** must match the people submitting; every author should agree to the submission.
5. **Re-run the benchmarks** if you change the code (`python3 bench/fanout.py`, `bench/slow_receiver.py`, `bench/transfer_speed.py`, `bench/crypto_cost.py`) and update Tables VI to IX. The numbers in the paper are from one Apple-silicon laptop on loopback and say so.
6. **Honest scope:** message bodies are not yet end-to-end encrypted, and no `asyncio` comparison was made. Both are stated in the paper; if you finish either, update the abstract, Table V and Sections VII and VIII.
