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
2. **Check arXiv's current rule for survey papers.** In late 2025 arXiv's computer-science section announced that review and survey articles are only accepted when they have already passed peer review at a journal or conference. This paper is a survey *plus* an implementation and measurements, which helps, but the moderators decide; read the current policy at arxiv.org before spending time, and be ready to retitle or reframe it as a systems paper if asked. Journals and conferences are an alternative first step.
3. **Endorsement:** first-time submitters in a category may need an endorser. Ask a faculty member who has posted in cs.NI or cs.CR.
4. **Names and affiliations** must match the people submitting; every author should agree to the submission.
5. **Re-run the benchmarks** if you change the code (`python3 bench/fanout.py`, `bench/slow_receiver.py`, `bench/transfer_speed.py`, `bench/crypto_cost.py`) and update Tables VI to IX. The numbers in the paper are from one Apple-silicon laptop on loopback and say so.
6. **Honest scope:** message bodies are not yet end-to-end encrypted, and no `asyncio` comparison was made. Both are stated in the paper; if you finish either, update the abstract, Table V and Sections VII and VIII.
