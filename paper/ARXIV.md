# Preparing this paper for arXiv

Files: `survey_paper.tex` (single file: figures are TikZ, the bibliography is inline, no external files), `survey_paper.pdf` (compiled), `survey_paper_original.*` (the first version) and `survey_paper_survey_version.*` (the survey-framed version, kept in case a journal or conference accepts it first). Compile check: `tectonic survey_paper.tex` (or `pdflatex` twice).

## Metadata to paste into the arXiv form

- **Title:** LANChat-H: Design, Implementation and Evaluation of a Dependency-Light Secure LAN Chat System with End-to-End Encryption
- **Authors:** Harish Goud B; Revanth Reddy Lingala; Saarthak Manocha
- **Primary category:** cs.NI (Networking and Internet Architecture). **Cross-lists:** cs.CR (Cryptography and Security), cs.DC (Distributed, Parallel, and Cluster Computing)
- **Comments:** 9 pages, 9 tables, 2 figures, 1 listing. Code and benchmark scripts: https://github.com/revanthreddy0906/LAN-Chat-Application
- **License:** your choice at submission; CC BY 4.0 is the usual one for papers.
- **Abstract:** copy the text of the abstract in the .tex (remove the LaTeX; there is no maths in it).

## Before you submit

1. **Push the code to the repository** (https://github.com/revanthreddy0906/LAN-Chat-Application) before submitting, so the link in the paper works. Do not commit `accounts.db`, `accounts_files/` or any `*.key`: the `.gitignore` in the project excludes them; check with `git status` first. Add a `LICENSE` file (for example MIT) so others know how they may reuse it. For a citable DOI, archive a release on Zenodo.
2. **arXiv's rule for survey papers (arXiv blog, 31 Oct 2025).** Review/survey and position papers in cs must already be accepted at a journal or conference after peer review. The paper is now framed as a **systems paper**: the contribution is the design, implementation and measurement of LANChat-H, and the literature is Related Work (Section II). Moderators decide the category, so keep the abstract and introduction as they are (do not re-add words like ``survey''). The earlier survey-framed version is in `survey_paper_survey_version.*`; if a moderator still treats the paper as a review, do not resubmit without an accepted appeal; post it on Zenodo or TechRxiv instead.
3. **Endorsement:** first-time submitters in a category may need an endorser. Ask a faculty member who has posted in cs.NI or cs.CR.
4. **Names and affiliations** must match the people submitting; every author should agree to the submission.
5. **Re-run the benchmarks** if you change the code (`python3 bench/fanout.py`, `bench/slow_receiver.py`, `bench/transfer_speed.py`, `bench/crypto_cost.py`) and update Tables VI to IX (the evaluation section). The numbers in the paper are from one Apple-silicon laptop on loopback and say so.
6. **Honest scope:** the paper states that there is no forward secrecy, that the server still sees metadata, that all measurements come from one machine and that no `asyncio` comparison was made. If you finish any of these, update the abstract, Table V and Sections VII and VIII.
