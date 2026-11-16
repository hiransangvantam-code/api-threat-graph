# The professor's four recommendations, and what changed

| # | Recommendation | What was done | Where |
|---|---|---|---|
| 1 | Ten more systems from open source, not shops we generated, in different fields | Ten published systems at pinned commits: Online Boutique and Bank of Anthos (Google), Stan's Robot Shop and Acme Air (IBM), Spring PetClinic, PiggyMetrics, Lakeside Mutual, FTGO, Hotel Reservation (Cornell DeathStarBench), Istio Bookinfo. Nine fields (two of the ten are shops), eight languages, 65 services, 201 operations, 712 labelled weaknesses | `opensource/README.md` |
| 2 | Compare with other tools, for example IBM and NVIDIA | Eight free tools run on all ten systems. IBM API Connect + Akamai, NVIDIA Morpheus, Salt, Akamai, Harness Traceable, Wiz, Prisma Cloud, Defender for APIs, 42Crunch and four threat-modelling tools compared from their documentation, with sources | `docs/TOOLS_COMPARISON.md` |
| 3 | Benchmark ATG against the other tools on the ten systems: which is better, what is different, where tools hit limits (one language only) | ATG and the eight tools scored against the same labels: accuracy by category, precision, speed, the systems each tool cannot run on, and the services each one-language scanner can read | `docs/BENCHMARK_OSS.md`, `results/opensource/comparison.md` |
| 4 | The output should recommend what to fix and how to harden, not only percentages; with accuracy and speed | A new Phase 4 page per scan: risk after each fix, every finding with why it matters, the fix in the system's own gateway / Kubernetes / framework, how to verify it, a hardening baseline per service, accuracy and speed | `docs/HARDENING_REPORT.md`, `atg/hardening.py` |

## The results in four lines

- ATG ran on all ten systems and found 462 of the 712 labelled weaknesses (65%, precision 75%). The best
  Kubernetes scanner (Polaris) found 349 (49%, precision 95%) and could not run on three systems.
- Only ATG found API behaviour problems (52 of 82) and inventory and visibility problems (88 of 88). On
  deployment configuration ATG and Polaris are level (60% and 61%).
- Every other tool stops somewhere. The Kubernetes scanners cannot read Docker Compose. Spectral needs an
  API document, which seven systems lack. The code scanners read one language each: 26 of the 65 services
  between Bandit, gosec and njsscan.
- ATG together with Checkov finds 86% of all labels. The two are complements, not rivals.

## What to keep in mind when presenting this

- The running services in the benchmark are stand-ins built from each system's code. The deployment files
  and API documents are the systems' own. `REAL-Windows.bat <system>` runs seven of them on their real
  images on a laptop. It was tested with stand-ins only, because the registries were unreachable here.
- Version 1.5 fixed gaps that version 1.4 showed on these same systems. Version 1.4's 47% is the fair
  figure for systems ATG has never seen; 65% is after the fixes.
- Commercial tools were not run. Their row in the comparison is what their vendors say they do.
