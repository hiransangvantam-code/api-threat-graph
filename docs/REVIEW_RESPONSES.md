# Review feedback and what changed (version 1.3)

Seven points came back after the demo. This file lists each one, what was changed or measured, and where to look.

| # | Feedback | What we did | Where |
|---|---|---|---|
| 1 | How is the data cleaned up once a company's review is finished? | Two clean-up levels. STOP stops both Dockers and deletes all review data (`docker compose down -v`). CLEAN also deletes the report pages and exports, after a confirmation. Each scan also clears the traffic and spans it has read. | `docs/DATA_HANDLING.md`, `STOP-Windows.bat`, `CLEAN-Windows.bat`, `stop.sh`, `clean.sh` |
| 2 | How to run | Guide rewritten in English: the demo, what each page shows, export, stop and clean, step-by-step commands, and a new section on reviewing a system other than ShopLite (`TARGET_NETWORK`, `TARGET_GATEWAY`, `TARGET_CONFIG`). | `HOW-TO-RUN.md`, `README.md` |
| 3 | Test limits | What a passive review cannot detect, by OWASP API Top 10 category, and a stress test of system size and call-chain density. The stress test found two bottlenecks, the fix planner and missing PostgreSQL statistics, and both were fixed without changing any result. | `docs/LIMITS.md`, `results/stress/`, `bench/stress.py` |
| 4 | Compare speed and effectiveness with other people's tools | OWASP ZAP 2.16.1 on the same ShopLite build, through the gateway and inside the network, scored against the same planted weaknesses. | `docs/COMPARISON_ZAP.md`, `results/zap/`, `bench/compare_zap.py` |
| 5 | Keep only the graph and clear leftover data (important) | Captured traffic, spans, Phase 1 files, EUJF/analysis JSON and the database now live in memory only. After STOP, only the threat graph exports and the report pages are left. | `docker-compose.yml`, `docker/scan.py`, `docs/DATA_HANDLING.md` |
| 6 | Do not keep data permanently, it belongs to the customer | Nothing raw is ever written to disk. Pages and exports stay only until CLEAN or the next START. | same as 5 |
| 7 | Which file format for exporting the threat graph? | GraphML for the graph, SARIF 2.1.0 for the findings, node-link JSON for scripts, SVG for documents. All four are written for every scan, and each was checked with an outside reader (NetworkX, the official SARIF schema, Chromium). | `docs/EXPORT_FORMATS.md`, `atg/export.py` |

## Main results

- **Data left after STOP** on the demo: before, 808 captured flows, 108 span batches, the graph database and 37 working files; now, six report pages and eight export files, nothing else (`docs/DATA_HANDLING.md`).
- **Limits** (`results/stress/tables.md`): Phase 3 takes 0.4 s for 31 services, 4.5 s for 151 and 20.7 s for 301 services. Version 1.2 needed 57 s for 61 services and did not finish 151 in five minutes. The two fixes (a faster fix planner with identical plans, and `ANALYZE` on PostgreSQL) came out of this test. The remaining limit is dense call chains: with 31 services it fails at four random calls per endpoint, because the number of attack paths up to 9 hops explodes.
- **ZAP comparison** (`results/zap/tables.md`): on ShopLite, ATG found 37 of the 40 planted weaknesses while sending 18 read-only requests. ZAP sent about 3,400 attack requests per run, reached the 8 documented endpoints (none of the 4 shadow ones), and found none of the 40. It did find one real low-risk issue ATG does not check (a missing `X-Content-Type-Options` header). The two tools look for different things, and `docs/COMPARISON_ZAP.md` explains why this result does not mean ZAP is weak.
- **Exports**: GraphML, JSON, SARIF and SVG for every scan. SARIF validates against the official schema.

Paper text for all of this: `docs/PAPER_ADDITIONS.md`.
