# Data handling: what ATG keeps, and how it is cleaned up

A review looks at another company's system, so everything ATG collects belongs to that company. The rule since version 1.3 is simple. The company's data stays inside its network while the review runs, and once the review is over, nothing is left on the reviewer's computer except the threat graph and the report pages. Those stay only until they are handed over.

## Where each piece of data lives

| Data | Contains | Where | Deleted |
|---|---|---|---|
| Captured traffic (`flows.jsonl`) | method, path, header names, auth scheme, body shapes, status, timing. Never header values, tokens or body values (`extractor/mitm_addon.py`) | Docker volume `capture`, in memory (tmpfs) | the part a scan has read is cleared right after the scan; the rest at STOP |
| Spans (`spans.jsonl`) | OpenTelemetry spans as the services send them (service, operation, timing, attributes) | Docker volume `telemetry`, in memory (tmpfs) | same as traffic |
| The scan's copy of that input | the lines the scan took from the two files above | `/work/scan-input/` in the `atg` container, in memory | as soon as Phase 1 has read it |
| Phase 1 JSON, Phase 1 report | what each source found | `/work/live/`, in memory | STOP |
| EUJF JSON, analysis JSON | Phase 2 and Phase 3 output | `/work/live/` and `/work/runs/`, in memory | STOP |
| PostgreSQL (`atg_eujf`, `atg_nodes`, `atg_edges`, `atg_findings`, `atg_paths`) | API inventory and threat graph | the `atg-postgres` data folder, in memory (tmpfs) | STOP |
| Report pages | dashboards and threat graph pages | `output/site/` on disk | CLEAN, or the next START |
| Threat graph exports | GraphML, JSON, SARIF, SVG per scan (`docs/EXPORT_FORMATS.md`) | `output/site/exports/<scan>/` on disk | CLEAN, or the next START |

"In memory" means a tmpfs mount. The data is in RAM and never touches the disk, and it is gone when the container or volume is removed. PostgreSQL works the same way, its data folder is a tmpfs mount, so nothing survives STOP.

## The three commands

| Command | What it does to data |
|---|---|
| START (`START-Windows.bat`, `sh start.sh`) | Starts a fresh review. It deletes the previous review's pages and exports, the leftovers of versions before 1.3 (the `atg_atg-capture` and `atg_atg-telemetry` volumes and any working files in `output/`), and starts an empty database. |
| STOP (`STOP-Windows.bat`, `sh stop.sh`) | `docker compose down -v` for both Dockers. This removes every container, the in-memory volumes and the database. Only `output/site/` is left. |
| CLEAN (`CLEAN-Windows.bat`, `sh clean.sh`) | Asks for confirmation, then does what STOP does and also deletes `output/`. Run it after the report has been handed over. |

Closing the PowerShell window does not stop Docker. Use STOP.

## Checking that nothing is left

After STOP:

```sh
docker volume ls                       # no capture / telemetry / database volume of the review
docker ps -a                           # no atg-* or shoplite-* containers
dir output\site                        # Windows: only the pages and exports/  (macOS/Linux: ls -R output/site)
```

After CLEAN, the `output` folder is gone and the three commands above show nothing from the review.

What we measured on the demo (two scans, 808 HTTP flows, 63 span batches):

| | Version 1.2 | Version 1.3 |
|---|---|---|
| Raw traffic on disk after STOP | 808 flows (669 KB) in a Docker volume, plus copies in `output/scan-input/` | none |
| Spans on disk after STOP | 108 batches (1.1 MB) in a Docker volume, plus copies | none |
| Database after STOP | an unnamed Docker volume with the full graph | none (it was in memory) |
| Phase 1, EUJF and analysis JSON after STOP | `output/raw/`, `output/runs/`, `output/site/scans/` | none |
| Review files left in `output/` after STOP (not counting the 18 experiment pages that ship with the code) | 37 | 14: six report pages and eight export files |

## Limits of this

- The pages and exports describe the company's APIs and their weaknesses, so they are confidential too. They stay on disk because they are the deliverable. Hand them over, then run CLEAN.
- If traffic keeps arriving while a scan reads the buffers, the newest lines stay in memory until the next scan or STOP. They are never written to disk either way.
- Each in-memory volume is capped at 1 GB. A busy system that is scanned rarely can fill it, and the sidecar then stops recording until the next scan clears it. On the demo one flow takes about 0.8 KB and one span batch about 11 KB, so 1 GB holds roughly a million flows. Scan more often on a busy system.
- Docker images (ShopLite and the ATG image) are not review data. They contain only code and are kept so the next start is fast.
- Versions before 1.3 also left an unnamed PostgreSQL volume after STOP. Docker gives it no project label, so the scripts cannot tell it apart from other projects' volumes. Delete it in Docker Desktop under Volumes (unnamed, "in use: no"), or with `docker volume prune` if you have no other unused volumes you want to keep.
