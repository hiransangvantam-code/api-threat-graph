# ATG and eight free tools on ten open-source systems (ATG v1.5)

Produced by `bench/compare_tools.py` from the saved runs in `results/opensource/`. Every tool is scored against the same ground truth (`opensource/<id>/ground-truth.json`): a label counts as found when the tool reports the same weakness category on the same service or endpoint. Method and limits: `docs/BENCHMARK_OSS.md`.

## Table A. Overall

*Labels found* counts every label in all ten systems, so a tool that cannot run on a system scores 0 there. *In reach* counts only the labels in categories the tool can report at all, on the systems it ran on. *Precision* is the share of the tool's (category, place) reports that match a label.

| Tool | Runs on | Labels found (all) | Configuration | API behaviour | Inventory and visibility | In reach | Precision | Time per system (median) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **ATG** | 10/10 | 466/716 (65%) | 326/546 (60%) | 52/82 (63%) | 88/88 (100%) | 466/547 (85%) | 718/954 (75%) | 7.9 s |
| Checkov | 7/10 | 262/716 (37%) | 262/546 (48%) | 0/82 (0%) | 0/88 (0%) | 262/354 (74%) | 262/355 (74%) | 2.7 s |
| Kubescape | 7/10 | 254/716 (35%) | 254/546 (47%) | 0/82 (0%) | 0/88 (0%) | 254/370 (69%) | 254/291 (87%) | 6.2 s |
| kube-linter | 7/10 | 164/716 (23%) | 164/546 (30%) | 0/82 (0%) | 0/88 (0%) | 164/282 (58%) | 164/184 (89%) | 0.04 s |
| Polaris | 7/10 | 331/716 (46%) | 331/546 (61%) | 0/82 (0%) | 0/88 (0%) | 331/338 (98%) | 331/350 (95%) | 0.2 s |
| Spectral (OWASP) | 3/10 | 14/716 (2%) | 4/546 (1%) | 10/82 (12%) | 0/88 (0%) | 14/22 (64%) | 14/38 (37%) | 1.7 s |
| Bandit | 4/10 | 1/716 (0%) | 1/546 (0%) | 0/82 (0%) | 0/88 (0%) | 1/5 (20%) | 1/5 (20%) | 0.4 s |
| gosec | 3/10 | 0/716 (0%) | 0/546 (0%) | 0/82 (0%) | 0/88 (0%) | 0/0 (–) | 0/0 (–) | 4.3 s |
| njsscan | 3/10 | 0/716 (0%) | 0/546 (0%) | 0/82 (0%) | 0/88 (0%) | 0/0 (–) | 0/0 (–) | 0.8 s |

ATG's time is the whole scan as START runs it (about 7 s of it is waiting for the sidecar and the Collector to go quiet); the analysis itself (Phases 1-4) takes well under a second. The other tools' time is one run of the tool on the system's files.

## Table B. Found, by weakness category

| Category | Meaning | Labels | ATG | Checkov | Kubescape | kube-linter | Polaris | Spectral (OWASP) | Bandit | gosec | njsscan |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| A1 | no authentication on a sensitive operation | 23 | 16 | · | · | · | · | 9 | · | · | · |
| A2 | broken object level authorization | 1 | 1 | · | · | · | · | · | · | · | · |
| A3 | admin function exposed | 7 | 1 | · | · | · | · | · | · | · | · |
| A4 | debug or diagnostic endpoint exposed | 7 | 2 | · | · | · | · | · | · | · | · |
| A5 | service-to-service call without credentials | 29 | 21 | · | · | · | · | · | · | · | · |
| A6 | login without rate limit | 6 | 4 | · | · | · | · | 1 | · | · | · |
| A7 | credential in the URL | 3 | 3 | · | · | · | · | · | · | · | · |
| A9 | bulk sensitive data | 3 | 3 | · | · | · | · | · | · | · | · |
| A10 | third-party API use | 3 | 1 | · | · | · | · | · | · | · | · |
| C1 | may run as root | 90 | 90 | 53 | 43 | 47 | 53 | · | · | · | · |
| C3 | no resource limits | 58 | 19 | 32 | 22 | 26 | 32 | · | · | · | · |
| C4 | mutable image tag | 71 | 71 | 49 | 5 | 43 | 49 | · | · | · | · |
| C5 | published outside the gateway | 16 | 16 | · | 0 | · | · | · | · | · | · |
| C6 | no network segmentation | 109 | 109 | 0 | 62 | 0 | 72 | · | · | · | · |
| C7 | secret in deployment files | 16 | 10 | 3 | 10 | 1 | · | · | 1 | 0 | 0 |
| C8 | public entry without TLS | 17 | 11 | · | 0 | · | · | 4 | · | · | · |
| C9 | missing container hardening | 97 | · | 53 | 50 | 47 | 53 | · | · | · | · |
| C10 | service account token mounted | 72 | · | 72 | 62 | · | 72 | · | · | · | · |
| O1 | no API document | 62 | 62 | · | · | · | · | · | · | · | · |
| O2 | not traced | 26 | 26 | · | · | · | · | · | · | · | · |

· = the tool has no check for this category. ATG reports missing resource limits (C3) only for services reachable from the internet, where they matter for API4 (resource consumption); the scanners report every container, which is why they find more C3 labels.

## Table C. Per system

Labels found (all groups) / labels. n/a = the tool cannot run on that system.

| System | Labels | ATG | Checkov | Kubescape | kube-linter | Polaris | Spectral (OWASP) | Bandit | gosec | njsscan |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| online-boutique | 55 | 43 | 23 | 24 | 11 | 35 | n/a | 0 | 0 | 0 |
| bank-of-anthos | 44 | 22 | 15 | 33 | 4 | 22 | n/a | 1 | n/a | n/a |
| robot-shop | 76 | 42 | n/a | n/a | n/a | n/a | n/a | 0 | 0 | 0 |
| acme-air | 79 | 53 | 40 | 50 | 32 | 48 | n/a | n/a | n/a | n/a |
| petclinic | 67 | 54 | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| piggymetrics | 88 | 62 | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| lakeside-mutual | 80 | 52 | 45 | 45 | 36 | 54 | 11 | n/a | n/a | n/a |
| ftgo | 82 | 46 | 53 | 6 | 18 | 63 | 2 | n/a | n/a | n/a |
| hotel-reservation | 107 | 68 | 70 | 76 | 51 | 89 | n/a | n/a | 0 | n/a |
| bookinfo | 38 | 24 | 16 | 20 | 12 | 20 | 1 | 0 | n/a | 0 |

## Table D. Where each tool stops

| Tool | Needs | Systems it could not run on |
|---|---|---|
| ATG | a running test deployment (any language), plus whatever files exist | 0: none |
| Checkov | Kubernetes manifests | 3: robot-shop, petclinic, piggymetrics (Checkov has no Docker Compose checks) |
| Kubescape | Kubernetes manifests (current API versions) | 3: robot-shop, petclinic, piggymetrics (reads Kubernetes manifests only (this system ships Docker Compose)) |
| kube-linter | Kubernetes manifests | 3: robot-shop, petclinic, piggymetrics (reads Kubernetes manifests only) |
| Polaris | Kubernetes manifests | 3: robot-shop, petclinic, piggymetrics (reads Kubernetes manifests only) |
| Spectral (OWASP) | an OpenAPI document | 7: online-boutique, bank-of-anthos, robot-shop, acme-air, petclinic, piggymetrics, hotel-reservation (no API document to lint) |
| Bandit | Python source | 6: acme-air, petclinic, piggymetrics, lakeside-mutual, ftgo, hotel-reservation (no Python service) |
| gosec | Go source | 7: bank-of-anthos, acme-air, petclinic, piggymetrics, lakeside-mutual, ftgo, bookinfo (no Go service) |
| njsscan | Node.js source | 7: bank-of-anthos, acme-air, petclinic, piggymetrics, lakeside-mutual, ftgo, hotel-reservation (no Node.js service) |

Kubescape also ran on FTGO but found 6 of 82 labels: FTGO declares its Deployments and StatefulSets with API versions Kubernetes has removed (`extensions/v1beta1`, `apps/v1beta1`), and Kubescape skipped them, scanning only the Services, the Secret and the Job. The other scanners read them.

Single-language code scanners: services each one could read, per system.

| System | Services | Bandit (Python) | gosec (Go) | njsscan (Node.js) |
|---|---:|---:|---:|---:|
| online-boutique | 10 | 2 | 4 | 2 |
| bank-of-anthos | 6 | 3 | 0 | 0 |
| robot-shop | 8 | 1 | 1 | 3 |
| acme-air | 5 | 0 | 0 | 0 |
| petclinic | 7 | 0 | 0 | 0 |
| piggymetrics | 6 | 0 | 0 | 0 |
| lakeside-mutual | 5 | 0 | 0 | 0 |
| ftgo | 6 | 0 | 0 | 0 |
| hotel-reservation | 8 | 0 | 8 | 0 |
| bookinfo | 4 | 1 | 0 | 1 |
| **All** | 65 | 7 (11%) | 13 (20%) | 6 (9%) |

Together the three code scanners read 26 of 65 services (40%); the Java, C#, Ruby and PHP services have no free scanner here. ATG does not read source code, so it works the same for every language.

## Table E. ATG together with a Kubernetes scanner

Labels found by each tool, by both, and by either. The scanners add the container-hardening checks ATG does not have (C9, C10); ATG adds the API, inventory and Compose findings they cannot make.

| Pair | ATG | Other tool | Both | Either |
|---|---:|---:|---:|---:|
| ATG + Polaris | 466 | 331 | 187 | 610/716 (85%) |
| ATG + Kubescape | 466 | 254 | 130 | 590/716 (82%) |
| ATG + Checkov | 466 | 262 | 115 | 613/716 (86%) |

## Table F. ATG v1.4 and v1.5 on the same systems

Version 1.5 was made after reading the misses of version 1.4 on these systems (see `docs/BENCHMARK_OSS.md`), so this table shows the fixes worked, not how ATG does on unseen systems.

| System | Labels | Found v1.4 | Found v1.5 | Precision v1.4 | Precision v1.5 |
|---|---:|---:|---:|---:|---:|
| online-boutique | 55 | 42 | 43 | 67% | 76% |
| bank-of-anthos | 44 | 21 | 22 | 68% | 82% |
| robot-shop | 76 | 16 | 42 | 93% | 86% |
| acme-air | 79 | 48 | 53 | 64% | 65% |
| petclinic | 67 | 12 | 54 | 41% | 81% |
| piggymetrics | 88 | 11 | 62 | 52% | 79% |
| lakeside-mutual | 80 | 50 | 52 | 80% | 76% |
| ftgo | 82 | 46 | 46 | 62% | 62% |
| hotel-reservation | 107 | 68 | 68 | 69% | 72% |
| bookinfo | 38 | 23 | 24 | 60% | 88% |
| **All** | 716 | 337 (47%) | 466 (65%) | 66% | 75% |
