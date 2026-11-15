# ATG on ten open-source systems (v1.4)

Produced by `bench/run_opensource.py`. ATG read each system's real deployment files and API
documents; the running services were stand-ins answering the same operations (see
`opensource/README.md`). Ground truth: `opensource/<id>/ground-truth.json`.

| System | Field | Languages | Operations found | Operation precision | Configuration labels found | API behaviour labels found | Inventory and visibility labels found | Findings that match a label | Scan (s) |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| Online Boutique | Retail (e-commerce) | Go, C#, Node.js, Python, Java | 25/26 | 100% | 23/36 | 9/9 | 10/10 | 72/107 (67%) | 7.6 |
| Bank of Anthos | Banking | Python, Java | 15/17 | 100% | 12/35 | 3/3 | 6/6 | 36/53 (68%) | 7.2 |
| Stan's Robot Shop | Retail (robot store) | Node.js, Java, Python, PHP, Go | 29/30 | 100% | 0/49 | 4/15 | 12/12 | 68/73 (93%) | 7.6 |
| Acme Air | Airline | Java | 20/22 | 57% | 34/58 | 4/11 | 10/10 | 88/137 (64%) | 7.2 |
| Spring PetClinic Microservices | Veterinary clinic | Java | 15/16 | 54% | 0/53 | 6/8 | 6/6 | 34/83 (41%) | 7.2 |
| PiggyMetrics | Personal finance | Java | 13/13 | 59% | 0/74 | 1/4 | 10/10 | 32/61 (52%) | 7.4 |
| Lakeside Mutual | Insurance | Java, TypeScript | 38/38 | 100% | 35/63 | 9/11 | 6/6 | 88/110 (80%) | 7.3 |
| FTGO | Food delivery | Java | 9/14 | 53% | 34/68 | 4/6 | 8/8 | 60/97 (62%) | 7.2 |
| DeathStarBench Hotel Reservation | Hotel booking | Go | 12/12 | 100% | 51/89 | 9/10 | 8/8 | 81/117 (69%) | 7.4 |
| Istio Bookinfo | Book reviews | Python, Ruby, Java, Node.js | 13/13 | 76% | 8/21 | 3/5 | 12/12 | 27/45 (60%) | 7.1 |
| **All ten** | | | 189/201 (94%) | 79% | 197/546 (36%) | 52/82 (63%) | 88/88 (100%) | 586/883 (66%) | 7.3 avg |

## By category

| Category | Meaning | Labels | Found by ATG |
|---|---|---:|---:|
| A1 | no authentication on a sensitive operation | 23 | 16 (70%) |
| A2 | broken object level authorization | 1 | 1 (100%) |
| A3 | admin function exposed | 7 | 1 (14%) |
| A4 | debug or diagnostic endpoint exposed | 7 | 2 (29%) |
| A5 | service-to-service call without credentials | 29 | 21 (72%) |
| A6 | login without rate limit | 6 | 4 (67%) |
| A7 | credential in the URL | 3 | 3 (100%) |
| A9 | bulk sensitive data | 3 | 3 (100%) |
| A10 | third-party API use | 3 | 1 (33%) |
| C1 | may run as root | 90 | 53 (59%) |
| C3 | no resource limits | 58 | 13 (22%) |
| C4 | mutable image tag | 71 | 49 (69%) |
| C5 | published outside the gateway | 16 | 0 (0%) |
| C6 | no network segmentation | 109 | 72 (66%) |
| C7 | secret in deployment files | 16 | 10 (62%) |
| C8 | public entry without TLS | 17 | 0 (0%) |
| C9 | missing container hardening | 97 | 0 (0%) |
| C10 | service account token mounted | 72 | 0 (0%) |
| O1 | no API document | 62 | 62 (100%) |
| O2 | not traced | 26 | 26 (100%) |
