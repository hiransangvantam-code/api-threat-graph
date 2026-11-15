# ATG on ten open-source systems (v1.5)

Produced by `bench/run_opensource.py`. ATG read each system's real deployment files and API
documents; the running services were stand-ins answering the same operations (see
`opensource/README.md`). Ground truth: `opensource/<id>/ground-truth.json`.

| System | Field | Languages | Operations found | Operation precision | Configuration labels found | API behaviour labels found | Inventory and visibility labels found | Findings that match a label | Scan (s) |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| Online Boutique | Retail (e-commerce) | Go, C#, Node.js, Python, Java | 25/26 | 100% | 24/36 | 9/9 | 10/10 | 73/96 (76%) | 7.9 |
| Bank of Anthos | Banking | Python, Java | 15/17 | 100% | 13/35 | 3/3 | 6/6 | 37/45 (82%) | 8.0 |
| Stan's Robot Shop | Retail (robot store) | Node.js, Java, Python, PHP, Go | 29/30 | 100% | 26/49 | 4/15 | 12/12 | 100/116 (86%) | 8.0 |
| Acme Air | Airline | Java | 20/22 | 57% | 39/58 | 4/11 | 10/10 | 92/141 (65%) | 7.9 |
| Spring PetClinic Microservices | Veterinary clinic | Java | 15/16 | 100% | 42/53 | 6/8 | 6/6 | 69/85 (81%) | 7.9 |
| PiggyMetrics | Personal finance | Java | 13/13 | 100% | 51/74 | 1/4 | 10/10 | 88/111 (79%) | 7.3 |
| Lakeside Mutual | Insurance | Java, TypeScript | 38/38 | 100% | 37/63 | 9/11 | 6/6 | 90/118 (76%) | 7.3 |
| FTGO | Food delivery | Java | 9/14 | 53% | 34/68 | 4/6 | 8/8 | 60/97 (62%) | 7.5 |
| DeathStarBench Hotel Reservation | Hotel booking | Go | 12/12 | 100% | 51/89 | 9/10 | 8/8 | 81/113 (72%) | 8.1 |
| Istio Bookinfo | Book reviews | Python, Ruby, Java, Node.js | 13/13 | 76% | 9/21 | 3/5 | 12/12 | 28/32 (88%) | 7.2 |
| **All ten** | | | 189/201 (94%) | 88% | 326/546 (60%) | 52/82 (63%) | 88/88 (100%) | 718/954 (75%) | 7.7 avg |

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
| C1 | may run as root | 90 | 90 (100%) |
| C3 | no resource limits | 58 | 19 (33%) |
| C4 | mutable image tag | 71 | 71 (100%) |
| C5 | published outside the gateway | 16 | 16 (100%) |
| C6 | no network segmentation | 109 | 109 (100%) |
| C7 | secret in deployment files | 16 | 10 (62%) |
| C8 | public entry without TLS | 17 | 11 (65%) |
| C9 | missing container hardening | 97 | 0 (0%) |
| C10 | service account token mounted | 72 | 0 (0%) |
| O1 | no API document | 62 | 62 (100%) |
| O2 | not traced | 26 | 26 (100%) |
