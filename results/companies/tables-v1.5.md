# Flexibility test: ten companies (v1.5)

Produced by `bench/run_companies.py`. Each company was started in its own Docker, ATG joined its
network, the company's users sent their requests (seeded), and one scan ran. Ground truth is
`companies/<id>/ground-truth.json`, written from the company definition before any scan.

## Table 25. Results per company

| Company | Industry | Services in | Gateway | Endpoints found (recall) | Endpoint precision | Planted found | Planted found, passive-visible | Findings that are planted | Negative controls flagged | Scan (s) |
|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| PayNow | Fintech (mobile wallet) | go | kong | 11/11 (100%) | 100% | 6/6 | 6/6 | 6/7 (86%) | 0/2 | 7.6 |
| CareLink | Hospital (patient portal) | python | nginx | 12/12 (100%) | 100% | 8/8 | 8/8 | 8/8 (100%) | 0/2 | 7.4 |
| SkyFly | Airline (booking and check-in) | node | spring-cloud-gateway | 12/12 (100%) | 100% | 7/7 | 7/7 | 7/7 (100%) | 0/3 | 7.6 |
| FleetGo | Logistics (parcel delivery) | go | istio | 11/11 (100%) | 100% | 5/5 | 5/5 | 5/5 (100%) | 0/3 | 7.3 |
| LearnHub | Education (online learning) | node | configmap | 13/13 (100%) | 100% | 5/6 | 5/5 | 5/5 (100%) | 0/2 | 7.4 |
| StreamBox | Media (video streaming) | python | kong | 12/12 (100%) | 100% | 6/6 | 6/6 | 6/6 (100%) | 0/3 | 7.8 |
| CityGov | Government (city e-services) | go | nginx | 10/10 (100%) | 100% | 5/5 | 5/5 | 5/5 (100%) | 0/2 | 7.1 |
| FoodDash | Food delivery | node | istio | 11/11 (100%) | 100% | 5/5 | 5/5 | 5/6 (83%) | 0/2 | 7.5 |
| InsureCo | Insurance (motor claims) | python | spring-cloud-gateway | 10/10 (100%) | 100% | 4/6 | 4/5 | 4/4 (100%) | 0/2 | 7.7 |
| TeleMax | Telecom (mobile operator) | go | spring-cloud-gateway | 18/18 (100%) | 100% | 11/11 | 11/11 | 11/11 (100%) | 0/2 | 7.4 |
| **All ten** | | | | 120/120 (100%) | 100% | 62/65 (95%) | 62/63 (98%) | 62/64 (97%) | 0/23 | 7.5 avg |

"Passive-visible" leaves out the planted weaknesses marked in advance as outside what a passive
review can see (`expect_miss` in the company definition). A negative control is something that
looks like a weakness but is not one; a finding there is a false alarm by construction.

## Table 26. Planted weaknesses by rule

| Rule | Planted | Found |
|---|---:|---:|
| API1 | 5 | 5 |
| API10 | 3 | 3 |
| API3 | 1 | 1 |
| API4 | 2 | 2 |
| API5 | 4 | 2 |
| API7 | 2 | 1 |
| API8-DEBUG | 1 | 1 |
| API8-NETPOL | 2 | 2 |
| API8-NODEPORT | 2 | 2 |
| API8-PRIV | 1 | 1 |
| API8-ROOT | 2 | 2 |
| API8-TAG | 3 | 3 |
| API9-NOSPEC | 3 | 3 |
| API9-SHADOW | 7 | 7 |
| API9-ZOMBIE | 2 | 2 |
| LT-01 | 3 | 3 |
| LT-02 | 2 | 2 |
| LT-03 | 2 | 2 |
| LT-04 | 4 | 4 |
| TS-01 | 7 | 7 |
| TS-02 | 2 | 2 |
| TS-05 | 1 | 1 |
| TS-06 | 1 | 1 |
| TS-07 | 1 | 1 |
| TS-08 | 2 | 2 |

## Planted weaknesses not found

| Company | Rule | Where | Known in advance to be out of reach |
|---|---|---|---|
| LearnHub | API5 | `GET /admin/users/export` | The role check is missing, but anonymous callers still get 401; passive traffic cannot tell a student from staff. |
| InsureCo | API5 | `GET /reports/claims-export` |  |
| InsureCo | API7 | `POST /claims` | The field is called photo_url, a name the SSRF rule does not know. |

## Negative controls that were flagged (false alarms)

| Company | Rule | Where | Why it is not a weakness |
|---|---|---|---|
| - | - | - | - |
