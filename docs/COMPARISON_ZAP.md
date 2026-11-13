# ATG compared with OWASP ZAP

The review asked how ATG compares with other people's tools on speed and effectiveness. We compared it with OWASP ZAP, the most widely used free API security scanner, on the same running ShopLite build. Commercial API security platforms (Akto, Salt, 42Crunch, Burp Suite Pro) could not be run for this project.

Numbers: `results/zap/tables.md` (Tables 23 and 24). Harness: `bench/compare_zap.py`. Raw results: `results/zap/zap.json`.

## Setup

- **Target:** ShopLite as shipped (vulnerable build), started by the company Docker exactly as in the demo.
- **ATG:** the normal demo flow. The customers' traffic runs through the sidecar, then one scan (Phases 1-4).
- **ZAP 2.16.1:** daemon mode, default active-scan policy, all release rules. It gets the same OpenAPI documents ATG used (user-service and order-service from their live `/openapi.json`, payment-service from the spec file) and network access to the services. Two runs:
  - *through the gateway:* the documents mapped onto the public routes (`/api/...`), which is how an outside tester would scan
  - *inside the network:* each service scanned directly, the position ATG's sidecar has
- **No login for ZAP.** This project does not create credentials or tokens in its test harness, so ZAP scans as an anonymous client, which is also the default of ZAP's API scan.
- **OpenAPI version.** The services publish OpenAPI 3.1. ZAP's OpenAPI add-on left every path and query parameter empty with those documents (`/users//addresses`, `?user_id=`) and reached only 4 of 12 endpoints. The harness therefore converts each document to 3.0.3 first. These documents use nothing that 3.0 cannot express, and with the converted documents ZAP reaches all 8 documented endpoints.
- **Scoring:** the same planted list as Table 16 (40 weaknesses, 3 of which no ATG rule covers). A ZAP alert counts when it is on the right endpoint and its CWE belongs to the matching family (access control, information exposure, brute force, resource consumption). Every ZAP alert type was also read by hand (Table 24).

## Results

| | ATG | ZAP through the gateway | ZAP inside the network |
|---|---|---|---|
| How it works | passive: reads traffic, specs, manifests, traces | active: sends attack requests | active |
| Requests sent to ShopLite | 18 (OpenAPI probes) | 3,393 | 3,527 |
| Time | 0.17 s for Phases 1-4 (33 s per scan, most of it waiting for the buffers to go quiet) | 27.7 s | 16.7 s |
| Endpoints reached | 12 of 12 | 8 of 12 | 8 of 12 |
| Shadow endpoints found | 4 of 4 | 0 | 0 |
| Planted weaknesses on an endpoint | 22 of 24 | 0 | 0 |
| Planted weaknesses in the deployment (manifests, gateway config) | 15 of 16 | 0 | 0 |
| Planted weaknesses, all | 37 of 40 | 0 of 40 | 0 of 40 |
| Other real issues | 0 | 1 (missing `X-Content-Type-Options` on `POST /charge`) | 1 (same) |

ZAP's other three alert types are informational and not weaknesses: a login endpoint was identified, user-agent fuzzing results, and "sensitive information in URL" for `user_id` in `GET /orders?user_id=`. The real problem on that last endpoint is broken object level authorization through the query parameter. ZAP does not report it, and ATG misses it too (it is one of the three weaknesses no ATG rule covers).

## What this shows, and what it does not

- **The two tools look for different things.** ShopLite's weaknesses are design and deployment problems: endpoints that answer anonymous callers, admin functions open to customers, undocumented endpoints, missing network policies, secrets in plaintext. ZAP has no idea which endpoint should require a login, never sees the manifests, and only tests the endpoints in the documents. ATG never sends a payload, so it cannot find injection or header problems, which is what ZAP is built for. ShopLite has no injection flaws planted, so ZAP's strongest checks had nothing to find here. This result does not say ZAP is a weak tool.
- **Speed.** On ShopLite, ZAP finished in 17-28 s, and ATG's analysis took under a second once the traffic was there. More important than the seconds is the load. ZAP sent about 3,400 requests, including the DELETE and POST operations from the documents, which change data on the target. ATG sent 18 read-only requests. That is why ATG can run next to a production system and ZAP should not.
- **Only one system and one other tool.** A fair test of ZAP's strengths needs a target with injection flaws (crAPI, for example, running for real). An authenticated ZAP scan would reach more endpoints, but it needs test accounts from the company.
- **The planted list was written by the same team as ATG's rules** (Table 16). That favours ATG. The crAPI comparison in Table 15 uses OWASP's own list instead.

The two are complements. ATG reviews the design and the deployment without touching the system. An active scanner tests the endpoints ATG has found, for the payload-level flaws ATG cannot see. ATG's inventory (shadow endpoints included) could serve as the scanner's target list, since ZAP missed all four shadow endpoints because they are in no document.
