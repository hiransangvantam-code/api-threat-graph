## Table 23. ATG vs OWASP ZAP on the same ShopLite build (vulnerable)

ZAP 2.16.1, default active scan policy, the OpenAPI documents ATG used (converted to 3.0.3), no login. Planted weaknesses as in Table 16: 40, of which 3 no ATG rule covers. 'Other real issues' are valid findings outside the planted list.

| Tool | Kind | Requests sent to the target | Time | Endpoints reached | Shadow endpoints found | Planted, endpoint level | Planted, service/config level | Planted, all | Other real issues |
|---|---|---|---|---|---|---|---|---|---|
| ATG (this tool) | passive | 18 (OpenAPI probes) | 0.17 s for Phases 1-4; 33.0 s per scan with the wait for the buffers to go quiet | 12/12 | 4/4 | 22/24 | 15/16 | 37/40 | 0 |
| ZAP, through the gateway | active (DAST) | 3,393 | 27.7 s | 8/12 | 0/4 | 0/24 | 0/16 | 0/40 | 1 |
| ZAP, inside the network | active (DAST) | 3,527 | 16.7 s | 8/12 | 0/4 | 0/24 | 0/16 | 0/40 | 1 |

## Table 24. Every alert type ZAP raised, and what it means

| Alert | Risk | CWE | Instances (gateway / internal) | Endpoints | Our reading | Does ATG report it? |
|---|---|---|---|---|---|---|
| X-Content-Type-Options Header Missing | Low | 693 | 1 / 1 | POST /charge (payment-service) | real, minor hardening issue | no: ATG has no response-header rule |
| Authentication Request Identified | Informational | – | 1 / 1 | POST /auth/login (user-service) | not a weakness: ZAP noting a login endpoint | – |
| Information Disclosure - Sensitive Information in URL | Informational | 598 | 1 / 1 | GET /orders (order-service) | not a real issue here: user_id is not secret. The actual weakness on this endpoint is BOLA through that parameter, which ZAP does not report | no, and ATG misses that BOLA too (one of the 3 uncovered weaknesses) |
| User Agent Fuzzer | Informational | – | 12 / 12 | POST /charge (payment-service) | not a weakness: ZAP records how responses vary by user agent | – |

With the services' OpenAPI 3.1 documents as served, ZAP reached 4/12 endpoints through the gateway and 4/12 inside, because it left every path and query parameter empty. Planted weaknesses found: 0 and 0.
