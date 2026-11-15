# The risk and hardening report ("What to fix, in order")

The professor's fourth point: the output should not stop at percentages. It should say which risks to
fix, how to fix and harden them, and how accurate and fast the review was. Every scan now writes a
fourth page next to the dashboard and the threat graph:

- `output/site/hardening-<scan>.html` (linked as "What to fix" from the home page, the dashboard and the
  threat graph)
- the same content as Markdown in `output/site/exports/<scan>/hardening.md`, for a ticket or an email

Code: `atg/hardening.py` (`build_hardening`), called by `docker/pages.py` and `atg/export.py`.
Tests: `tests/test_hardening.py`.

## What is on the page

1. **Risk after each fix.** The total attack-path risk now, and after each fix of the remediation
   planner, in order. The planner picks the fix that removes the most attack-path risk first
   (`atg/analysis.py`). The page says how many fixes remove 70% and 90% of the risk. On ShopLite: 472
   now, 13 fixes remove 70%, 20 remove 90%.
2. **Fix plan.** One entry per fix, most risk removed first, then every remaining finding by score. For
   each finding:
   - **what and where**: the rule, the endpoint or service, and the evidence (for example "returned
     2xx to 21 requests without a token")
   - **why it matters**: likelihood × impact and the reasons the score went up (reachable from the
     internet, anonymous success seen on the public path, ...)
   - **the fix, for this system's own technology.** Gateway fixes are written for the gateway the system
     uses: Kong, nginx, Spring Cloud Gateway, Istio, Zuul or a route table. NetworkPolicies allow exactly
     the callers seen in the traces. Kubernetes fixes come as `securityContext` / `resources` / `tls`
     blocks. Code fixes name the finding's own method and path, in the service's framework when the
     review can tell what it is: Spring Security when the service serves `/v3/api-docs` or `/actuator`,
     FastAPI for `/openapi.json`, Quarkus for `/q/openapi`, Express or Go from the image name.
     Otherwise they come as pseudocode labelled as such.
   - **how to check the fix**: a concrete test, for example "call POST /charge with no Authorization
     header: expect 401" or "a pod not on the allow list must time out"
   - **references**: OWASP API Top 10 2023, CWE, MITRE ATT&CK, NIST SP
3. **Hardening baseline.** One row per service: authentication enforced, owner checks seen, not root,
   resource limits, pinned image, NetworkPolicy, mTLS, API document, traced. Each cell says yes, no, or
   "cannot tell" (no manifest, nothing to check).
4. **Accuracy, speed and what to run next.**
   - **Accuracy**: how many findings are high and how many are medium confidence. Medium findings are
     design signals for a person to confirm, such as "possible BOLA", which a test with a second account
     settles.
   - **Speed**: the time of each phase of this scan.
   - **What a passive review cannot cover**: injection, headers, business-flow abuse, secret strength.
     For those it says which active scanner to run on the inventory.

The accuracy and speed measured over many systems are in `docs/BENCHMARK_OSS.md` (ten open-source
systems), `companies/README.md` (ten generated companies) and `results/tables.md` (ShopLite, Train
Ticket, crAPI).
