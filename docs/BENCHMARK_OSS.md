# Benchmark: ten open-source systems, ATG and eight other tools

This answers the professor's points 1 and 3: ten real open-source systems from different fields
instead of shops we generated, and ATG measured next to other tools on all ten, including where each
tool cannot run at all.

Numbers: `results/opensource/comparison.md` (Tables A-F) and `results/opensource/atg-v1.5/tables.md`.
Systems and ground truth: `opensource/README.md`. Commercial tools: `docs/TOOLS_COMPARISON.md`.

## Systems

| System | Field | Published by | Languages | ATG reads |
|---|---|---|---|---|
| Online Boutique | Retail | Google Cloud | Go, C#, Node.js, Python, Java | Kubernetes + Istio |
| Bank of Anthos | Banking | Google Cloud | Python, Java | Kubernetes |
| Stan's Robot Shop | Retail (robots) | Instana (IBM) | Node.js, Java, Python, PHP, Go | Compose + nginx |
| Acme Air | Airline | IBM | Java | Kubernetes + Ingress |
| Spring PetClinic Microservices | Veterinary | Spring community | Java | Compose + Spring Cloud Gateway |
| PiggyMetrics | Personal finance | A. Lukyanchikov | Java | Compose + Zuul |
| Lakeside Mutual | Insurance | Microservice API Patterns (OST) | Java, TypeScript | Kubernetes |
| FTGO | Food delivery | C. Richardson | Java | Kubernetes |
| DeathStarBench Hotel Reservation | Hotels | Cornell SAIL | Go | Kubernetes |
| Istio Bookinfo | Book reviews | Istio project | Python, Ruby, Java, Node.js | Kubernetes + Istio |

Nine fields (two of the ten are shops), eight languages, 65 services, 201 API operations. Three systems ship Docker Compose
instead of Kubernetes. Five gateway styles: nginx, Spring Cloud Gateway, Zuul, an Ingress controller,
and gateway routes written in Java code. Five systems have no gateway at all, so an edge service
faces the internet.

## Method

**Ground truth: 716 labels, written before the tools were scored.** Each label is a weakness category
on a service or an operation. 91 come from reading the code by hand (each with the source file); the
rest are derived by fixed rules from the deployment files, the call graph and the API documents
(`opensource/config_labels.py`, `opensource/build.py`). Categories:

- **API behaviour** (A1-A10): anonymous sensitive operations, BOLA, exposed admin and debug functions,
  calls between services without credentials, logins without rate limits, credentials in URLs, bulk
  data, third-party calls
- **Configuration** (C1-C10): root, privileged, limits, image tags, published outside the gateway, no
  network segmentation, secrets in files, entry without TLS, container hardening, service-account token
- **Inventory and visibility** (O1, O2): operations or services with no API document; services that send
  no traces

**Running systems.** The workspace could not download container images, so the services that run are
stand-ins with each system's real names, ports, operations, call graph and authentication checks. They
answer with masked values instead of personal data. Everything ATG reads besides traffic and traces is
the system's own: its Kubernetes or Compose files, gateway configuration and API documents, at the
pinned commit. `opensource/real/` runs seven of the systems on their real images on a laptop (see
"Real images" below).

**Tools.** ATG v1.5, run the way START runs it (`bench/run_opensource.py`), and eight free tools on the
same files (`bench/run_tools.py`): Checkov, Kubescape, kube-linter and Polaris on the Kubernetes files;
Spectral with the OWASP API ruleset on the API documents; Bandit, gosec and njsscan on the Python, Go
and Node.js source. Each tool's findings are mapped to the same categories and places
(`bench/run_tools.py` lists every mapping), then scored by `bench/oss_scoring.py`. A label counts as
found when the tool reports its category on the same service or operation.

## Results

**Table A (overall).** Labels found out of all 716, and precision (share of the tool's reports that
match a label):

| Tool | Runs on | Labels found | Configuration | API behaviour | Inventory | Precision | Time per system |
|---|---:|---:|---:|---:|---:|---:|---:|
| **ATG v1.5** | 10/10 | **466 (65%)** | 326/546 (60%) | **52/82 (63%)** | **88/88 (100%)** | 75% | 0.35 s* |
| Polaris | 7/10 | 331 (46%) | 331/546 (61%) | 0 | 0 | 95% | 0.13 s |
| Checkov | 7/10 | 262 (37%) | 262/546 (48%) | 0 | 0 | 74% | 2.3 s |
| Kubescape | 7/10 | 254 (35%) | 254/546 (47%) | 0 | 0 | 87% | 1.9 s |
| kube-linter | 7/10 | 164 (23%) | 164/546 (30%) | 0 | 0 | 89% | 0.04 s |
| Spectral (OWASP) | 3/10 | 14 (2%) | 4 | 10 | 0 | 37% | 1.4 s |
| Bandit | 4/10 | 1 | 1 | 0 | 0 | 20% | 0.47 s |
| gosec | 3/10 | 0 | 0 | 0 | 0 | – | 3.6 s |
| njsscan | 3/10 | 0 | 0 | 0 | 0 | – | 0.61 s |

Times are medians per system from one run of `BENCH-Windows.bat` / `bench.sh` on a 2-vCPU host; they
change a little from run to run. \* ATG's time is Phases 1-4 of one scan (0.2-0.9 s). A whole scan as
START runs it takes 7.2-8.1 s, most of it waiting for the sidecar and the Collector to go quiet before
reading them. The other tools' time is one run on the files.

What this shows:

1. **Only ATG finds API behaviour and inventory problems.** No scanner sees that an operation answers
   anonymous callers, that one service calls another without a token, that a login has no rate limit,
   or that 62 operations and services have no API document. Spectral comes closest, but only on the
   three systems that have an API document, and only for what the document says (A1 9 of 23).
2. **On deployment configuration ATG is level with the best Kubernetes scanner.** ATG finds 60% of the
   configuration labels, Polaris 61%. The difference is in what each checks. ATG has no checks for
   container hardening (C9) or service-account tokens (C10): 169 labels it cannot find. Polaris cannot
   read Docker Compose, so it misses three of the ten systems entirely. Polaris is more precise (95%
   against 75%) and faster.
3. **Coverage limits decide a lot.** Every Kubernetes scanner skipped the three Compose systems.
   Spectral needs an API document, which seven systems do not have. Each code scanner reads one
   language: Bandit 7 of the 65 services, gosec 13, njsscan 6. Together they read 26 (40%). The other
   39, written in Java, C#, Ruby or PHP (plus Robot Shop's nginx), had no free scanner here. Kubescape skipped FTGO's workloads
   because they use removed Kubernetes API versions. ATG ran on all ten because it watches the running
   system and reads whatever files exist.
4. **ATG plus one Kubernetes scanner is the best combination** (Table E). ATG and Checkov together find
   613 of the 716 labels (86%); ATG and Polaris 610 (85%). They overlap on 115-187 labels and each adds
   what the other lacks.
5. **The code scanners found almost nothing in these categories.** That is expected: their checks are for
   code flaws (injection, weak crypto, unsafe functions), which none of the labels describe. Their
   findings were not scored as wrong; they simply answer a different question.

**Per category (Table B).** ATG: C1 90/90, C4 71/71, C5 16/16, C6 109/109, O1 62/62, O2 26/26, A7 3/3,
A9 3/3, A5 21/29, A1 16/23, A6 4/6, C8 11/17, C7 10/16, C3 19/58 (it reports missing limits only on
internet-reachable services), A3 1/7, A4 2/7, A10 1/3.

**Operations (the API inventory).** ATG listed 189 of the 201 operations (94%) with 88% precision. The 27
extra entries come from three systems: Acme Air (15), where the Ingress controller is the gateway for five
services and ATG lists some operations under the controller as well; and FTGO (8), whose gateway routes
are written in Java code ATG does not read; and Bookinfo (4).

## What changed from v1.4 to v1.5, and why this needs care

ATG v1.4 was run on the ten systems first (`results/opensource/atg-v1.4/`). Reading its misses showed
gaps in ATG, not in the systems. Version 1.5 fixes them:

- a Kubernetes Service and its workload were counted as two services (Online Boutique, Bank of Anthos)
- with no gateway, the edge service was not treated as the front door
- Docker Compose files and Zuul gateway configs were not read at all (Robot Shop, PetClinic,
  PiggyMetrics: 0 configuration findings)
- Spring Cloud Gateway files with several profiles (`---`) failed to parse, which silently dropped all
  of PetClinic's deployment files
- the newer Spring Cloud Gateway route keys, plain-HTTP LoadBalancers, Istio Gateways and published
  Compose ports were not checked for TLS or exposure

| | v1.4 | v1.5 |
|---|---:|---:|
| Labels found | 337/716 (47%) | 466/716 (65%) |
| Precision | 66% | 75% |
| Operation precision | 79% | 88% |

**This is not a fair test of v1.5.** The fixes were made after looking at these ten systems, so the v1.5
numbers are better than what ATG would score on ten new systems. The v1.4 numbers are the fair ones for
"unseen systems". The fixes are general (Compose, Zuul, multi-profile YAML, Service/workload names) and
broke nothing: ShopLite still scores 472 → 13.5, the ten generated companies give the same results as
with v1.4, and the unit tests pass (68). One company, FoodDash, now has one extra finding: its Istio
Gateway serves plain HTTP. That is true, but it was not planted, so it counts against precision there.

## Real images

`opensource/real/` runs seven of the ten systems on their published images (Robot Shop, PetClinic,
Lakeside Mutual, Hotel Reservation, PiggyMetrics, Bookinfo, Online Boutique): `sh real.sh <id>` or
`REAL-Windows.bat <id>`. It writes `results/opensource/atg-real/<id>.json`, and
`python bench/run_opensource.py --score-only --tag real` scores those runs with the same ground truth.
**The real images could not be run where this was written** (no access to the image registries); the
script was tested end to end with Bookinfo's stand-ins in place of its images. The differences to expect (real services do not send their
internal calls through the sidecar, so ATG sees them only where the system sends traces) are listed in
`opensource/real/README.md`.

## Threats to validity

- **Stand-ins.** The running services imitate each system's API, call graph and authentication checks
  from reading its code. They do not run its business logic, and they answer with masked values, so data
  classification sees less than it would on the real system. The real-image kit is there to check this.
- **Who wrote the labels.** The hand labels were written by the team that wrote ATG's rules. The
  rule-derived configuration labels use the same kind of checks as the Kubernetes scanners, which
  favours those scanners. Both effects are known; neither is removed.
- **Mapping other tools' findings.** Each tool's check IDs were mapped to our categories by hand
  (`bench/run_tools.py`). A check we did not map counts as nothing, even if it is a real issue.
- **v1.5 was tuned on these systems** (see above).
- **Speed** was measured on one machine, with ATG including its fixed wait; compare orders of magnitude,
  not the decimals.
- **Commercial tools were not run** (cost and accounts); `docs/TOOLS_COMPARISON.md` compares them from
  their documentation only.
