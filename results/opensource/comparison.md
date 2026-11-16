# ATG and eight free tools on ten open-source systems (ATG laptop)

Produced by `bench/compare_tools.py` from the saved runs in `results/opensource/`. Every tool is scored against the same ground truth (`opensource/<id>/ground-truth.json`): a label counts as found when the tool reports the same weakness category on the same service or endpoint. Method and limits: `docs/BENCHMARK_OSS.md`. The sections follow the five questions of the evaluation: speed, computing resources, accuracy, systems covered and language limits.

## The tools compared

How each tool works, in its own words where it describes itself (the package description or `--help` of the version installed by `bench/tools.Dockerfile` and `bench/tools_fetch.py`), with what it is good at and what it cannot see in this benchmark.

| Tool (version, maker) | Kind | What it reads | How it works | Checks in this version | Good at | Cannot see |
|---|---|---|---|---|---|---|
| **ATG** (this project) | design review of a running test deployment | traffic through its sidecar, traces, the services' API documents, Kubernetes, Docker Compose and gateway files | merges the four sources into one API inventory, applies 27 rules, builds a threat graph and ranks attack paths | 27 rules | API behaviour and inventory, works for any language and both deployment formats | source code; container hardening and service-account checks (no rule); anything not in HTTP traffic |
| Checkov 3.4.5 (Bridgecrew) | infrastructure-as-code scanner ("Infrastructure as code static analysis") | Kubernetes files, secrets in files, API documents; also Terraform, Helm, Dockerfiles and more | evaluates each policy on every resource of the parsed files ("graph-based scanning") | 119 Kubernetes checks, 18 secret detectors, 21 OpenAPI checks | many file formats, secrets | Docker Compose; the running API; it needs up to about 1 GB of memory |
| Kubescape 3.0.18 (ARMO) | Kubernetes posture scanner ("a tool for testing Kubernetes security posture") | Kubernetes YAML files or a live cluster | evaluates controls from its control library on each resource | 290 controls in the downloaded library | broad Kubernetes controls (RBAC, hardening, network policy) | Docker Compose; workloads with removed API versions (it skipped FTGO's) |
| kube-linter 0.7.1 (StackRox) | Kubernetes linter ("Lint Kubernetes YAML files and Helm charts") | Kubernetes YAML files | runs each built-in check on every object | 57 built-in checks | fastest and smallest | Docker Compose; fewer checks |
| Polaris 9.6.1 (Fairwinds) | Kubernetes best-practice checker ("Validation of best practices in your Kubernetes clusters") | Kubernetes YAML files (audit mode) or a cluster | checks each workload and its containers against its policy | 32 checks run by default | most precise of all | Docker Compose |
| Spectral 6.17.1 + OWASP ruleset 2.0.1 (Stoplight) | API document linter | OpenAPI documents | runs rules on the JSON or YAML of the document; the OWASP ruleset follows the OWASP API Security Top 10 2023 | 28 OWASP rules | missing security schemes, error responses, rate-limit responses in the document | anything not written in a document: in its own words, "As OpenAPI is only describing the surface level of the API it cannot see what is happening in your code"; 7 systems have no document |
| Bandit 1.9.4 (PyCQA) | Python code scanner ("Security oriented static analyser for python code") | Python source | "processes each file, builds an AST from it, and runs appropriate plugins against the AST nodes" | 75 tests | code mistakes such as hard-coded passwords or requests without a timeout | other languages; deployment and API design |
| gosec 2.21.4 (securego) | Go code scanner ("analyzes Go source code to look for common programming mistakes that can lead to security problems") | Go source | loads each Go package and runs its rules | 41 rules | Go code mistakes such as unchecked errors or weak random numbers | other languages; it must load the packages, so it is the slowest on large Go systems |
| njsscan 1.0.1 (Ajin Abraham) | Node.js code scanner ("a SAST tool that can find insecure code patterns in your Node.js applications") | Node.js source | pattern matching with libsast and semgrep | 124 rules | insecure Node.js code patterns | other languages |

## 1. Speed

### Time to review one system

Slowest first.

| Tool | Systems it can read | Median | Fastest | Slowest |
|---|---:|---:|---:|---:|
| **ATG**, whole scan (with the wait for the capture buffers) | 10/10 | 7.7 s | 7.0 s | 8.3 s |
| gosec | 3/10 | 4.1 s | 0.21 s | 34.1 s |
| Checkov | 7/10 | 3.8 s | 2.7 s | 12.7 s |
| Kubescape | 7/10 | 1.9 s | 1.7 s | 2.1 s |
| Spectral (OWASP) | 3/10 | 1.8 s | 0.83 s | 3.5 s |
| njsscan | 3/10 | 0.96 s | 0.27 s | 1.1 s |
| Bandit | 4/10 | 0.56 s | 0.25 s | 1.6 s |
| **ATG** (Phases 1-4) | 10/10 | 0.44 s | 0.23 s | 0.88 s |
| Polaris | 7/10 | 0.14 s | 0.10 s | 0.23 s |
| kube-linter | 7/10 | 0.04 s | 0.04 s | 0.06 s |

ATG's time is Phases 1-4 of one scan (reading all four sources, normalising, analysing and writing the pages), measured inside the ATG container; it does not include starting the system or its users. The whole scan adds the wait until the sidecar and the Collector are quiet. The other tools' time is one run of the tool on the system's files (the first run of each tool is slower: it loads its rules). 

## 2. Computing resources

How much of the computer each tool uses to review one system. CPU time is the processor time all of the tool's processes used (user time: running the tool's own code; system time: the operating system working for it, such as reading files). *Cores used* is CPU time divided by the time the run took: 1.00 means one processor core busy for the whole run. Memory is the resident memory of all its processes, at its highest and on average over the run. Data read and written counts the bytes its processes read and wrote (files, pipes and network sockets alike), so it shows how much input the tool goes through. Processes counts the processes it started.

### Computing resources to review one system

Median over the systems each tool can read; most CPU time first.

| Tool | Systems it can read | CPU time | User / system | Cores used | Memory at peak | Memory on average | Data read | Data written | Processes |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| gosec | 3/10 | 5.1 s | 3.0 s / 2.1 s | 1.24 | 75 MB | 37 MB | 82 MB | 1.4 MB | 146 |
| Checkov | 7/10 | 4.1 s | 3.7 s / 0.39 s | 1.06 | 761 MB | 147 MB | 45 MB | 2.1 MB | 7 |
| Spectral (OWASP) | 3/10 | 2.2 s | 2.0 s / 0.23 s | 1.25 | 132 MB | 90 MB | 20 MB | 32 KB | 2 |
| Kubescape | 7/10 | 1.7 s | 1.6 s / 0.10 s | 0.92 | 120 MB | 105 MB | 4.7 MB | 2.0 MB | 1 |
| **ATG** scan (ATG + PostgreSQL containers) | 10/10 | 0.82 s | 0.71 s / 0.11 s | 0.11 | 144 MB | 128 MB | 3.9 MB | 2.8 MB | 14 |
| njsscan | 3/10 | 0.80 s | 0.69 s / 0.11 s | 0.95 | 65 MB | 28 MB | 11 MB | 15 KB | 5 |
| Bandit | 4/10 | 0.46 s | 0.42 s / 0.04 s | 0.84 | 31 MB | 23 MB | 6.9 MB | 16 KB | 2 |
| Polaris | 7/10 | 0.16 s | 0.14 s / 0.02 s | 1.10 | 37 MB | 30 MB | 16 KB | 99 KB | 1 |
| kube-linter | 7/10 | 0.05 s | 0.03 s / 0.01 s | 0.92 | 35 MB | 16 MB | 16 KB | 31 KB | 1 |

### The largest use on one system

Most CPU time first.

| Tool | CPU time (most) | Memory at peak (most) | On which system |
|---|---:|---:|---|
| gosec | 48.1 s | 282 MB | online-boutique (most CPU) |
| Checkov | 13.2 s | 954 MB | lakeside-mutual (most CPU) |
| Spectral (OWASP) | 4.4 s | 132 MB | lakeside-mutual (most CPU) |
| Kubescape | 2.0 s | 124 MB | hotel-reservation (most CPU) |
| **ATG** scan | 1.2 s | 159 MB | online-boutique (most CPU) |
| njsscan | 1.1 s | 92 MB | robot-shop (most CPU) |
| Bandit | 0.84 s | 32 MB | bank-of-anthos (most CPU) |
| Polaris | 0.25 s | 38 MB | hotel-reservation (most CPU) |
| kube-linter | 0.05 s | 36 MB | bank-of-anthos (most CPU) |

How it was measured: for the eight tools, `bench/run_tools.py` runs each tool as a child process; CPU time comes from `wait4`, memory and the read/write byte counters from `/proc`, sampled every 20 ms. For ATG, `bench/usage.py` reads Docker's counters for the ATG and PostgreSQL containers during the scan (CPU time exactly, memory every 0.5 s, the in-memory folders included); data read and written are the scan process's own counters (`/proc/self/io`). The first run of each tool is slower (it loads its rules). 

### What ATG's four containers use during a review

Median over the 10 systems (most in brackets). *While users run*: the system's users send their requests through the sidecar; *scan*: Phases 1-4. Network: megabytes the container received and sent during the whole review (the sidecar's traffic counts twice: in from a caller, out to the service, and back). Disk: ATG keeps its data in memory, so its containers read and write almost nothing on disk.

| Container | Role | CPU while users run | CPU during the scan | Memory at peak | Memory on average | Network in / out | Disk read / write | Processes |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| atg-proxy | sidecar (mitmproxy): carries and records the traffic | 1.5 s (3.6 s) | 0.03 s (0.15 s) | 54 MB (60 MB) | 53 MB | 484 KB / 474 KB | 0 KB / 0 KB | 3 |
| atg-collector | OpenTelemetry Collector: receives the spans | 0.02 s (0.16 s) | 0.01 s (0.04 s) | 35 MB (45 MB) | 30 MB | 104 KB / 5 KB | 0 KB / 0 KB | 7 |
| atg-postgres | PostgreSQL: EUJF records, threat graph, attack-path query | 0.08 s (0.14 s) | 0.16 s (0.19 s) | 70 MB (89 MB) | 66 MB | 387 KB / 76 KB | 0 KB / 0 KB | 11 |
| atg | ATG: scan (Phases 1-4), pages, web view | 0.20 s (0.64 s) | 0.69 s (1.0 s) | 73 MB (80 MB) | 36 MB | 113 KB / 424 KB | 0 KB / 0 KB | 4 |
| **All four** | | 2.8 s (5.1 s) in all | | 232 MB (260 MB) | | | | |

The sidecar used 2.4 ms of CPU per request it carried (median; 2.0-2.7 ms).

## 3. Accuracy: known weaknesses found

The 712 known weaknesses fall into three groups:

- **Configuration (546)**: mistakes in the deployment files (Kubernetes manifests, Docker Compose files, gateway settings), for example a container that may run as root, no network policy, no memory or CPU limit, a password written in a plain file, an image without a fixed version, or a public entry without HTTPS. The Kubernetes scanners and ATG can find these.
- **API behaviour (82)**: how the running API behaves when it is used, for example an operation that returns private data without a login, one service calling another without credentials, an admin or debug page open to everyone, a password sent in the URL, or a login with no limit on wrong tries. Only a tool that sees the API in use (ATG) or reads its API document (Spectral and Checkov's OpenAPI checks, partly) can find these.
- **Inventory and visibility (84)**: what the company does not know about its own APIs, for example operations that no API document describes (shadow APIs) and services that send no traces. Only ATG compares what runs with what is documented.

### Inventory and visibility: detected or not

Finding these needs the running system compared with the API documents and the deployment files, so it is a capability a tool either has or does not have; it is shown as *detected* or *not detected* rather than as a score, and left out of the chart above.

| Tool | Shadow APIs and services without an API document | Services that send no traces | Inventory and visibility (84) |
|---|---|---|---|
| **ATG** | Detected (58/58) | Detected (26/26) | **Detected (84/84)** |
| Checkov | Not detected | Not detected | Not detected |
| Kubescape | Not detected | Not detected | Not detected |
| kube-linter | Not detected | Not detected | Not detected |
| Polaris | Not detected | Not detected | Not detected |
| Spectral (OWASP) | Not detected | Not detected | Not detected |
| Bandit | Not detected | Not detected | Not detected |
| gosec | Not detected | Not detected | Not detected |
| njsscan | Not detected | Not detected | Not detected |

### Operations ATG listed (its API inventory)

Every API operation in the systems' code, against ATG's inventory from the same DEMO-ALL run. *Correct* is the share of ATG's entries that are real operations (an operation listed twice, for example once at the gateway and once at the service, counts as one wrong entry). No other tool lists operations.

| System | Operations in the code | ATG listed correctly | ATG's entries | Correct |
|---|---:|---:|---:|---:|
| lakeside-mutual | 38 | 38 (100%) | 38 | 100% |
| robot-shop | 30 | 29 (97%) | 29 | 100% |
| online-boutique | 26 | 25 (96%) | 25 | 100% |
| acme-air | 22 | 20 (91%) | 35 | 57% |
| bank-of-anthos | 17 | 15 (88%) | 15 | 100% |
| petclinic | 16 | 15 (94%) | 15 | 100% |
| ftgo | 14 | 9 (64%) | 17 | 53% |
| piggymetrics | 13 | 13 (100%) | 13 | 100% |
| bookinfo | 13 | 13 (100%) | 13 | 100% |
| hotel-reservation | 12 | 12 (100%) | 12 | 100% |
| **All** | 201 | 189 (94%) | 212 | 89% |

### How many known weaknesses each tool found

*Found* counts all 712 known weaknesses of the ten systems, so a tool that cannot read a system scores 0 there. *Found, of what it can check* counts only the kinds of weakness the tool has a check for, on the systems it can read. *Correct reports* is the share of the tool's reports (kind of weakness and place) that are in the answer key; the rest are false alarms or problems the key does not list. Inventory and visibility is in the table above.

| Tool | Systems it can read | Found (of 712) | Configuration | API behaviour | Found, of what it can check | Correct reports |
|---|---:|---:|---:|---:|---:|---:|
| **ATG** | 10/10 | 462/712 (65%) | 326/546 (60%) | 52/82 (63%) | 462/543 (85%) | 714/950 (75%) |
| Checkov | 7/10 | 271/712 (38%) | 262/546 (48%) | 9/82 (11%) | 271/382 (71%) | 271/385 (70%) |
| Kubescape | 7/10 | 254/712 (36%) | 254/546 (47%) | 0/82 (0%) | 254/370 (69%) | 254/291 (87%) |
| kube-linter | 7/10 | 164/712 (23%) | 164/546 (30%) | 0/82 (0%) | 164/282 (58%) | 164/184 (89%) |
| Polaris | 7/10 | 349/712 (49%) | 349/546 (64%) | 0/82 (0%) | 349/368 (95%) | 349/368 (95%) |
| Spectral (OWASP) | 3/10 | 13/712 (2%) | 3/546 (1%) | 10/82 (12%) | 13/22 (59%) | 13/35 (37%) |
| Bandit | 4/10 | 1/712 (0%) | 1/546 (0%) | 0/82 (0%) | 1/5 (20%) | 1/5 (20%) |
| gosec | 3/10 | 0/712 (0%) | 0/546 (0%) | 0/82 (0%) | 0/0 (–) | 0/0 (–) |
| njsscan | 3/10 | 0/712 (0%) | 0/546 (0%) | 0/82 (0%) | 0/0 (–) | 0/0 (–) |

### ATG's reports that are not in the answer key

236 of ATG's 950 reports match no known weakness. By kind:

| Kind | Reports | Note |
|---|---:|---|
| O2 not traced | 74 | 48 on workloads the answer key does not count as API services (databases, caches, message brokers, registries, monitoring, load generators, web front ends); 26 on operations, mostly the extra entries ATG lists at Acme Air's Ingress controller and at FTGO's gateway (no traces) |
| O1 no API document | 73 | 50 on workloads the answer key does not count as API services (databases, caches, message brokers, registries, monitoring, load generators, web front ends); 23 on operations, mostly the extra entries ATG lists at Acme Air's Ingress controller and at FTGO's gateway (no API document) |
| A1 no authentication on a sensitive operation | 62 | operations with no authentication check that the answer key does not count as sensitive; most serve public data, such as a catalogue or a flight search |
| A9 bulk sensitive data | 9 |  |
| A4 debug or diagnostic endpoint exposed | 8 |  |
| C5 published outside the gateway | 6 |  |
| A2 broken object level authorization | 3 |  |
| A6 login without rate limit | 1 |  |

### Why the file scanners find configuration but no API behaviour or inventory

API behaviour is how the running API answers: who may call an operation, what it returns, whether one service calls another without credentials. Kubernetes and Compose files do not describe API operations at all, and code scanners look for coding mistakes, not for who may call what. Only an API document says something about the API, which is why Spectral (and Checkov's OpenAPI checks) find a few API-behaviour weaknesses where a document exists. Inventory and visibility compare what runs with what is documented and traced; a tool that reads one kind of file has nothing to compare it with.

To check that this is not a scoring gap, every check each tool reported on the ten systems is listed below: *counted* checks are translated into a kind of known weakness, the others are not about any of the 22 kinds (most are about probes, labels, namespaces, requests or image signatures).

| Tool | Checks it reported | Findings | Counted (checks / findings) | Not counted: the most frequent |
|---|---:|---:|---:|---|
| Checkov | 30 | 1288 | 17 / 584 | CKV_K8S_21 (The default namespace should not be used) x173; CKV_K8S_40 (Containers should run as a high UID to avoid host conflict) x74; CKV_K8S_31 (Ensure that the seccomp profile is set to docker/default or ) x74; CKV_K8S_43 (Image should use digest) x65; CKV_K8S_29 (Apply security context to your pods and containers) x55; CKV_K8S_30 (Apply security context to your containers) x55 |
| Kubescape | 32 | 1252 | 16 / 653 | C-0077 (K8s common labels usage) x64; C-0061 (Pods in default namespace) x64; C-0210 (Ensure that the seccomp profile is set to docker/default in ) x64; C-0211 (Apply Security Context to Your Pods and Containers) x64; C-0237 (Check if signature exists) x64; C-0236 (Verify image signature) x64 |
| kube-linter | 12 | 244 | 6 / 219 | readiness-port (readiness port) x6; no-extensions-v1beta (no extensions v1beta) x6; liveness-port (liveness port) x4; mismatching-selector (mismatching selector) x4; startup-port (startup port) x3; deprecated-service-account-field (deprecated service account field) x2 |
| Polaris | 23 | 1171 | 12 / 522 | metadataAndInstanceMismatched (Label app.kubernetes.io/instance must match metadata.name) x74; priorityClassNotSet (Priority class should be set) x74; topologySpreadConstraint (Pod should be configured with a valid topology spread constr) x73; deploymentMissingReplicas (Only one replica is scheduled) x67; missingPodDisruptionBudget (Should have a PodDisruptionBudget) x67; pullPolicyNotAlways (Image pull policy should be "Always") x59 |
| Spectral (OWASP) | 16 | 712 | 5 / 160 | owasp:api4:2023-string-limit (Schema of type string must specify maxLength, enum, or const) x101; owasp:api4:2023-string-restricted (Schema of type string should specify a format, pattern, enum) x101; owasp:api8:2023-define-error-responses-401 (Operation is missing responses[401].) x90; owasp:api8:2023-define-error-responses-500 (Operation is missing responses[500].) x90; owasp:api4:2023-integer-limit-legacy (Schema of type integer must specify minimum and maximum.) x55; owasp:api8:2023-define-error-validation (Missing error response of either 400, 422 or 4XX.) x42 |
| Bandit | 5 | 29 | 1 / 6 | B113 (request_without_timeout) x12; B311 (blacklist) x7; B413 (blacklist) x2; B104 (hardcoded_bind_all_interfaces) x2 |
| gosec | 6 | 24 | 0 / 0 | G104 (Errors unhandled.) x13; G404 (Use of weak random number generator (math/rand or math/rand/) x7; G114 (Use of net/http serve function that has no support for setti) x1; G107 (Potential HTTP request made with variable url) x1; G109 (Potential Integer overflow made by strconv.Atoi result conve) x1; G112 (Potential Slowloris Attack because ReadHeaderTimeout is not ) x1 |
| njsscan | 0 | 0 | 0 / 0 | – |

Corrections made by this check (version 1.6.4): Polaris's `sensitiveContainerEnvVar` and `sensitiveConfigmapContent` now count as secrets in deployment files and `tlsSettingsMissing` as an entry without TLS (they had been left out); Spectral's error-response rules no longer count as "no TLS" (only its http:// server rule does); and Checkov now also reads the API documents with its OpenAPI checks.

### Found, by kind of weakness

| Code | Kind of weakness | Known | ATG | Checkov | Kubescape | kube-linter | Polaris | Spectral (OWASP) | Bandit | gosec | njsscan |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| A1 | no authentication on a sensitive operation | 23 | 16 | 9 | · | · | · | 9 | · | · | · |
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
| C7 | secret in deployment files | 16 | 10 | 3 | 10 | 1 | 13 | · | 1 | 0 | 0 |
| C8 | public entry without TLS | 17 | 11 | 0 | 0 | · | 5 | 3 | · | · | · |
| C9 | missing container hardening | 97 | · | 53 | 50 | 47 | 53 | · | · | · | · |
| C10 | service account token mounted | 72 | · | 72 | 62 | · | 72 | · | · | · | · |
| O1 | no API document | 58 | 58 | · | · | · | · | · | · | · | · |
| O2 | not traced | 26 | 26 | · | · | · | · | · | · | · | · |

· = the tool has no check for this category. ATG reports missing resource limits (C3) only for services reachable from the internet, where they matter for API4 (resource consumption); the scanners report every container, which is why they find more C3 labels.

### Found on each system

**Where the known weaknesses come from.** Every system has an answer key, `opensource/<system>/ground-truth.json`, made before any tool was scored. Each known weakness is one kind of weakness (22 kinds, codes A1-A10, C1-C10, O1-O2) at one place (a service or an API operation), and it says where it comes from:

- 91 come from reading the system's code (marked *code review*), each with the file it was found in. Example: Bank of Anthos's login form has no limit on wrong tries (`src/frontend/frontend.py`).
- 621 come from fixed rules applied to the system's real deployment files, its service calls and its API documents (marked *deployment files*; `opensource/config_labels.py`). Example: every container that does not set `runAsNonRoot` gets "may run as root"; every service that no NetworkPolicy selects gets "no network segmentation".

**How a tool gets credit.** Each tool's findings are translated into the same 22 kinds with a fixed table (`bench/run_tools.py` for the tools, `bench/oss_scoring.py` for ATG). Example: Checkov's `CKV_K8S_23` and ATG's `API8-ROOT` both become "may run as root". A known weakness counts as found when the tool reports the same kind at the same service or operation. One script marks every tool the same way; n/a means the tool cannot read that system's files, and 0 that it ran and found none.

<!--FIG:systems-->

The same numbers as a table, the systems with the most known weaknesses first:

| System | Known weaknesses | **ATG** | Checkov | Kubescape | kube-linter | Polaris | Spectral (OWASP) | Bandit | gosec | njsscan |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| hotel-reservation | 107 | **68** | 70 | 76 | 51 | 89 | n/a | n/a | 0 | n/a |
| piggymetrics | 88 | **62** | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| ftgo | 82 | **46** | 55 | 6 | 18 | 67 | 2 | n/a | n/a | n/a |
| lakeside-mutual | 80 | **52** | 52 | 45 | 36 | 54 | 11 | n/a | n/a | n/a |
| acme-air | 79 | **53** | 40 | 50 | 32 | 58 | n/a | n/a | n/a | n/a |
| robot-shop | 76 | **42** | n/a | n/a | n/a | n/a | n/a | 0 | 0 | 0 |
| petclinic | 67 | **54** | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| online-boutique | 55 | **43** | 23 | 24 | 11 | 35 | n/a | 0 | 0 | 0 |
| bank-of-anthos | 44 | **22** | 15 | 33 | 4 | 26 | n/a | 1 | n/a | n/a |
| bookinfo | 34 | **20** | 16 | 20 | 12 | 20 | 0 | 0 | n/a | 0 |

### ATG and a Kubernetes scanner used together

Known weaknesses found by each tool, by both, and by at least one of them. The scanners add the container-hardening checks ATG does not have (C9, C10); ATG adds the API, inventory and Compose findings they cannot make.

| Pair | ATG | Other tool | Both | At least one |
|---|---:|---:|---:|---:|
| ATG + Polaris | 462 | 349 | 202 | 609/712 (86%) |
| ATG + Kubescape | 462 | 254 | 130 | 586/712 (82%) |
| ATG + Checkov | 462 | 271 | 122 | 611/712 (86%) |

#### Measured: every combination on the same answer key

| Combination | Known weaknesses found |
|---|---:|
| **ATG alone** | 462/712 (65%) |
| ATG + Polaris | 609/712 (86%) |
| ATG + Checkov | 611/712 (86%) |
| ATG + Polaris + Kubescape | 616/712 (87%) |
| ATG + the four Kubernetes scanners | 619/712 (87%) |
| ATG + all eight tools | 622/712 (87%) |
| ATG + the three code scanners (Bandit, gosec, njsscan) | 462/712 (65%) |
| The eight tools without ATG | 370/712 (52%) |

Even all nine tools together leave 90 of the 712 known weaknesses unfound. *Proof in the code* means the answer key's evidence for that weakness is a source-code file, so only something that reads the code could confirm it.

| Kind | Missed by ATG | of which proof in the code | Missed by every tool | of which proof in the code |
|---|---:|---:|---:|---:|
| A1 no authentication on a sensitive operation | 7 | 7 | 5 | 5 |
| A3 admin function exposed | 6 | 6 | 6 | 6 |
| A4 debug or diagnostic endpoint exposed | 5 | 5 | 5 | 5 |
| A5 service-to-service call without credentials | 8 | 8 | 8 | 8 |
| A6 login without rate limit | 2 | 2 | 2 | 2 |
| A10 third-party API use | 2 | 2 | 2 | 2 |
| C3 no resource limits | 39 | 0 | 20 | 0 |
| C7 secret in deployment files | 6 | 1 | 2 | 1 |
| C8 public entry without TLS | 6 | 1 | 3 | 0 |
| C9 missing container hardening | 97 | 0 | 37 | 0 |
| C10 service account token mounted | 72 | 0 | 0 | 0 |
| **All** | 250 | 32 | 90 | 29 |

#### Future plan

Each step lists the most it could add: the known weaknesses of that kind ATG misses today. They are upper bounds counted from the answer key, not results; a step is only proven once it is built and measured again, and because these steps are chosen after seeing ATG's misses on these systems, they would have to be checked on systems ATG has not seen.

**Plan A, first choice: no source code needed.** ATG keeps working from the running system and its files, so it stays independent of the programming language and works where the code is not available.

| Step | What it adds | At most | ATG alone would reach at most |
|---|---|---:|---:|
| A1. Container-hardening and service-account-token rules | ATG already reads `readOnlyRootFilesystem`, `allowPrivilegeEscalation`, capabilities and `automountServiceAccountToken` from the manifests but has no rule for them (C9, C10) | +169 | 631/712 (89%) |
| A2. Resource limits on every service | today ATG reports missing limits only on services the internet reaches (API4); an option to report all of them (C3) | +39 | 670/712 (94%) |
| A3. More secret and TLS cases in the files | the plaintext-secret and missing-TLS cases ATG misses in deployment files (C7, C8) | +10 | 680/712 (96%) |
| A4. One merged report with a Kubernetes scanner | import Checkov's or Polaris's SARIF into ATG's threat graph and hardening report, so the two run as one review | measured today: ATG + Checkov 611/712 | |
| A5. Longer or guided user sessions | operations nobody calls during the review stay invisible, because the traffic and traces show only what is used (the operations table in section 3); replaying a fuller user session or the API documents' examples | +12 operations (189 to 201 of 201) | |

**Plan B, second choice: when the source code is available.** An optional fifth source that reads the code to list every route, the authentication each one checks, the calls it makes to other services and to third-party APIs, and admin or debug consoles registered in it. It is a second choice because the code is often not available to the reviewer (bought or outsourced services, only container images delivered, code the owner will not share), and because it needs a reader for each language and framework (the ten systems use eight languages), which gives up ATG's independence from the language. The three free code scanners show that ordinary code scanning is not enough: they look for coding mistakes, and adding them to ATG adds 0 known weaknesses.

| Step | What it adds | At most |
|---|---|---:|
| B1. Routes from the code | every operation, even one nobody calls during the review | +12 operations (201 of 201) |
| B2. Authentication, calls and consoles from the code | the API-behaviour weaknesses ATG misses today, all of which have their proof in the code (A1 no authentication 7, A3 admin 6, A4 debug 5, A5 service calls without credentials 8, A6 login rate limit 2, A10 third-party APIs 2) and the secret and TLS cases with their proof in the code | +32 |

Together the steps of both plans cover every kind of weakness ATG misses today. That does not mean ATG would find them all: how many each step really finds can only be measured once it is built.

Plan B matters most for the 29 weaknesses with proof in the code that no tool finds today: no combination of the tools in this benchmark can find them without reading the code.

## 4. Systems covered

### Which systems each tool can read

| Tool | What it needs | Systems it could not read |
|---|---|---|
| ATG | a running test deployment (many languages), plus whatever files exist | 0: none |
| Checkov | Kubernetes manifests | 3: robot-shop, petclinic, piggymetrics (Checkov has no Docker Compose checks) |
| Kubescape | Kubernetes manifests (current API versions) | 3: robot-shop, petclinic, piggymetrics (reads Kubernetes manifests only) |
| kube-linter | Kubernetes manifests | 3: robot-shop, petclinic, piggymetrics (reads Kubernetes manifests only) |
| Polaris | Kubernetes manifests | 3: robot-shop, petclinic, piggymetrics (reads Kubernetes manifests only) |
| Spectral (OWASP) | an OpenAPI document | 7: online-boutique, bank-of-anthos, robot-shop, acme-air, petclinic, piggymetrics, hotel-reservation (no API document to lint) |
| Bandit | Python source | 6: acme-air, petclinic, piggymetrics, lakeside-mutual, ftgo, hotel-reservation (no Python service) |
| gosec | Go source | 7: bank-of-anthos, acme-air, petclinic, piggymetrics, lakeside-mutual, ftgo, bookinfo (no Go service) |
| njsscan | Node.js source | 7: bank-of-anthos, acme-air, petclinic, piggymetrics, lakeside-mutual, ftgo, hotel-reservation (no Node.js service) |

Kubescape also ran on FTGO but found 6 of 82 labels: FTGO declares its Deployments and StatefulSets with API versions Kubernetes has removed (`extensions/v1beta1`, `apps/v1beta1`), and Kubescape skipped them, scanning only the Services, the Secret and the Job. The other scanners read them.

## 5. Language limits

The three code scanners each read one programming language. The Kubernetes scanners and Spectral do not read code: their limit is the kind of file (Kubernetes files, API documents), so they reach only the services, of whatever language, that have such a file. ATG does not read source code either: it reviews the running system (its HTTP traffic and traces) and its files, so it reviewed the services of all eight languages in the ten systems. Its limits are of another kind (the last table).

### Services and languages each tool can review

| Tool | What it reads | Services it can review (of 65) | Languages (of 8) | Which languages |
|---|---|---:|---:|---|
| **ATG** | the running system and all its files | 65 | 8 | C#, Go, Java, JavaScript (browser page), Node.js, PHP, Python, Ruby |
| Checkov | Kubernetes files | 44 | 6 | C#, Go, Java, Node.js, Python, Ruby |
| Kubescape | Kubernetes files | 44 | 6 | C#, Go, Java, Node.js, Python, Ruby |
| kube-linter | Kubernetes files | 44 | 6 | C#, Go, Java, Node.js, Python, Ruby |
| Polaris | Kubernetes files | 44 | 6 | C#, Go, Java, Node.js, Python, Ruby |
| Spectral (OWASP) | API documents | 7 | 2 | Java, Python |
| Bandit | Python code | 7 | 1 | Python |
| gosec | Go code | 13 | 1 | Go |
| njsscan | Node.js code | 6 | 1 | Node.js |

### The services of each system and their languages

| System | Services | Languages | Each service (language) | Bandit (Python) | gosec (Go) | njsscan (Node.js) |
|---|---:|---|---|---:|---:|---:|
| online-boutique | 10 | Go, C#, Node.js, Python, Java | frontend (Go), cartservice (C#), productcatalogservice (Go), currencyservice (Node.js), recommendationservice (Python), shippingservice (Go), paymentservice (Node.js), emailservice (Python), checkoutservice (Go), adservice (Java) | 2 | 4 | 2 |
| bank-of-anthos | 6 | Python, Java | frontend (Python), userservice (Python), contacts (Python), balancereader (Java), transactionhistory (Java), ledgerwriter (Java) | 3 | 0 | 0 |
| robot-shop | 8 | JavaScript (browser page), Node.js, Java, Python, PHP, Go | web (JavaScript (browser page)), catalogue (Node.js), user (Node.js), cart (Node.js), shipping (Java), payment (Python), ratings (PHP), dispatch (Go) | 1 | 1 | 3 |
| acme-air | 5 | Java | acmeair-main-service (Java), acmeair-auth-service (Java), acmeair-booking-service (Java), acmeair-customer-service (Java), acmeair-flight-service (Java) | 0 | 0 | 0 |
| petclinic | 7 | Java | api-gateway (Java), customers-service (Java), visits-service (Java), vets-service (Java), genai-service (Java), admin-server (Java), config-server (Java) | 0 | 0 | 0 |
| piggymetrics | 6 | Java | gateway (Java), auth-service (Java), account-service (Java), statistics-service (Java), notification-service (Java), monitoring (Java) | 0 | 0 | 0 |
| lakeside-mutual | 5 | Java | customer-core (Java), customer-self-service-backend (Java), customer-management-backend (Java), policy-management-backend (Java), spring-boot-admin (Java) | 0 | 0 | 0 |
| ftgo | 6 | Java | ftgo-api-gateway (Java), ftgo-consumer-service (Java), ftgo-order-service (Java), ftgo-order-history-service (Java), ftgo-kitchen-service (Java), ftgo-restaurant-service (Java) | 0 | 0 | 0 |
| hotel-reservation | 8 | Go | frontend (Go), search (Go), geo (Go), rate (Go), profile (Go), recommendation (Go), user (Go), reservation (Go) | 0 | 8 | 0 |
| bookinfo | 4 | Python, Ruby, Java, Node.js | productpage (Python), details (Ruby), reviews (Java), ratings (Node.js) | 1 | 0 | 1 |
| **All** | 65 | 8 languages | | 7 (11%) | 13 (20%) | 6 (9%) |

Together the three code scanners read 26 of 65 services (40%); the Java, C#, Ruby, PHP and browser JavaScript services have no free code scanner here.

### Which tool can review each language

yes: the tool reviewed at least one service of this language in the ten systems.

| Language | Services | ATG | Checkov | Kubescape | kube-linter | Polaris | Spectral (OWASP) | Bandit | gosec | njsscan |
|---|---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Java | 35 | yes | yes | yes | yes | yes | yes | no | no | no |
| Go | 13 | yes | yes | yes | yes | yes | no | no | yes | no |
| Python | 7 | yes | yes | yes | yes | yes | yes | yes | no | no |
| Node.js | 6 | yes | yes | yes | yes | yes | no | no | no | yes |
| C# | 1 | yes | yes | yes | yes | yes | no | no | no | no |
| JavaScript (browser page) | 1 | yes | no | no | no | no | no | no | no | no |
| PHP | 1 | yes | no | no | no | no | no | no | no | no |
| Ruby | 1 | yes | yes | yes | yes | yes | no | no | no | no |

### What ATG cannot read

| What | Where in the ten systems | Why |
|---|---|---|
| Source code, in any language | all 65 services | ATG reviews the running system and its files, not the code, so code bugs such as injection need a code scanner or an active scanner |
| Messages on a queue | RabbitMQ in Robot Shop and PiggyMetrics, Kafka in FTGO | the sidecar records HTTP traffic only; Robot Shop's dispatch service, which only reads RabbitMQ, has no API to see |
| Database traffic | MongoDB, MySQL, PostgreSQL, Redis or Memcached in eight systems | not HTTP; ATG only lists which services connect to a database, from their settings |
| Operations nobody uses during the review | operations outside the users' session | the traffic and traces show only what is used; API documents and deployment files show the rest only if they list it |
