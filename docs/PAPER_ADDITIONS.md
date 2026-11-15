# Text for the paper: additions from the review (version 1.3)

Drop-in text for the new parts. Section numbers follow the current draft. Table numbers continue after Table 20 of `results/tables.md`. Numbers come from `results/stress/tables.md`, `results/zap/tables.md` and `docs/DATA_HANDLING.md`.

---

## III-A. System overview: add after "...outside the organization's control boundaries."

**Data retention.** Zero exfiltration also has to hold after the review ends, because everything the platform collects belongs to the client. Raw evidence never reaches persistent storage. The sidecar's capture and the Collector's span file are written to in-memory (tmpfs) volumes, and each scan copies the new records it needs and then truncates both files. Phase 1 output, the EUJF and analysis documents and the PostgreSQL data directory are also held in memory. Only the report pages and the exported threat graph are written to disk. Stopping the platform (`docker compose down -v`) removes every container, volume and database, and a separate clean-up command removes the report after it has been handed to the client. On the demonstration system, the previous version left 808 captured flows, 108 span batches and the full graph database on disk after shutdown. The current version leaves only six report pages and eight export files.

---

## III-E. Phase 4: add a paragraph "Threat graph export"

**Threat graph export.** Each scan exports the threat graph in four formats. GraphML [ref] is the primary interchange format. It is an open XML standard that keeps directed edges and typed node and edge attributes (node type, own and propagated risk, the EUJF fields of each endpoint), and Gephi, yEd, Cytoscape, NetworkX and Neo4j read it directly. The findings are also written as SARIF 2.1.0 [ref], the OASIS format for the results of static analysis tools, so they can be imported into vulnerability trackers and CI pipelines. Each result carries a fingerprint derived from its rule and target, so the same weakness is recognised across scans. A node-link JSON file holds the graph together with the ranked attack paths and the remediation plan, and an SVG file holds the drawing used in the dashboard. The SARIF output validates against the official 2.1.0 schema, and the GraphML and JSON files load into NetworkX with the node and edge counts of the graph store.

References to add:
- GraphML: U. Brandes, M. Eiglsperger, J. Lerner, C. Pich, "Graph Markup Language (GraphML)," in *Handbook of Graph Drawing and Visualization*, R. Tamassia, Ed. CRC Press, 2013, pp. 517-541.
- SARIF: OASIS, "Static Analysis Results Interchange Format (SARIF) Version 2.1.0," OASIS Standard, Mar. 2020.

---

## IV. New subsection "Scalability limits"

To find how large a system the analysis handles, the EUJF of one ShopLite scan was cloned k times behind a single gateway (k = 1 to 100, i.e. 4 to 301 services and 12 to 1,101 endpoints), so that every copy carries real findings and attack paths. A second experiment kept 31 services and added d random endpoint-to-endpoint calls per endpoint (d = 0 to 6), which lengthens the CALLS chains the attack path query follows. Phases 3 and 4 ran on PostgreSQL, one configuration per fresh process with fresh tables, with a limit of 300 s (Tables 21 and 22, Fig. X).

The test exposed two bottlenecks in the version evaluated in Tables 11-20. The greedy remediation planner re-scored every action against every remaining path at each step, which took 55 s at 61 services. Because an action's gain depends only on the findings whose paths it removes, the planner now scores each action on those findings alone. The plans are identical on every recorded run, on synthetic systems and on 300 random inputs built to contain ties, and the planner takes 0.5 s at 61 services. PostgreSQL also planned the recursive attack-path query without statistics on the newly created tables. Running ANALYZE after the graph is loaded made the query 12 to 52 times faster with identical results. With both changes, Phase 3 takes 0.4 s for 31 services, 4.5 s for 151 and 20.7 s for 301 services with 11,408 attack paths, using at most 226 MB of memory. The previous version needed 57 s for 61 services and did not finish within 300 s for 151.

The remaining limit is call-chain density. The query enumerates all simple paths of up to nine hops, and their number grows exponentially with the number of calls per endpoint. With 31 services the analysis completes in 23 s at three calls per endpoint (12,813 scored paths) and exhausts 4 GB of temporary space at four. Since the risk model keeps one best path per entry point and finding, a k-best-paths search would avoid the full enumeration. We leave this to future work. For comparison, the largest real system in our evaluation, Train Ticket, has 45 services.

Fig. X: `results/figures/fig_stress.png`. Tables 21-22: `results/stress/tables.md`.

---

## IV. New subsection "Comparison with an active scanner"

We compared the platform with OWASP ZAP 2.16.1, a widely used open-source API scanner, on the same running ShopLite build. ZAP received the OpenAPI documents the platform used and network access to the services, and it ran its default active-scan policy twice: through the public gateway, and against each service inside the cluster network. It had no credentials. Because ZAP's OpenAPI importer left every parameter empty with the services' OpenAPI 3.1 documents and reached only 4 of the 12 endpoints, the documents were converted to OpenAPI 3.0.3 first. Both tools were scored against the 40 weaknesses of Table 16.

Table 23 (from `results/zap/tables.md`): ATG and ZAP side by side. Table 24 lists every ZAP alert type with our reading of it.

ZAP reached the 8 documented endpoints, sent 3,393 requests through the gateway (27.7 s) and 3,527 inside the network (16.7 s), and reported one valid low-risk issue (a missing `X-Content-Type-Options` header) and three informational alerts. It found none of the 40 planted weaknesses and none of the four shadow endpoints, which no document lists. The platform found 37 of the 40 in 0.17 s of analysis, after observing 407 customer requests, while sending 18 read-only requests of its own. The comparison favours the platform in one respect: ShopLite's weaknesses are design and deployment flaws, and the planted list was written by the authors of the rules. ShopLite contains no injection flaws, which are the main strength of an active scanner and outside the scope of a passive review. The two approaches are complementary, and the platform's inventory, shadow endpoints included, can serve as the target list for an active scan.

---

## V. Limitations: add

A passive review only sees endpoints that are documented or exercised during the observation window (Table 10), and it cannot confirm that a suspected authorization flaw is exploitable, because that requires sending a crafted request. It does not cover payload-level flaws such as injection, response-header and CORS configuration, business-flow abuse (OWASP API6), or the strength of secrets, whose values the extractor never copies by design. Of the 18 vulnerabilities OWASP lists for crAPI, 12 are within reach of a passive tool (Table 15). The full list of limits, by OWASP API Security Top 10 category, is in `docs/LIMITS.md`.

---

# Additions from the professor's review (version 1.5)

Numbers come from `results/opensource/comparison.md`, `results/opensource/atg-v1.4/tables.md`,
`results/opensource/atg-v1.5/tables.md` and `results/companies/tables-v1.5.md`. Table numbers continue
after Table 26.

## III-E. Phase 4: add a paragraph "Risk and hardening report"

**Risk and hardening report.** The dashboard quantifies risk; the hardening report turns it into work.
It lists the remediation planner's fixes in the order that removes the most attack-path risk, with the
remaining risk after each one and the number of fixes needed to remove 70% and 90% of it. Every finding
is shown with its likelihood and impact factors, a fix written for the technology the system actually
uses, and a concrete check that the fix works. Gateway fixes are written for the gateway found in Phase 1
(Kong, nginx, Spring Cloud Gateway, Istio or Zuul). NetworkPolicies admit exactly the callers seen in the
traces. Code fixes name the finding's own operation, in the service's web framework when the evidence
reveals it (for example a `/v3/api-docs` endpoint implies Spring). A per-service baseline marks each
hardening control as present, missing or not observable. On the demonstration system the report shows
that 13 of the planner's fixes remove 70% of the attack-path risk and 20 remove 90%.

## IV. New subsection "Open-source systems"

To test the approach on systems its authors did not write, we selected ten open-source microservice
applications published by companies and research groups, spanning nine domains: Online Boutique
and Bank of Anthos (Google), Stan's Robot Shop and Acme Air (IBM), Spring PetClinic, PiggyMetrics,
Lakeside Mutual, FTGO, DeathStarBench Hotel Reservation and Istio Bookinfo. Together they have 65
services in eight languages and 201 API operations. Three are deployed with Docker Compose rather than
Kubernetes, and they use five gateway styles; five have no gateway. Each was pinned to one commit. We
labelled 716 weaknesses: 91 by reading the code, and the rest derived by fixed rules from the deployment
files, the call graph and the API documents. The platform read each system's own deployment files and
API documents. Because the evaluation environment could not pull container images, the running services
were stand-ins that reproduce each system's operations, call graph and authentication checks.

Table 27 (from `results/opensource/atg-v1.4/tables.md` and `atg-v1.5/tables.md`): the platform found 189
of the 201 operations. Version 1.4 found 337 of the 716 labels (47%) at 66% precision. Its misses
revealed general gaps: Kubernetes Service and workload names were not unified, Compose files, Zuul
configurations and multi-profile Spring files were not read, and there was no notion of an edge service
when no gateway exists. Version 1.5 closes these gaps and finds 466 labels (65%) at 75% precision. These
fixes were made after inspecting the same ten systems, so the version 1.4 figures are the unbiased
estimate. Version 1.5 gives the same results as version 1.4 on the demonstration system and on the ten
generated companies.

## IV. New subsection "Comparison with other tools"

We ran eight freely available tools on the same ten systems and scored them against the same labels
(Table 28, from `results/opensource/comparison.md`). Four Kubernetes scanners (Checkov, Kubescape,
kube-linter, Polaris) read the manifests. Spectral with the OWASP API ruleset reads the API documents.
Bandit, gosec and njsscan read Python, Go and Node.js source. The best Kubernetes scanner, Polaris, found
61% of the configuration labels against the platform's 60%. It was more precise (95% against 75%) and
faster (0.2 s against about 8 s per scan, most of which is the platform waiting for its buffers to settle).
No scanner reported any of the 82 API behaviour labels or the 88 inventory and visibility labels. The
platform found 52 and 88 of them. Every tool hit a coverage limit the platform does not have. The
Kubernetes scanners could not read the three Compose systems. Spectral needs an API document, which seven
systems lack. Each code scanner reads one language: together they covered 26 of the 65 services. Kubescape
skipped the workloads of a system that uses removed Kubernetes API versions. The platform and a
Kubernetes scanner complement each other: the platform with Checkov found 86% of all labels.

Commercial API security platforms (IBM API Connect with Akamai API Security, Salt, Harness Traceable,
Wiz, Prisma Cloud, Microsoft Defender for APIs, 42Crunch) and NVIDIA Morpheus could not be run. Table 29
(`docs/TOOLS_COMPARISON.md`) compares them from their documentation. They observe production traffic
through their own gateways, agents or traffic mirroring, or review an OpenAPI contract. None of them
combines runtime evidence with the deployment and gateway configuration in a single attack graph before
production.

## V. Threats to validity: add

The open-source evaluation used stand-in services rather than the published images. The hand-written
labels were produced by the authors of the rules, and the rule-derived configuration labels resemble the
checks of the Kubernetes scanners, which favours those scanners. The mapping of other tools' check
identifiers to our categories was done by hand. A kit to repeat the evaluation on the published images is
included (`opensource/real/`).
