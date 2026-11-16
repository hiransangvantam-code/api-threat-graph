# ATG compared with other tools

The professor asked how ATG compares with other tools, IBM's and NVIDIA's for example, and for a
benchmark on more systems that also shows where tools hit a limit (one language only, for example).
This document has two parts:

1. **Tools we ran.** Eight free tools and ATG on the same ten open-source systems, scored with the same
   ground truth. The numbers come from `results/opensource/comparison.md` (written by
   `bench/compare_tools.py`); the method is in `docs/BENCHMARK_OSS.md`.
2. **Tools we could not run.** Commercial platforms (IBM, NVIDIA, Salt, Akamai, Harness/Traceable, Wiz,
   Palo Alto, Microsoft, 42Crunch) and threat-modelling tools, compared from their public documentation.
   They need paid accounts, a cloud, their own gateway product or GPUs, so they are compared on what
   they say they do, not on measured results.

## 1. Tools we ran

| Tool | Made by | What it reads | Category it belongs to |
|---|---|---|---|
| **ATG** (this project) | this project | live traffic through a sidecar, OpenTelemetry / Zipkin / Jaeger traces, Kubernetes and Compose files, gateway configs (Kong, nginx, Spring Cloud Gateway, Zuul, Istio), API documents | API design review |
| Checkov 3.4 | Palo Alto Networks (the open-source scanner inside Prisma Cloud) | Kubernetes manifests, secrets | IaC scanner |
| Kubescape 3.0 | ARMO, CNCF project | Kubernetes manifests | Kubernetes posture |
| kube-linter 0.7 | Red Hat (StackRox) | Kubernetes manifests | Kubernetes linter |
| Polaris 9.6 | Fairwinds | Kubernetes manifests | Kubernetes posture |
| Spectral 6.17 + OWASP API ruleset | Stoplight | OpenAPI documents | API document linter |
| Bandit 1.9 | PyCQA | Python source | SAST, one language |
| gosec 2.21 | Securego | Go source | SAST, one language |
| njsscan 1.0 | OpenSecurity | Node.js source | SAST, one language |

OWASP ZAP (active scanner) was compared on ShopLite earlier (`docs/COMPARISON_ZAP.md`). It was not run
on the ten systems: it tests only the operations in an API document, only three of the ten systems ship or serve one,
and on stand-in services its attack results would mean nothing.

The results tables (accuracy by category group, what each tool can reach, speed, and where each
tool stops) are in `results/opensource/comparison.md` and summarised in `docs/BENCHMARK_OSS.md`. In short:

| | ATG v1.6.5 | Polaris | Checkov | Kubescape | kube-linter | Spectral | Bandit / gosec / njsscan |
|---|---:|---:|---:|---:|---:|---:|---:|
| Systems it runs on | 10 | 7 | 7 | 7 | 7 | 3 | 4 / 3 / 3 |
| Labels found (of 712) | 462 | 349 | 271 | 254 | 164 | 13 | 1 / 0 / 0 |
| API behaviour (82) and inventory (84) labels | 52 + 84 | 0 | 9 + 0 | 0 | 0 | 10 + 0 | 0 |
| Configuration labels (546) | 326 | 349 | 262 | 254 | 164 | 3 | 1 / 0 / 0 |
| Precision | 75% | 95% | 70% | 87% | 89% | 37% | – |
| Time per system (median) | 0.44 s for Phases 1-4 (~8 s per whole scan) | 0.14 s | 3.8 s | 1.9 s | 0.04 s | 1.8 s | 0.6-4.1 s |

The Kubernetes scanners are as good as ATG on deployment configuration and more precise, but they stop
at the manifests: three systems ship Docker Compose, which none of them reads, and they say nothing about
how the API behaves. The code scanners each read one language (26 of the 65 services between them).
ATG with Checkov finds 86% of all labels.

## 2. Tools we could not run, from their documentation

Columns: **Data** = where the tool gets its picture of the system. **Before production** = can it review
a design or deployment without production traffic. **Deploy files** = does it read Kubernetes / gateway
configuration. **Graph / paths** = does it connect weaknesses into attack paths. **Runs where** = what
you need to run it.

| Tool | Data | Finds undocumented APIs | Before production | Deploy files | Graph / paths | Fix guidance | Runs where |
|---|---|---|---|---|---|---|---|
| **ATG** | sidecar traffic, traces, manifests, gateway configs, API documents, combined | yes (traffic + traces vs documents) | yes, on a test deployment | yes: K8s, Compose, Kong, nginx, SCG, Zuul, Istio | yes, attack paths with path risk | ordered fix plan, fix in the system's own stack, how to verify | two Dockers, offline, free |
| IBM API Connect with Akamai (Noname) Advanced API Security | API Connect / DataPower gateway traffic (analytics offload), plus the Akamai platform | yes | active testing in CI/CD | gateway policies | not documented | posture findings | IBM API Connect + Akamai subscription |
| NVIDIA Morpheus | streaming network, log and endpoint data, GPU AI pipelines | not its purpose | no | no | graph views for some workflows | none: a framework to build detectors | NVIDIA GPUs (CPU mode exists), Triton |
| Salt Security | mirrored API traffic, out of band; eBPF; external scan (Salt Surface) | yes | posture governance policies | partly | not documented | posture findings | SaaS, traffic mirroring |
| Akamai API Security (Noname) | runtime traffic, code repositories, API documentation, gateways, cloud | yes | active testing (200+ tests) | gateways, cloud | not documented | remediation context | SaaS or on-premises |
| Harness API Security (Traceable) | distributed traces (OpenTelemetry agents) | yes, within what is instrumented | CI tests | no | API call flows | findings | Harness platform, agents in each service |
| Wiz (Google) | cloud provider APIs (agentless), eBPF sensor | not at endpoint level | yes, cloud and code | cloud and Kubernetes configuration | Security Graph: attack paths, "toxic combinations" | prioritised issues | SaaS, cloud accounts |
| Palo Alto Prisma Cloud / Cortex Cloud (WAAS) | Defender agents, or AWS VPC mirroring | yes | Checkov for IaC | yes (Checkov) | no for APIs | WAF rules, virtual patching | SaaS, agents |
| Microsoft Defender for APIs | Azure API Management traffic | only APIs in APIM | no | APIM settings | attack path analysis | security recommendations | Azure, APIs published in APIM |
| 42Crunch | the OpenAPI contract; conformance scan of the running API | no: tests the contract | yes (audit, 300+ checks, score 0-100) | no | no | per-issue remediation | IDE, CI, SaaS |
| Microsoft Threat Modeling Tool | a data-flow diagram drawn by hand | no | yes | no | threats per interaction (STRIDE) | mitigation text | Windows, free |
| OWASP Threat Dragon | a diagram drawn by hand | no | yes | no | threats per element (STRIDE, LINDDUN, CIA, DIE, PLOT4ai) | mitigation text | desktop or web, free |
| Threagile | a YAML model written by hand | no | yes | no | about 40 risk rules over the model graph | mitigation text, PDF / Excel / JSON | CLI / Docker, offline, free |
| IriusRisk | diagrams, Terraform / CloudFormation, OTM files | no | yes | IaC (cloud), not runtime | rules engine over the model | countermeasures | SaaS, commercial |

### What the table says

- **IBM** does API security through its gateway products: API Connect with the Akamai (formerly Noname)
  integration adds discovery, posture management, runtime protection and active testing. It needs the
  traffic to pass through IBM's gateway. ATG reads the gateway the system already has (Kong, nginx,
  Spring Cloud Gateway, Zuul, Istio) and needs no gateway product.
- **NVIDIA Morpheus** is not an API review tool. It is a GPU framework for building AI detectors over
  streaming security data: digital fingerprinting of user and machine behaviour, sensitive information
  detection, phishing. It works after deployment, on traffic and logs, and finds anomalies. It does not
  say that an endpoint lacks an owner check or that a gateway route has no authentication. ATG works
  before production and explains each finding. The two could meet: Morpheus' sensitive-information model
  could classify the response bodies ATG captures.
- **The runtime platforms** (Salt, Akamai, Harness/Traceable, Prisma WAAS, Defender for APIs) find APIs
  in production traffic and detect attacks. Harness/Traceable is the closest to ATG's idea of building the
  picture from traces, but it needs agents in every service and its coverage stops where the
  instrumentation stops. None of them reads the Kubernetes and gateway files next to the traffic the way
  ATG does, and all need a subscription and production traffic.
- **Wiz** has the closest *graph* idea: one security graph across cloud resources, identities and
  exposure, with attack paths. It works at the level of cloud resources, not API operations (which
  endpoint answers anonymous callers, which call chain reaches the payment service without a token).
- **42Crunch** reviews the OpenAPI contract and tests the API against it. It cannot see what is not in the
  contract. Only three of our ten systems ship or serve API documents, and they are incomplete: Bookinfo's
  `swagger.yaml` lists 4 of its 13 operations. ATG found the other 9 from traffic (API9 shadow findings).
- **Threat-modelling tools** start from a model a person draws or writes. ATG builds the model from the
  running system and its files, which is the gap the paper addresses: the model is never out of date.

### Threats to validity of part 2

These are vendors' own descriptions (product pages, documentation, press releases), not measurements.
Feature names differ between vendors, a "not documented" cell can mean "not public" rather than "not
there", and products change quickly (Noname became Akamai in 2024, Traceable became Harness in 2025,
Wiz joined Google in 2026). The table should be read as "what each tool is built to do", not as a ranking.

## Sources

- IBM, API Connect security: https://www.ibm.com/products/api-connect/secure
- Akamai, Integrated API security and governance for IBM API Connect and DataPower (solution brief, 2025): https://akamai.com/content/dam/site/en/documents/solution-brief/2025/integrated-api-security-and-governance-for-ibm-api-connect-and-datapower.pdf
- IBM Community, How to set robust API security with IBM API Connect and Noname integration (2024): https://community.ibm.com/community/user/blogs/alessandra-iampieri/2024/07/16/how-to-set-robust-api-security-with-ibm-api-connec
- NVIDIA Morpheus: https://developer.nvidia.com/morpheus-cybersecurity and https://www.nvidia.com/en-us/ai-data-science/products/morpheus/get-started/
- NVIDIA technical blog, Morpheus sensitive information detection and digital fingerprinting: https://developer.nvidia.com/blog/?p=55006
- Salt Security, API discovery updates (eBPF, Salt Surface, posture governance): https://www.securityinfowatch.com/cybersecurity/press-release/55131214/salt-security-announces-api-discovery-updates-for-api-protection-platform
- Salt Security, platform overview (traffic mirroring): https://content.salt.security/rs/352-UXR-417/images/TagCyber_Real-Time-Mitigation-of-Cyberthreats-to-APIs-Salt-Platform-Overview.pdf
- Akamai API Security: https://www.akamai.com/products/API-security
- SDxCentral, Akamai completes Noname acquisition (2024): https://www.sdxcentral.com/articles/interview/akamai-doubles-down-on-api-security-with-noname-acquisition/2024/06/
- Harness / Traceable: https://appsecsanta.com/traceable-ai and https://salt.security/vs-traceable
- Google Cloud, Google completes acquisition of Wiz: https://cloud.google.com/blog/products/identity-security/google-completes-acquisition-of-wiz
- Wiz Security Graph: https://platformengineering.org/tools/wiz
- Palo Alto Networks, Discover and protect API endpoints (Prisma Cloud WAAS): https://docs.prismacloud.io/use-cases/secure-the-infrastructure/discover-and-protect-api-endpoints
- Microsoft, Defender for APIs: https://learn.microsoft.com/azure/defender-for-cloud/defender-for-apis-introduction and https://learn.microsoft.com/en-us/azure/defender-for-cloud/api-security-posture-overview
- 42Crunch, API Security Audit: https://docs.42crunch.com/latest/content/concepts/api_contract_security_audit.htm and https://42crunch.com/tutorial-api-security-audit-report/
- Microsoft Threat Modeling Tool: https://learn.microsoft.com/en-us/training/modules/introduction-to-secure-devops/7-understand-threat-modeling
- OWASP Threat Dragon: https://owasp.org/projects/threat-dragon and https://owasp.org/www-project-threat-dragon/docs-2/threats
- Threagile: https://github.com/Threagile/threagile
- IriusRisk, infrastructure as code: https://iriusrisk.com/iac
