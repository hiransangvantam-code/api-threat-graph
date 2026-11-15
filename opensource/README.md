# Ten open-source microservice systems

The professor asked for ten real open-source systems from different fields, instead of shops we
generated ourselves (`companies/`). These are the ten. Each one is a well-known demo or reference
application published by a company or a research group, pinned to one commit.

| `<id>` | System | Field | Published by | Languages | Deployment files ATG reads | Front door |
|---|---|---|---|---|---|---|
| `online-boutique` | Online Boutique | Retail | Google Cloud | Go, C#, Node.js, Python, Java | Kubernetes, Istio | `frontend` (edge service) |
| `bank-of-anthos` | Bank of Anthos | Banking | Google Cloud | Python, Java | Kubernetes | `frontend` (edge service) |
| `robot-shop` | Stan's Robot Shop | Retail (robots) | Instana (IBM) | Node.js, Java, Python, PHP, Go | Docker Compose, nginx | nginx gateway |
| `acme-air` | Acme Air | Airline | IBM | Java | Kubernetes, Ingress | Ingress controller |
| `petclinic` | Spring PetClinic Microservices | Veterinary clinic | Spring community | Java | Docker Compose, Spring Cloud Gateway | Spring Cloud Gateway |
| `piggymetrics` | PiggyMetrics | Personal finance | A. Lukyanchikov | Java | Docker Compose, Zuul | Zuul gateway |
| `lakeside-mutual` | Lakeside Mutual | Insurance | Microservice API Patterns (OST) | Java, TypeScript | Kubernetes | three backends (edge services) |
| `ftgo` | FTGO | Food delivery | C. Richardson (*Microservices Patterns*) | Java | Kubernetes | API gateway (routes in Java code) |
| `hotel-reservation` | DeathStarBench Hotel Reservation | Hotels | Cornell SAIL | Go | Kubernetes | `frontend` (edge service) |
| `bookinfo` | Istio Bookinfo | Book reviews | Istio project | Python, Ruby, Java, Node.js | Kubernetes, Istio | `productpage` (edge service) |

All ten are Apache-2.0 except PiggyMetrics (MIT). Their code is **not** copied into this repository:
`fetch.py` downloads each one at its pinned commit into `opensource/<id>/upstream/` (git-ignored), so
their code, and the demo keys and passwords some of them ship, stay in their own projects.

## How the benchmark runs them

ATG needs a running system to watch. The workspace this was built in cannot download container images,
so the running services are **stand-ins**: small services (`companies/runtime/`) with the system's real
service names, ports, operations, call graph and authentication checks, answering with masked values
(`"***"`) instead of personal data. Everything else ATG reads is the system's own: its Kubernetes or
Compose files, gateway configuration and API documents, from `upstream/`.

To run the real images instead, on a laptop with Docker: `opensource/real/README.md`
(`sh real.sh <id>` or `REAL-Windows.bat <id>`), for seven of the ten.

## Files per system

| File | Written by | What it is |
|---|---|---|
| `system.yaml` | hand, from reading the code | the pinned commit, languages, deployment files, gateway or edge, login, every service's operations and calls (with the source file each came from), and the labelled weaknesses with their evidence |
| `ground-truth.json` | `build.py` | the operations and the labels ATG and the other tools are scored against |
| `company.json`, `docker-compose.yml` | `build.py` | the stand-ins and their users |
| `atg-target.yaml`, `atg.env` | `build.py` | ATG's Phase 1 settings: which files under `upstream/` to read |
| `live-specs/` | `build.py` | the API documents a service serves at run time (Lakeside Mutual's springdoc), from the code |

## Ground truth

Each label is a weakness category on a service or an operation (`opensource/config_labels.py` and
`bench/oss_scoring.py` have the list):

- **From the deployment files, by rule** (`config_labels.py`): may run as root, privileged, no resource
  limits, mutable image tag, published outside the gateway, no NetworkPolicy, secret in the files, public
  entry without TLS, missing hardening (read-only filesystem, dropped capabilities, no privilege
  escalation), service-account token mounted. These are written by a script so they are complete and
  repeatable; they are also what the Kubernetes scanners check, so they favour those tools.
- **From the call graph**: every service-to-service call that carries no credential (A5).
- **From the API documents**: every operation the system runs that no document lists, and every service
  with no document (O1); every service that sends no traces (O2).
- **From reading the code, by hand** (`labels:` in `system.yaml`, each with the file it was seen in):
  anonymous sensitive operations, missing owner checks, exposed admin and debug functions, credentials in
  URLs, logins without rate limits, bulk data, third-party calls.

## Commands

    python opensource/fetch.py                  # download the ten systems (git, internet)
    python opensource/build.py                  # write the files above from system.yaml
    python opensource/build.py --check          # are they up to date?
    python bench/run_opensource.py --tag v1.5   # ATG on all ten (Docker), scored
    python bench/run_tools.py                   # the eight free tools on all ten, scored
    python bench/compare_tools.py               # results/opensource/comparison.md
