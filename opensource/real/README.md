# Real images on your laptop

The benchmark in `results/opensource/` ran ATG on the ten systems' real deployment files and API
documents, with stand-in services answering the same operations (the workspace it was built in cannot
download container images). This kit runs seven of the systems on their **real, published images**
on a laptop with Docker, reviews them with ATG, and keeps the result so it can be scored with the same
ground truth.

The real images could not be run where this was written: the image registries were not reachable
there. The script itself was tested end to end there with Bookinfo's stand-ins in place of its images
(download skipped, start, ATG on port 18080, `load.txt` through the sidecar, scan, result file, scoring,
stop). Treat the first run of each system as a test, and send back the console output if a step stops.

## Run one system

macOS / Linux:

    sh real.sh robot-shop

Windows (double-click does not pass the name, so use a Command Prompt in the project folder):

    REAL-Windows.bat robot-shop

The script downloads the system's code at the pinned commit (if `opensource/<id>/upstream` is not there
yet), starts the system from its own images, starts ATG on port **18080** (so it does not clash with the
systems that use 8080), sends users through the ATG sidecar, scans, writes
`results/opensource/atg-real/<id>.json`, and stops both Dockers. The pages stay at
http://localhost:18080 and in `output/site` until the next review.

When you have run the ones you want, zip `results/opensource/atg-real` and send it back. Scoring it
(its time column is Phases 1-4 only, without the wait the benchmark runner includes):

    python bench/run_opensource.py --score-only --tag real    # writes results/opensource/atg-real/tables.md

## The seven systems

| System | `<id>` | Images | Users | Traces ATG receives | Notes |
|---|---|---|---|---|---|
| Stan's Robot Shop | `robot-shop` | robotshop/rs-*:2.1.0 (Docker Hub) | its own Locust load generator, 2 min, plus `load.txt` | none (Instana only) | |
| Spring PetClinic | `petclinic` | springcommunity/* (Docker Hub) | `load.txt` | Zipkin: the ATG Collector answers as `tracing-server` | GenAI service off (needs an OpenAI key). The config server reads its settings from GitHub |
| Lakeside Mutual | `lakeside-mutual` | lakesidemutual/* (Docker Hub; built from source if missing) | `load.txt` | none | the three browser front ends are off |
| Hotel Reservation | `hotel-reservation` | deathstarbench/hotel-reservation (Docker Hub); two services built from source | `load.txt` | Jaeger agent (UDP 6831): the Collector answers as `jaeger` | |
| PiggyMetrics | `piggymetrics` | sqshq/piggymetrics-* (Docker Hub) | `load.txt` | none | its passwords are random for every run and live only in that run's environment. The gateway takes host port 80 |
| Istio Bookinfo | `bookinfo` | registry.istio.io/release/examples-bookinfo-*:1.20.3 | `load.txt` | none (no Istio here) | `docker-compose.yml` made from `bookinfo.yaml` by `k8s2compose.py` |
| Online Boutique | `online-boutique` | us-central1-docker.pkg.dev/online-boutique-ci/...:v0.10.7 | its own Locust load generator, 2 min, plus `load.txt` | OTLP: tracing switched on, pointed at the ATG Collector | `docker-compose.yml` made from the release manifests by `k8s2compose.py` |

Bank of Anthos, Acme Air and FTGO are not in the kit. Bank of Anthos needs a JWT key pair and its
databases set up by hand. Acme Air and FTGO publish no images for the pinned commits, and building
them takes a full Java tool chain.

## What is different from the stand-in runs

- **East-west traffic.** The stand-ins sent their service-to-service calls through the sidecar. Real
  services do not, so ATG sees those calls only where the system sends traces (PetClinic, Hotel
  Reservation, Online Boutique). Expect fewer A5 (call without credentials) findings elsewhere.
- **Users.** `load.txt` is anonymous: it never logs in or sends a password, and its writes send `{}`.
  Endpoints behind a login show up as 401 / 403. Robot Shop and Online Boutique's own load generators do
  log in and shop, the way their authors wrote them.
- **Answers.** Real services return real demo data, so ATG's data classification has more to work with
  than the stand-ins' masked values.

## Files

| File | What it is |
|---|---|
| `<id>/kit.env` | which compose files to use, the system's own load generator, the passwords to make up, how long to wait for start-up |
| `<id>/override.yml` | added to the system's own compose file: the network name ATG joins, services left off |
| `<id>/atg.override.yml` | added to ATG's compose file: the name the Collector answers to, so the system's spans reach it |
| `<id>/docker-compose.yml` | Bookinfo and Online Boutique only: made from their Kubernetes manifests by `k8s2compose.py` |
| `<id>/load.txt` | the anonymous requests, made from `opensource/<id>/system.yaml` by `make_load.py` |
| `load.sh` | sends `load.txt` through the sidecar, from a curl container on the system's network |
| `dump.py` | run inside the ATG container: the scan's endpoints and findings as JSON |
