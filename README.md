# Vyomanaut_V2

Welcome to Vyomanaut🚀✨.

This is where the `Version 2` of the ambitious and exhilarating project is being developed.

> **The Core Idea:** Distributed cloud storage network for India powered by over a billion devices.

**Note:** If you want to understand *why* it's being built this way, the thinking lives in the [Research repo](https://github.com/vyomanaut-labs/Vyomanaut_Research). If you want to see where it all started, that's [V1](https://github.com/vyomanaut-labs/Vyomanaut).

---

## What is Vyomanaut?

A distributed storage network where your files are split, encrypted, and spread across independent providers — none of whom can read your data, and all of whom get paid for storing it reliably.

No central server holds your keys. No single provider holds your file. The math guarantees reconstruction even if a third of the network disappears overnight.

V1 proved the concept. V2 is the real thing.

---

## What's different in V2?

V1 failed. In delivering the what the project targeted.

**It failed due to:**

- Lack of research in architecture
- Structural compromises made during build
- Inefficient transfer speed, storage, and peer discovery

But it paved the way for V2 which learnt from it's predecessor. Also personally it added a great skill boost so I could believe in V2.

V2 is a ground-up redesign with 41 research papers behind it, a formal data model, a complete cryptographic specification, and a build plan detailed enough to leave nothing to chance. The erasure coding, the audit system, the payment rails, the P2P layer — every piece has a governing document and every governing document has a reason.

The [Research repo](https://github.com/masamasaowl/Vyomanaut_Research) holds all of that: architecture, data model, interface contracts, API spec, ADRs, and the research summaries that shaped every major decision.

---

## Status

🏗️ **Active build**

The full build plan runs M0 → M18 across 18 milestones and ~120 sessions. Each session is atomic: it produces passing tests before the next one begins.

---

## Repository layout

```go
cmd/            → microservice, provider, client binaries
internal/       → all business logic (crypto, erasure, audit, payment, p2p, ...)
migrations/     → schema generator + SQL migrations
deployments/    → dev docker-compose, production configs, Grafana dashboards
scripts/        → CI checks, benchmarks, integration tests
runbooks/       → operational playbooks
docs/           → system design documents (authoritative source in Research repo)
```

---

## Running locally

```bash
git clone https://github.com/masamasaowl/Vyomanaut_V2.git
cd Vyomanaut_V2
docker-compose -f deployments/dev/docker-compose.yml up
```

Demo mode spins up a 5-provider network on your laptop. Full upload → audit → repair cycle in under 30 minutes.

---

## Related

- **[Vyomanaut V1](https://github.com/vyomanaut-labs/Vyomanaut)** — where this idea was born
- **[Vyomanaut Research](https://github.com/vyomanaut-labs/Vyomanaut_Research)** — the system design, ADRs, and 41 papers behind V2
