# Vyomanaut_V2

Welcome to Vyomanaut 🚀✨

This is where **Version 2** of the project is built.

> **The core idea:** A distributed cloud storage network for India, powered by the idle disks of ordinary computers.

---

## Links

- 🎥 **YouTube:** [youtube.com/@vyomanaut-labs](https://www.youtube.com/@vyomanaut-labs)
- 💼 **LinkedIn:** [linkedin.com/company/vyomanaut-labs](https://www.linkedin.com/company/vyomanaut-labs)
- 📄 **Demo report (VLD-001):** [Read it on Google Drive](https://drive.google.com/drive/folders/1tCk9fueHt9Np4GcJYck9dJC2D98Lb1Y6?usp=drive_link)
- 🌱 **Vyomanaut V1:** [where this idea started](https://github.com/vyomanaut-labs/Vyomanaut)

---

## What is Vyomanaut?

Vyomanaut is a network where your files are split, encrypted, and spread across many independent providers.

- No provider can read your data.
- No single provider holds your whole file.
- No central server holds your keys.
- Providers get paid for storing your data reliably.

Even if a third of the network disappears overnight, the math still lets you get your file back.

---

## What's different in V2?

V1 did not deliver what the project aimed for. It failed because of:

- too little research into the architecture
- shortcuts taken during the build
- slow transfers, wasteful storage, and weak peer discovery

V2 is a ground-up redesign that learns from those mistakes. It is built on:

- 41 research papers
- a formal data model
- a complete cryptography specification
- a detailed build plan

Every part of the system (erasure coding, audits, payments, the peer-to-peer layer) has a clear reason to exist.

---

## Status

🏗️ **Active build**

The build plan has 18 milestones (M0 to M18) and about 120 sessions. Each session is small and must pass its tests before the next one starts.

The project has two versions:

1. **DEMO:** shows the whole system working, end to end.
2. **LTS:** the long-term version, built after the demo.

### Demo results

The demo has been tested on 10 real machines (9 providers and 1 coordinator) in a campus lab. In that test:

- Files from 3 MiB to 200 MiB were encrypted, split, and stored across the providers.
- Every fragment the coordinator assigned was confirmed as stored.
- More than 73,000 storage audits ran, and no stored fragment failed an integrity check.
- The payment ledger was exact to the paisa.
- Repair started automatically when a provider left.

The full story, with numbers and limits, is in the [demo report](https://drive.google.com/drive/folders/1tCk9fueHt9Np4GcJYck9dJC2D98Lb1Y6?usp=drive_link).

---

## Repository layout

```
cmd/            → coordinator, provider, and client programs
internal/       → all the main logic (crypto, erasure coding, audit, payment, p2p, ...)
migrations/     → database schema generator and SQL migrations
deployments/    → dev docker-compose, production configs, Grafana dashboards
scripts/        → CI checks, benchmarks, integration tests
runbooks/       → operational guides
docs/           → design documents
```

---

## Running locally

```bash
git clone https://github.com/vyomanaut-labs/Vyomanaut_V2.git
cd Vyomanaut_V2
docker-compose -f deployments/dev/docker-compose.yml up
```

Demo mode starts a 5-provider network on your laptop. You can see a full upload → audit → repair cycle in under 30 minutes.

Follow the guides based on your OS to run it locally: [Guide](./guides/)

---

## Follow the project

Watch the demos on [YouTube](https://www.youtube.com/@vyomanaut-labs) and follow updates on [LinkedIn](https://www.linkedin.com/company/vyomanaut-labs).
