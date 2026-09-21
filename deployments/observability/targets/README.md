# Scrape targets

Three files live here, one per Prometheus job in `prometheus.yml`. All three work the
same way: Prometheus rereads them every 15 seconds on its own — no restart, no reload
command, no touching `prometheus.yml` itself. All three start as an empty list:

```json
[]
```

## `providers.json` — the `vyomanaut-providers` job

One entry per provider machine, added as each one joins (guides/operator_unix_guide.md
Part 5):

```json
[
  {
    "targets": ["10.35.114.94:9091"],
    "labels": { "desk": "DESK-01" }
  },
  {
    "targets": ["10.35.114.95:9091"],
    "labels": { "desk": "DESK-02" }
  }
]
```

- `9091` is fixed — every provider's metrics port, per `internal/metrics/daemon.go`. Only
  the IP before the colon changes per machine.
- That machine must have been started with `--metrics-addr=0.0.0.0:9091` (join.sh) or
  `-MetricsAddr 0.0.0.0:9091` (join.ps1). Without that flag its metrics endpoint stays
  loopback-only and this target will show red (`DOWN`) in Prometheus no matter how
  correctly you write the JSON.
- `desk` is just a label — call it whatever you want, but it's what shows up in every
  Grafana legend, so a name a human recognises (`DESK-01`, `AryanLaptop`, ...) is worth
  the extra two seconds over a bare IP.

## `microservice.json` — the `vyomanaut-microservice` job

Normally just one entry, for the coordinator itself — its own `10.x` address, which you
already have from `up.sh`'s printed `MICROSERVICE_URL` (or `$MY_IP`, known even earlier,
in operator_unix_guide.md 4.4):

```json
[
  {
    "targets": ["10.35.114.52:8080"],
    "labels": { "desk": "COORDINATOR" }
  }
]
```

- The port is whatever `--port` you gave `up.sh` (default `8080`) — the SAME port as the
  main API, not a separate one. `GET /metrics` is mounted directly on that listener
  (`internal/api/router.go`).
- The coordinator must have been started with `--expose-metrics` (`up.sh`) — off by
  default, same reasoning as the provider flag above: this endpoint has no
  authentication either.

## `hosts.json` — the `vyomanaut-hosts` job (C5, optional)

One entry per desk running `windows_exporter` (`winget install --id
Prometheus.WindowsExporter` — see that command's own notes for what it sets up).
Per-machine CPU, RAM, disk I/O, network, and uptime — the only source in this stack for
provider-side host burden, since everything else here is Vyomanaut's own application
metrics:

```json
[
  {
    "targets": ["10.35.114.94:9182"],
    "labels": { "desk": "DESK-01" }
  }
]
```

- `9182` is `windows_exporter`'s default port. Same IP as that machine's `providers.json`
  entry — it is the same physical desk, just a second port on it.
- `desk` must be the EXACT same label already used for that machine in `providers.json`.
  This is what lets a Grafana panel line up a desk's host metrics (this job) against its
  daemon metrics (the `vyomanaut-providers` job) — a typo or a renamed desk here breaks
  that join silently rather than erroring.
- Unlike `providers.json` and `microservice.json`, adding the `vyomanaut-hosts` job block
  itself to `prometheus.yml` (a one-time change, already done) needed a Prometheus
  restart to take effect — file_sd's 15-second hot-reload only watches for changes
  *within* a job Prometheus already knows about, not a brand new `job_name`. Editing
  `hosts.json` itself afterward (adding or removing a desk) does NOT need a restart,
  same as the other two files.

## Rules that apply to all three files

- Valid JSON, always: a trailing comma after the last `}` in the array is the single most
  common way to break one of these files. If Prometheus's Targets page
  (`http://localhost:9090/targets`) stops showing a job's entries entirely after an edit,
  check for that first.
- Removing a machine (it left for the day, or you're done for the demo) is just deleting
  its `{ ... }` block. Nothing else to clean up.
