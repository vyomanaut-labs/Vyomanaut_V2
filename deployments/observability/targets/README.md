# Scrape targets

Two files live here, one per Prometheus job in `prometheus.yml`. Both work the same way:
Prometheus rereads them every 15 seconds on its own — no restart, no reload command, no
touching `prometheus.yml` itself. Both start as an empty list:

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

## Rules that apply to both files

- Valid JSON, always: a trailing comma after the last `}` in the array is the single most
  common way to break one of these files. If Prometheus's Targets page
  (`http://localhost:9090/targets`) stops showing a job's entries entirely after an edit,
  check for that first.
- Removing a machine (it left for the day, or you're done for the demo) is just deleting
  its `{ ... }` block. Nothing else to clean up.
