# Provider scrape targets

This file is `providers.json`, right next to this README. Prometheus rereads it every
15 seconds on its own — no restart, no reload command, no touching `prometheus.yml`.

It starts as an empty list:

```json
[]
```

When a teammate's machine joins (guides/operator_unix_guide.md Part 5) and you know their
ZeroTier `10.x` address, add one entry per machine:

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

Rules that matter:

- `9091` is fixed — every provider's metrics port, per `internal/metrics/daemon.go`. Only
  the IP before the colon changes per machine.
- That machine must have been started with `--metrics-addr=0.0.0.0:9091` (join.sh) or
  `-MetricsAddr 0.0.0.0:9091` (join.ps1). Without that flag its metrics endpoint stays
  loopback-only and this target will show red (`DOWN`) in Prometheus no matter how
  correctly you write the JSON.
- `desk` is just a label — call it whatever you want, but it's what shows up in every
  Grafana legend, so a name a human recognises (`DESK-01`, `AryanLaptop`, ...) is worth
  the extra two seconds over a bare IP.
- Valid JSON, always: a trailing comma after the last `}` in the array is the single most
  common way to break this file. If Prometheus's Targets page (`http://localhost:9090/targets`)
  stops showing `vyomanaut-providers` entirely after an edit, check for that first.
- Removing a machine (it left for the day) is just deleting its `{ ... }` block. Nothing
  else to clean up.
