# scap-offenders

Analyze a sysdig `.scap` capture to find processes that dominate its event stream and estimate the
effect of adding them to the agent's `skip_events_by_process` list.

## Requirements

- Python 3.
- `run` and `collect`: Docker or Podman. The default image is
  `docker.io/sysdig/sysdig:latest`; the runtime pulls it if it is not already available locally.
- `report` and `whatif`: Python standard library. To make reports work offline, install Plotly in
  the Python environment; otherwise the report loads Plotly.js from a CDN. `--no-embed` always
  uses the CDN.

Set `CONTAINER_RUNTIME` to `docker` or `podman` to choose a runtime explicitly. Set `SYSDIG_IMAGE`
to use a different Sysdig image.

## Quick start

```
python3 offenders.py run capture.scap -o report.html
```

This writes `report.html` and the adjacent `report.json`. Open the HTML report in a browser. For a
self-contained report, install Plotly with `python3 -m pip install plotly` before running the
command.

Pass multiple captures from the same node and incident together to place them on one timeline:

```sh
python3 offenders.py run first.scap second.scap -o report.html
```

The separate commands let you reuse the collected JSON or test a skip list without rescanning:

```sh
python3 offenders.py collect capture.scap -o offenders.json
python3 offenders.py report offenders.json -o report.html
python3 offenders.py whatif offenders.json --exclude worker,cron-job
```

Treat the JSON and HTML outputs as sensitive: they contain process names and command lines from the
capture. Review them before sharing or publishing.

## What the report tells you

- Every process with the events it accounts for *including its descendants*, because
  `skip_events_by_process` suppresses a matching process and everything it spawns.
- Selection total: tick rows and read the exact share removed and the events/s before and after.
  Subtrees overlap, so row shares do not add up; the selection total does.
- `infra` rows (init, container runtimes, `su`, ...) and `shared` rows (shells, interpreters, common
  utilities) are flagged: skipping them hides a whole subtree, or every process of that name on the host.
- Names are the kernel `comm` (15 characters), exactly what the agent matches.

These are estimates for the captured window, not a security review. Skipping a process also skips
everything it spawns; use the `infra` and `shared` flags to spot names that can hide broad parts of
the event stream.

## Limits

- Ancestry is limited to `--depth` (default 12); a skipped ancestor beyond that depth is not seen.
- At most `--max-chains` ancestry chains are retained (default 5000). Events in dropped chains are
  counted, but a what-if cannot attribute them to a skip list.
- Invalid UTF-8 bytes in process names are shown as U+FFFD; that displayed name may not match the
  original name in the agent configuration.
- Multiple captures are merged by process name and laid end to end. Use captures from the same node
  and incident.
- Rates describe only the capture window and the events recorded in it.

## JSON contract (version 2)

The chisel prints one JSON object. Anything that produces the same object can feed `report`.

| field | meaning |
|---|---|
| `version` | `2` |
| `depth` | ancestor levels walked |
| `start_sec`, `end_sec` | first and last capture second (epoch) |
| `events` | total events |
| `total_sec` | events per second, dense from `start_sec` |
| `comms[]` | `{comm, subtree, self, exe, cmdline, sec[]}`, sorted by `subtree` descending; `subtree` counts an event once per distinct comm in its chain |
| `chains[]` | `{c, n, sec[]}`: distinct ancestry chains (`c` = indices into `comms`, self first, empty = event with no known process) |
| `chains_total`, `chains_listed`, `chains_dropped_events` | rare chains are dropped beyond `max_chains` and counted here |
| `segments[]` | added by `offenders.py`: `{name, start_sec, secs}` per capture, laid end to end in `total_sec` and every `sec[]` |

`sum(chains[].n) + chains_dropped_events == events`. Removed events for a skip set = chains whose `c`
intersects the set, which is why the what-if is exact without another pass over the capture.

## Tests

Run the Python test suite with:

```sh
python3 -I -m unittest discover -s tests
```

The collector tests use LuaJIT, and the report tests use Node.js. Tests for either runtime are
skipped when that runtime is not installed.
