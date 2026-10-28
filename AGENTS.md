# AGENTS.md

`scap-offenders` analyzes sysdig `.scap` captures and estimates the effect of process skip lists.
User-facing commands and the JSON contract are documented in `README.md`.

## Data handling

- Captures and generated JSON/HTML can contain process names and command lines from the host. Do not
  add captures or generated reports to version control; review outputs before sharing them.
- Multiple captures should come from the same node and incident because results are merged by
  process name.

## Development

- Run the Python tests with `python3 -I -m unittest discover -s tests`.
- Collector tests require LuaJIT; report tests require Node.js. Tests for a missing runtime are
  skipped.
- When changing the collector or JSON schema, preserve
  `sum(chains[].n) + chains_dropped_events == events` and validate the result against a real capture.

## Repository map

- `offenders.py`: command-line interface and report generation.
- `chisels/top_offenders.lua`: sysdig event collector.
- `report/template.html`: interactive HTML report.
- `tests/`: Python and report smoke tests.
