#!/usr/bin/env python3
"""Find the processes that dominate a sysdig capture and evaluate skip_events_by_process lists.

  offenders.py run     CAPTURE.scap [MORE.scap ...] -o report.html   # collect + report
  offenders.py collect CAPTURE.scap [MORE.scap ...] -o offenders.json
  offenders.py report  offenders.json -o report.html
  offenders.py whatif  offenders.json --exclude comm1,comm2

`collect` needs docker or podman and the sysdig/sysdig image; everything else is stdlib.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CHISEL = os.path.join(HERE, "chisels", "top_offenders.lua")
TEMPLATE = os.path.join(HERE, "report", "template.html")
IMAGE = os.environ.get("SYSDIG_IMAGE", "docker.io/sysdig/sysdig:latest")
SCHEMA_VERSION = 2


def runtime():
    forced = os.environ.get("CONTAINER_RUNTIME")
    if forced:
        if not shutil.which(forced):
            sys.exit(f"CONTAINER_RUNTIME={forced} not found on PATH")
        return forced
    for cr in ("podman", "docker"):
        if shutil.which(cr):
            return cr
    sys.exit("need podman or docker on PATH (or set CONTAINER_RUNTIME)")


def collect_one(scap, depth, max_chains):
    scap = os.path.abspath(scap)
    if not os.path.isfile(scap):
        sys.exit(f"no such capture: {scap}")
    cr = runtime()
    opts = "ro,z" if cr == "podman" else "ro"
    cmd = [cr, "run", "--rm", "--log-driver=none", "--entrypoint", "sysdig",
           "-v", f"{os.path.dirname(scap)}:/cap:{opts}",
           "-v", f"{CHISEL}:/usr/share/sysdig/chisels/top_offenders.lua:{opts}",
           IMAGE, "-r", f"/cap/{os.path.basename(scap)}",
           "-c", "top_offenders", f"{depth} {max_chains}"]
    print(f"scanning {os.path.basename(scap)} with {cr} ...", file=sys.stderr)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    label = os.path.basename(scap)
    if proc.returncode != 0:
        sys.exit(f"{label}: sysdig exited with rc={proc.returncode}:\n{proc.stderr[-800:]}")
    try:
        data = json.loads(proc.stdout)
    except ValueError:
        sys.exit(f"{label}: sysdig printed no JSON:\n{proc.stderr[-800:]}")
    problem = check(data)
    if problem:
        sys.exit(f"{label}: unusable output ({problem}):\n{proc.stderr[-800:]}")
    data["name"] = os.path.basename(scap)
    return data


def merge(parts):
    """Concatenate captures on one timeline; comms are matched by name."""
    if len(parts) == 1:
        d = dict(parts[0])
        d["segments"] = [{"name": d["name"], "start_sec": d["start_sec"], "secs": len(d["total_sec"])}]
        return d
    names, info = [], {}
    for p in parts:
        for c in p["comms"]:
            if c["comm"] not in info:
                names.append(c["comm"])
                info[c["comm"]] = {"comm": c["comm"], "subtree": 0, "self": 0,
                                   "exe": c["exe"], "cmdline": c["cmdline"]}
    secs = [len(p["total_sec"]) for p in parts]
    offs = [sum(secs[:i]) for i in range(len(parts))]
    total = sum(secs)
    for n in names:
        info[n]["sec"] = [0] * total
    chains, total_sec = {}, [0] * total
    for p, off in zip(parts, offs):
        for i, v in enumerate(p["total_sec"]):
            total_sec[off + i] = v
        for c in p["comms"]:
            m = info[c["comm"]]
            m["subtree"] += c["subtree"]
            m["self"] += c["self"]
            for i, v in enumerate(c["sec"]):
                m["sec"][off + i] += v
        for ch in p["chains"]:
            key = tuple(sorted(p["comms"][i]["comm"] for i in ch["c"]))
            slot = chains.setdefault(key, {"n": 0, "sec": [0] * total})
            slot["n"] += ch["n"]
            for i, v in enumerate(ch["sec"]):
                slot["sec"][off + i] += v
    order = sorted(names, key=lambda n: (-info[n]["subtree"], n))
    index = {n: i for i, n in enumerate(order)}
    out_chains = [{"c": [index[n] for n in key], "n": v["n"], "sec": v["sec"]}
                  for key, v in sorted(chains.items(), key=lambda kv: -kv[1]["n"])]
    return {
        "version": SCHEMA_VERSION,
        "depth": parts[0]["depth"],
        "start_sec": parts[0]["start_sec"],
        "end_sec": parts[-1]["end_sec"],
        "events": sum(p["events"] for p in parts),
        "total_sec": total_sec,
        "chains_total": len(out_chains),
        "chains_listed": len(out_chains),
        "chains_dropped_events": sum(p["chains_dropped_events"] for p in parts),
        "comms": [info[n] for n in order],
        "chains": out_chains,
        "segments": [{"name": p["name"], "start_sec": p["start_sec"], "secs": n}
                     for p, n in zip(parts, secs)],
    }


def collect(scaps, out, depth, max_chains):
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=min(len(scaps), 4)) as ex:
        parts = list(ex.map(lambda f: collect_one(f, depth, max_chains), scaps))
    data = merge(parts)
    with open(out, "w") as fh:
        json.dump(data, fh, separators=(",", ":"))
    print(f"wrote {out}: {data['events']:,} events in {len(parts)} capture(s), "
          f"{len(data['comms'])} comms, {data['chains_listed']} chains", file=sys.stderr)


def check(data):
    """Return a description of the first inconsistency in a collector JSON, or None."""
    if not isinstance(data, dict) or data.get("version") != SCHEMA_VERSION:
        return "unsupported version"
    events = data.get("events")
    if not events:
        return "no events"
    total_sec = data["total_sec"]
    segments = data.get("segments")
    expected = sum(g["secs"] for g in segments) if segments else data["end_sec"] - data["start_sec"] + 1
    if not total_sec or len(total_sec) != expected:
        return "timeline length does not match the capture window"
    if sum(total_sec) != events:
        return "per-second totals do not sum to events"
    if sum(c["n"] for c in data["chains"]) + data["chains_dropped_events"] != events:
        return "chains do not sum to events"
    comms = data["comms"]
    for c in comms:
        if len(c["sec"]) != len(total_sec) or sum(c["sec"]) != c["subtree"]:
            return f"inconsistent series for {c['comm']!r}"
    for ch in data["chains"]:
        if len(ch["sec"]) != len(total_sec) or any(not 0 <= i < len(comms) for i in ch["c"]):
            return "malformed chain"
    return None


def load(path):
    try:
        with open(path) as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        sys.exit(f"cannot read {path}: {exc}")
    problem = check(data)
    if problem:
        sys.exit(f"{path}: {problem}")
    return data


def removed(data, skip):
    names = [c["comm"] for c in data["comms"]]
    missing = [s for s in skip if s not in names]
    if missing:
        sys.exit(f"not in capture: {', '.join(missing)}")
    idx = {names.index(s) for s in skip}
    n = len(data["total_sec"])
    per_sec = [0] * n
    for ch in data["chains"]:
        if idx.intersection(ch["c"]):
            for i, v in enumerate(ch["sec"]):
                per_sec[i] += v
    return per_sec


def whatif(data, skip):
    per_sec = removed(data, skip)
    secs = len(data["total_sec"])
    gone, total = sum(per_sec), data["events"]
    print(f"capture: {total:,} events over {secs}s ({total / secs:,.0f}/s)")
    print(f"skipping {', '.join(skip)}")
    print(f"  removes {gone:,} events ({100 * gone / total:.1f}%) -> {(total - gone) / secs:,.0f}/s remain")
    if data["chains_dropped_events"]:
        print(f"  note: {data['chains_dropped_events']:,} events sit in dropped rare chains (not counted as removed)")
    print("\nskip_events_by_process:")
    for s in skip:
        print(f"  - {s}")


def report(data_path, out, embed_plotly):
    data = load(data_path)
    with open(TEMPLATE) as fh:
        html = fh.read()
    if embed_plotly:
        try:
            import plotly.offline as po
            plotly_tag = f"<script>{po.get_plotlyjs()}</script>"
        except ImportError:
            print("plotly not installed: using the CDN script tag (report needs internet)", file=sys.stderr)
            embed_plotly = False
    if not embed_plotly:
        plotly_tag = '<script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>'
    payload = json.dumps(data, separators=(",", ":")).replace("</", "<\\/")
    html = html.replace("__PLOTLY__", plotly_tag).replace("__DATA__", payload)
    with open(out, "w") as fh:
        fh.write(html)
    print(f"wrote {out} ({os.path.getsize(out) / 1e6:.1f} MB)", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("collect")
    p.add_argument("scaps", nargs="+", metavar="scap")
    p.add_argument("-o", "--out", required=True)
    p.add_argument("--depth", type=int, default=12, help="ancestor levels to walk")
    p.add_argument("--max-chains", type=int, default=5000)

    p = sub.add_parser("report")
    p.add_argument("json")
    p.add_argument("-o", "--out", required=True)
    p.add_argument("--no-embed", action="store_true", help="load plotly.js from a CDN")

    p = sub.add_parser("whatif")
    p.add_argument("json")
    p.add_argument("--exclude", required=True, help="comma-separated comm names")

    p = sub.add_parser("run")
    p.add_argument("scaps", nargs="+", metavar="scap")
    p.add_argument("-o", "--out", required=True, help="report HTML path")
    p.add_argument("--depth", type=int, default=12)
    p.add_argument("--max-chains", type=int, default=5000)
    p.add_argument("--no-embed", action="store_true")

    a = ap.parse_args()
    if a.cmd == "collect":
        collect(a.scaps, a.out, a.depth, a.max_chains)
    elif a.cmd == "report":
        report(a.json, a.out, not a.no_embed)
    elif a.cmd == "whatif":
        whatif(load(a.json), [s for s in a.exclude.split(",") if s])
    else:
        js = os.path.splitext(a.out)[0] + ".json"
        collect(a.scaps, js, a.depth, a.max_chains)
        report(js, a.out, not a.no_embed)


if __name__ == "__main__":
    main()
