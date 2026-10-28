"""Regression tests for the collector, scan failure handling and the report.

The chisel tests drive chisels/top_offenders.lua under LuaJIT (the runtime sysdig uses) with mocked
event fields; they are skipped when `luajit` is not on PATH. The report test needs `node`.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import offenders  # noqa: E402

CHISEL = os.path.join(ROOT, "chisels", "top_offenders.lua")
SMOKE = os.path.join(ROOT, "tests", "report_smoke.js")
NS = 1_000_000_000


def lua_str(b):
    return '"' + "".join("\\%03d" % c for c in b) + '"'


def run_chisel(events, depth=3, max_chains=5000):
    """events: list of (seconds, [self, parent, ...] as bytes, exe, cmdline). Returns parsed JSON."""
    rows = []
    for sec, chain, exe, cmd in events:
        names = "".join(f"[{i}]={lua_str(n)}," for i, n in enumerate(chain))
        rows.append(f"{{t={sec * NS},a={{{names}}},exe={lua_str(exe)},cmd={lua_str(cmd)}}}")
    script = f"""
local out = {{}}
function print(s) out[#out + 1] = s end
chisel = {{ request_field = function(n) return n end }}
local cur
evt = {{ field = function(f)
  if f == "evt.rawtime" then return cur.t end
  if f == "proc.exe" then return cur.exe end
  if f == "proc.cmdline" then return cur.cmd end
  local j = f:match("^proc%.aname%[(%d+)%]$")
  return cur.a[tonumber(j)]
end }}
dofile("{CHISEL}")
assert(on_set_arg("depth", "{depth}") and on_set_arg("max_chains", "{max_chains}"))
assert(on_init())
for _, e in ipairs({{{",".join(rows)}}}) do cur = e; on_event() end
on_capture_end()
io.write(table.concat(out))
"""
    res = subprocess.run(["luajit", "-"], input=script.encode(), capture_output=True, check=True)
    return json.loads(res.stdout.decode("utf-8"))


@unittest.skipUnless(shutil.which("luajit"), "luajit not installed")
class Chisel(unittest.TestCase):
    def test_backward_timestamps_keep_a_consistent_timeline(self):
        d = run_chisel([(101, [b"a"], b"/a", b"a"), (100, [b"a"], b"/a", b"a")])
        self.assertEqual(d["start_sec"], 100)
        self.assertEqual(d["end_sec"], 101)
        self.assertEqual(d["total_sec"], [1, 1])
        self.assertIsNone(offenders.check(d))

    def test_control_character_in_comm_is_valid_json_and_chain_is_right(self):
        d = run_chisel([(1, [b"a\x01b", b"parent"], b"/x", b"x")])
        names = [c["comm"] for c in d["comms"]]
        self.assertIn("a\u0001b", names)
        chain = d["chains"][0]["c"]
        self.assertEqual(sorted(names[i] for i in chain), sorted(["a\u0001b", "parent"]))
        self.assertIsNone(offenders.check(d))

    def test_utf8_names_are_preserved(self):
        d = run_chisel([(1, ["café".encode()], b"/c", b"c")])
        self.assertEqual(d["comms"][0]["comm"], "café")

    def test_invalid_utf8_becomes_replacement_char_without_collapsing_valid_names(self):
        d = run_chisel([(1, [b"caf\xe9"], b"/c", b"c"), (1, ["café".encode()], b"/c", b"c")])
        names = sorted(c["comm"] for c in d["comms"])
        self.assertEqual(names, sorted(["caf�", "café"]))

    def test_events_without_a_process_sum_into_the_total(self):
        d = run_chisel([(1, [], b"", b""), (1, [], b"", b"")])
        self.assertEqual(d["events"], 2)
        self.assertEqual(d["comms"], [])
        self.assertEqual(d["chains"][0]["c"], [])
        self.assertIsNone(offenders.check(d))

    def test_ancestors_are_credited_once_per_event(self):
        d = run_chisel([(1, [b"tr", b"ksh", b"ksh", b"su"], b"/tr", b"tr")])
        by = {c["comm"]: c for c in d["comms"]}
        self.assertEqual({k: v["subtree"] for k, v in by.items()}, {"tr": 1, "ksh": 1, "su": 1})
        self.assertEqual(by["tr"]["self"], 1)
        self.assertEqual(by["ksh"]["self"], 0)

    def test_chain_cap_drops_rare_chains_and_counts_them(self):
        events = [(1, [b"a"], b"", b"")] * 3 + [(1, [b"b"], b"", b"")] + [(1, [b"c"], b"", b"")]
        d = run_chisel(events, max_chains=1)
        self.assertEqual(d["chains_listed"], 1)
        self.assertEqual(d["chains_dropped_events"], 2)
        self.assertIsNone(offenders.check(d))


def good_capture():
    return {
        "version": 2, "depth": 12, "start_sec": 100, "end_sec": 101, "events": 4,
        "total_sec": [3, 1], "chains_total": 2, "chains_listed": 2, "chains_dropped_events": 0,
        "comms": [{"comm": "a", "subtree": 4, "self": 4, "exe": "/a", "cmdline": "a", "sec": [3, 1]}],
        "chains": [{"c": [0], "n": 3, "sec": [2, 1]}, {"c": [0], "n": 1, "sec": [1, 0]}],
    }


class Scan(unittest.TestCase):
    def run_scan(self, rc, stdout):
        fake = subprocess.CompletedProcess([], rc, stdout=stdout, stderr="boom")
        with tempfile.NamedTemporaryFile(suffix=".scap") as f, \
                mock.patch.object(offenders, "runtime", return_value="docker"), \
                mock.patch.object(offenders.subprocess, "run", return_value=fake):
            return offenders.collect_one(f.name, 12, 5000)

    def test_valid_output_is_accepted(self):
        self.assertEqual(self.run_scan(0, json.dumps(good_capture()))["events"], 4)

    def test_nonzero_exit_is_rejected_even_with_valid_json(self):
        with self.assertRaises(SystemExit) as cm:
            self.run_scan(1, json.dumps(good_capture()))
        self.assertIn("rc=1", str(cm.exception))
        self.assertIn("boom", str(cm.exception))

    def test_inconsistent_output_is_rejected(self):
        bad = good_capture()
        bad["total_sec"] = []
        with self.assertRaises(SystemExit):
            self.run_scan(0, json.dumps(bad))

    def test_check_flags_each_inconsistency(self):
        for mutate in (
            lambda d: d.update(events=5),
            lambda d: d["chains"][0].update(n=9),
            lambda d: d["comms"][0].update(subtree=9),
            lambda d: d["chains"][0].update(c=[7]),
            lambda d: d.update(end_sec=105),
        ):
            d = good_capture()
            mutate(d)
            self.assertIsNotNone(offenders.check(d))


class Merge(unittest.TestCase):
    def part(self, name, comm_a, comm_b):
        sec = [2, 1]
        return {
            "name": name, "version": 2, "depth": 12, "start_sec": 10, "end_sec": 11, "events": 3,
            "total_sec": sec, "chains_total": 1, "chains_listed": 1, "chains_dropped_events": 0,
            "comms": [{"comm": comm_a, "subtree": 3, "self": 2, "exe": "", "cmdline": "", "sec": sec},
                      {"comm": comm_b, "subtree": 3, "self": 1, "exe": "", "cmdline": "", "sec": sec}],
            "chains": [{"c": [0, 1], "n": 3, "sec": sec}],
        }

    def test_captures_are_laid_end_to_end_and_comms_matched_by_name(self):
        merged = offenders.merge([self.part("x", "a", "b"), self.part("y", "b", "c")])
        self.assertEqual(merged["events"], 6)
        self.assertEqual(merged["total_sec"], [2, 1, 2, 1])
        by = {c["comm"]: c for c in merged["comms"]}
        self.assertEqual(by["b"]["subtree"], 6)
        self.assertEqual(by["b"]["sec"], [2, 1, 2, 1])
        self.assertEqual(by["a"]["sec"], [2, 1, 0, 0])
        self.assertIsNone(offenders.check(merged))
        names = [c["comm"] for c in merged["comms"]]
        removed = offenders.removed(merged, ["a"])
        self.assertEqual(removed, [2, 1, 0, 0])
        self.assertEqual(names[0], "b")


@unittest.skipUnless(shutil.which("node"), "node not installed")
class Report(unittest.TestCase):
    def timeline(self, secs, segments=None):
        data = {
            "version": 2, "depth": 12, "start_sec": 100, "end_sec": 99 + secs, "events": secs,
            "total_sec": [1] * secs, "chains_total": 1, "chains_listed": 1,
            "chains_dropped_events": 0, "comms": [],
            "chains": [{"c": [], "n": secs, "sec": [1] * secs}],
        }
        if segments is not None:
            data["segments"] = segments
        return data

    def render(self, data):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        src, out = os.path.join(d, "o.json"), os.path.join(d, "r.html")
        with open(src, "w") as fh:
            json.dump(data, fh)
        subprocess.run([sys.executable, os.path.join(ROOT, "offenders.py"), "report", src, "-o", out,
                        "--no-embed"], check=True, capture_output=True)
        return out

    def smoke(self, data, comm=None):
        args = ["node", SMOKE, self.render(data)] + ([comm] if comm else [])
        return json.loads(subprocess.run(args, check=True, capture_output=True, text=True).stdout)

    def test_selection_updates_totals_and_snippet(self):
        r = self.smoke(good_capture(), "a")
        self.assertEqual(r["pct"], "100.0%")
        self.assertIn("  - a", r["snippet"])
        self.assertEqual(r["kept"], [0, 0])

    def test_report_renders_when_no_event_has_a_known_process(self):
        data = {"version": 2, "depth": 12, "start_sec": 1, "end_sec": 1, "events": 2, "total_sec": [2],
                "chains_total": 1, "chains_listed": 1, "chains_dropped_events": 0, "comms": [],
                "chains": [{"c": [], "n": 2, "sec": [2]}]}
        r = self.smoke(data)
        self.assertEqual(r["comms"], 0)
        self.assertEqual(r["kept"], [2])
        self.assertIn("nothing to skip", r["caveat"])

    def test_chart_shows_each_tick_for_short_captures(self):
        r = self.smoke(self.timeline(3))
        self.assertEqual(r["xTickvals"], ["+0s", "+1s", "+2s"])

    def test_chart_limits_ticks_and_keeps_endpoints_for_long_captures(self):
        r = self.smoke(self.timeline(101))
        self.assertIsNotNone(r["xTickvals"])
        self.assertLessEqual(len(r["xTickvals"]), 12)
        self.assertEqual(r["xTickvals"][0], "+0s")
        self.assertEqual(r["xTickvals"][-1], "+100s")

    def test_chart_keeps_capture_boundaries_in_tick_labels(self):
        r = self.smoke(self.timeline(86, [
            {"name": "first.scap", "start_sec": 100, "secs": 30},
            {"name": "second.scap", "start_sec": 200, "secs": 34},
            {"name": "third.scap", "start_sec": 300, "secs": 22},
        ]))
        self.assertIsNotNone(r["xTickvals"])
        self.assertIn("#2 +0s", r["xTickvals"])
        self.assertIn("#2 +8s", r["xTickvals"])
        self.assertNotIn("#2 +2s", r["xTickvals"])
        self.assertNotIn("#2 +32s", r["xTickvals"])
        self.assertEqual(r["xTickvals"][-1], "#3 +21s")


if __name__ == "__main__":
    unittest.main()
