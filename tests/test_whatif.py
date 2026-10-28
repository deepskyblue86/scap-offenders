import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import offenders  # noqa: E402

# a(0) spawns b(1); c(2) is independent. Events: 6 under a->b, 3 under a only, 2 under c, 1 unknown.
DATA = {
    "version": 2, "depth": 12, "start_sec": 100, "end_sec": 101, "events": 12,
    "total_sec": [7, 5], "chains_total": 4, "chains_listed": 4, "chains_dropped_events": 0,
    "comms": [
        {"comm": "a", "subtree": 9, "self": 3, "exe": "/bin/a", "cmdline": "a", "sec": [5, 4]},
        {"comm": "b", "subtree": 6, "self": 6, "exe": "/bin/b", "cmdline": "b", "sec": [4, 2]},
        {"comm": "c", "subtree": 2, "self": 2, "exe": "/bin/c", "cmdline": "c", "sec": [1, 1]},
    ],
    "chains": [
        {"c": [1, 0], "n": 6, "sec": [4, 2]},
        {"c": [0], "n": 3, "sec": [1, 2]},
        {"c": [2], "n": 2, "sec": [1, 1]},
        {"c": [], "n": 1, "sec": [1, 0]},
    ],
}


class WhatIf(unittest.TestCase):
    def test_child_only(self):
        self.assertEqual(offenders.removed(DATA, ["b"]), [4, 2])

    def test_ancestor_covers_child_without_double_count(self):
        self.assertEqual(offenders.removed(DATA, ["a", "b"]), [5, 4])
        self.assertEqual(offenders.removed(DATA, ["a"]), [5, 4])

    def test_unknown_comm_is_rejected(self):
        with self.assertRaises(SystemExit):
            offenders.removed(DATA, ["nope"])

    def test_chains_sum_to_events(self):
        self.assertEqual(sum(c["n"] for c in DATA["chains"]), DATA["events"])


if __name__ == "__main__":
    unittest.main()
