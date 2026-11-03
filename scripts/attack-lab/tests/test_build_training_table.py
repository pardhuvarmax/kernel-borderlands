import os, sys

import pandas as pd
import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..")))
import build_training_table as btt

S = 1_000_000_000


def rows(*r):
    return pd.DataFrame(r, columns=["pid", "ppid", "recv_ns", "dim_file", "dim_network"])


def test_replay_siblings_share_family_evidence():
    ps = rows((101, 100, 1 * S, 80.0, 0.0),      # reader
              (102, 100, 2 * S, 0.0, 15.0))      # connector, same parent
    f, n, b = btt.replay_tree(ps)
    assert (f[0], n[0], b[0]) == (80.0, 0.0, 0.0)
    assert (f[1], n[1], b[1]) == (80.0, 15.0, 15.0)


def test_replay_unrelated_parents_and_init_children_do_not_mix():
    ps = rows((101, 100, 1 * S, 80.0, 0.0), (202, 200, 2 * S, 0.0, 15.0),
              (301, 1, 3 * S, 80.0, 0.0), (302, 1, 4 * S, 0.0, 15.0))
    f, n, b = btt.replay_tree(ps)
    assert b[1] == 0.0 and b[3] == 0.0


def test_replay_stops_counting_a_process_after_the_ttl():
    ps = rows((101, 100, 1 * S, 80.0, 0.0), (102, 100, 200 * S, 0.0, 15.0))
    assert btt.replay_tree(ps)[2][1] == 0.0


def test_replay_reparented_pid_leaves_its_old_family():
    ps = rows((101, 100, 1 * S, 80.0, 0.0), (101, 500, 2 * S, 0.0, 0.0), (103, 100, 3 * S, 0.0, 15.0))
    assert btt.replay_tree(ps)[0][2] == 0.0


def test_feature_columns_come_from_the_schema_only():
    assert set(btt.schema.NAMES) & btt.schema.FORBIDDEN == set()
    assert set(btt.TREE) <= set(btt.schema.NAMES)
