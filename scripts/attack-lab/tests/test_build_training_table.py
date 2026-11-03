import os, sys

import pandas as pd
import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..")))
import build_training_table as btt

S = 1_000_000_000


def rows(*r):
    return pd.DataFrame(r, columns=["pid", "ppid", "recv_ns", "dim_file", "dim_network"])


def test_replay_ancestor_sees_descendant_evidence_but_not_the_reverse():
    ps = rows((201, 200, 1 * S, 80.0, 0.0),      # cat (grandchild): file evidence
              (200, 100, 2 * S, 0.0, 0.0),       # sudo
              (100, 50, 3 * S, 0.0, 15.0),       # python: the connect
              (201, 200, 4 * S, 80.0, 0.0))      # the reader again
    f, n, b = btt.replay_tree(ps)
    assert (f[2], n[2], b[2]) == (80.0, 15.0, 15.0)
    assert b[3] == 0.0 and n[3] == 0.0


def test_replay_exit_snapshot_keeps_parent_and_evidence():
    ps = rows((101, 100, 1 * S, 80.0, 0.0), (101, 0, 2 * S, 0.0, 0.0), (100, 50, 3 * S, 0.0, 15.0))
    assert btt.replay_tree(ps)[2][2] == 15.0


def test_replay_siblings_and_init_children_do_not_mix():
    ps = rows((101, 100, 1 * S, 80.0, 0.0), (102, 100, 2 * S, 0.0, 15.0),
              (301, 1, 3 * S, 80.0, 0.0), (302, 1, 4 * S, 0.0, 15.0))
    f, n, b = btt.replay_tree(ps)
    assert b[1] == 0.0 and b[3] == 0.0


def test_replay_stops_counting_a_process_after_the_ttl():
    ps = rows((101, 100, 1 * S, 80.0, 0.0), (100, 50, 200 * S, 0.0, 15.0))
    assert btt.replay_tree(ps)[2][1] == 0.0


def test_replay_reparented_pid_leaves_its_old_parent():
    ps = rows((101, 100, 1 * S, 80.0, 0.0), (101, 500, 2 * S, 0.0, 0.0), (100, 50, 3 * S, 0.0, 15.0))
    assert btt.replay_tree(ps)[0][2] == 0.0


def test_feature_columns_come_from_the_schema_only():
    assert set(btt.schema.NAMES) & btt.schema.FORBIDDEN == set()
    assert set(btt.TREE) <= set(btt.schema.NAMES)
