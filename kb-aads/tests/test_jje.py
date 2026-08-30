import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from consensus.jje import decide_vote, quorum_reached, CONTAIN_VOTE_THRESHOLD


# --- BUG-003: the CONTAIN vote must be reachable on the 0.0-1.0 confidence
# scale used everywhere else in the system, not the old 0-100 scale. ---

def test_decide_vote_high_confidence_contains():
    assert decide_vote(0.95) == "CONTAIN"


def test_decide_vote_exactly_at_threshold_does_not_contain():
    assert decide_vote(CONTAIN_VOTE_THRESHOLD) == "ALLOW"


def test_decide_vote_just_above_threshold_contains():
    assert decide_vote(CONTAIN_VOTE_THRESHOLD + 0.01) == "CONTAIN"


def test_decide_vote_low_confidence_allows():
    assert decide_vote(0.2) == "ALLOW"


def test_decide_vote_threshold_is_fraction_not_percent():
    # Regression guard for the exact bug: the old threshold (75.0) meant
    # every realistic 0.0-1.0 confidence value failed the ">" check, so
    # CONTAIN was unreachable. Assert the threshold itself lives on the
    # 0.0-1.0 scale, not the old 0-100 one.
    assert 0.0 < CONTAIN_VOTE_THRESHOLD <= 1.0


# --- BUG-007: quorum_reached must exclude nothing itself (callers already
# filter out failed votes) but must handle the all-failed / no-votes case
# without raising ZeroDivisionError, so one bad round doesn't crash the
# whole consensus process. ---

def test_quorum_reached_majority_contain():
    votes = [{"vote": "CONTAIN", "weight": 1.0}, {"vote": "CONTAIN", "weight": 1.0}, {"vote": "ALLOW", "weight": 1.0}]
    assert quorum_reached(votes) is True


def test_quorum_reached_majority_allow():
    votes = [{"vote": "ALLOW", "weight": 1.0}, {"vote": "ALLOW", "weight": 1.0}, {"vote": "CONTAIN", "weight": 1.0}]
    assert quorum_reached(votes) is False


def test_quorum_reached_exact_tie_does_not_contain():
    votes = [{"vote": "CONTAIN", "weight": 1.0}, {"vote": "ALLOW", "weight": 1.0}]
    assert quorum_reached(votes) is False


def test_quorum_reached_empty_votes_returns_false_not_raise():
    # Simulates every juror in the round failing (BUG-007's crashed-juror
    # scenario) — must degrade to "no quorum", not divide by zero.
    assert quorum_reached([]) is False


def test_quorum_reached_excludes_only_surviving_votes():
    # A round where 2 of 5 jurors crashed: quorum_reached only ever sees
    # the 3 that responded (coordinate_consensus filters failures out
    # before calling this) and should tally correctly among just those.
    surviving_votes = [{"vote": "CONTAIN", "weight": 1.0}, {"vote": "CONTAIN", "weight": 1.0}, {"vote": "ALLOW", "weight": 1.0}]
    assert quorum_reached(surviving_votes) is True
