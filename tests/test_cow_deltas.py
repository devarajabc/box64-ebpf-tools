"""Tests for compute_cow_deltas() from box64_common."""
from box64_common import compute_cow_deltas


class TestComputeCowDeltas:
    def test_zero_deltas(self):
        smaps = {"Private_Dirty": 4096, "Rss": 8192}
        delta_dirty, delta_minflt = compute_cow_deltas(smaps, 100, smaps, 100)
        assert delta_dirty == 0
        assert delta_minflt == 0

    def test_positive_delta(self):
        parent = {"Private_Dirty": 4096}
        child = {"Private_Dirty": 8192}
        delta_dirty, delta_minflt = compute_cow_deltas(parent, 10, child, 25)
        assert delta_dirty == 4096
        assert delta_minflt == 15

    def test_missing_keys_default_zero(self):
        delta_dirty, delta_minflt = compute_cow_deltas({}, 0, {}, 0)
        assert delta_dirty == 0
        assert delta_minflt == 0

    def test_minflt_subtraction(self):
        delta_dirty, delta_minflt = compute_cow_deltas(
            {"Private_Dirty": 1000}, 50,
            {"Private_Dirty": 1000}, 200)
        assert delta_dirty == 0
        assert delta_minflt == 150

    def test_negative_dirty_clamped_to_zero(self):
        parent = {"Private_Dirty": 8192}
        child = {"Private_Dirty": 4096}
        delta_dirty, delta_minflt = compute_cow_deltas(parent, 0, child, 0)
        assert delta_dirty == 0  # clamped, not -4096
