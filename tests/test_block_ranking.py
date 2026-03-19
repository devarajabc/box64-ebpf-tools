"""Tests for rank_items() from box64_common."""
from box64_common import rank_items


class TestRankItems:
    def test_empty(self):
        assert rank_items([]) == []

    def test_top_n_limits(self):
        items = [(i, i * 100) for i in range(50)]
        result = rank_items(items, top_n=5, sort_key_idx=1)
        assert len(result) == 5

    def test_sort_order_idx_2(self):
        """Dynarec/steam block sort by size at index 2."""
        blocks = [
            (1, 10, 100, 0, 0, 0),
            (2, 20, 300, 0, 0, 0),
            (3, 30, 200, 0, 0, 0),
        ]
        result = rank_items(blocks, top_n=3, sort_key_idx=2)
        assert result[0][2] == 300
        assert result[1][2] == 200
        assert result[2][2] == 100

    def test_sort_order_idx_1(self):
        """Memleak alloc sort by size at index 1."""
        items = [
            (1, 100, 0, 0, 0, 0, 0, 0),
            (2, 300, 0, 0, 0, 0, 0, 0),
            (3, 200, 0, 0, 0, 0, 0, 0),
        ]
        result = rank_items(items, top_n=3, sort_key_idx=1)
        assert result[0][1] == 300
        assert result[1][1] == 200
        assert result[2][1] == 100

    def test_top_n_greater_than_len(self):
        items = [(1, 100), (2, 200)]
        result = rank_items(items, top_n=50, sort_key_idx=1)
        assert len(result) == 2

    def test_default_sort_key_idx_zero(self):
        items = [(3, "c"), (1, "a"), (2, "b")]
        result = rank_items(items, top_n=3)
        assert [x[0] for x in result] == [3, 2, 1]
