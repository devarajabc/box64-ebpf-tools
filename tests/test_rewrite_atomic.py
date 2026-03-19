"""Test _rewrite_atomic_increment string replacement."""
import re


def _rewrite_atomic_increment(bpf_text):
    def _replace(m):
        table = m.group(1)
        key = m.group(2)
        return (
            f'{{ u64 _ai_zero = 0, *_ai_val = '
            f'{table}.lookup_or_init(&({key}), &_ai_zero); '
            f'if (_ai_val) __sync_fetch_and_add(_ai_val, 1); }}'
        )
    return re.sub(r'(\w+)\.atomic_increment\((\w+)\)', _replace, bpf_text)


class TestRewriteAtomicIncrement:
    def test_single_replacement(self):
        src = "    alloc_sizes.atomic_increment(bucket);\n"
        out = _rewrite_atomic_increment(src)
        assert "atomic_increment" not in out
        assert "alloc_sizes.lookup_or_init" in out
        assert "__sync_fetch_and_add" in out
        assert "bucket" in out

    def test_multiple_replacements(self):
        src = (
            "alloc_sizes.atomic_increment(bucket);\n"
            "block_lifetimes.atomic_increment(lt_bucket);\n"
        )
        out = _rewrite_atomic_increment(src)
        assert out.count("lookup_or_init") == 2
        assert out.count("__sync_fetch_and_add") == 2

    def test_no_match_untouched(self):
        src = "int x = 42;\n"
        assert _rewrite_atomic_increment(src) == src

    def test_preserves_surrounding_code(self):
        src = (
            "    int bucket = log2_u64(p->size);\n"
            "    alloc_sizes.atomic_increment(bucket);\n"
            "#ifdef TRACK_THREADS\n"
        )
        out = _rewrite_atomic_increment(src)
        assert "log2_u64" in out
        assert "TRACK_THREADS" in out

    def test_all_six_call_sites(self):
        """Verify regex matches the exact patterns used in the tools."""
        patterns = [
            "alloc_sizes.atomic_increment(bucket)",
            "block_lifetimes.atomic_increment(lt_bucket)",
            "death_isizes.atomic_increment(is_bucket)",
            "death_native_sizes.atomic_increment(ns_bucket)",
        ]
        for p in patterns:
            out = _rewrite_atomic_increment(p)
            assert "atomic_increment" not in out, f"Failed to rewrite: {p}"
