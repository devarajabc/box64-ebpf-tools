"""Test HIST_INCREMENT macro for both old and new BCC code paths."""
import pytest

MACRO_NEW = """
#define HAS_ATOMIC_INCREMENT 1
#define HIST_INCREMENT(table, key) table.atomic_increment(key)
"""

MACRO_OLD = r"""
#define HIST_INCREMENT(table, key) \
    { u64 _zero = 0, *_val = table.lookup_or_init(&(key), &_zero); \
      if (_val) __sync_fetch_and_add(_val, 1); }
"""

BPF_TEMPLATE = """
{macro}
BPF_HISTOGRAM(test_hist, int, 64);

int test_probe(void *ctx) {{
    int bucket = 3;
    HIST_INCREMENT(test_hist, bucket);
    return 0;
}}
"""


@pytest.fixture(params=["new", "old"], ids=["atomic_increment", "fallback"])
def bpf_text(request):
    macro = MACRO_NEW if request.param == "new" else MACRO_OLD
    return BPF_TEMPLATE.format(macro=macro)


def test_hist_increment_compiles(bpf_text):
    """Both HIST_INCREMENT paths must produce BPF C that compiles."""
    try:
        from bcc import BPF
    except ImportError:
        pytest.skip("BCC not installed")
    try:
        b = BPF(text=bpf_text)
        b.cleanup()
    except Exception as e:
        if "atomic_increment" in str(e):
            pytest.skip("BCC too old for atomic_increment (expected)")
        raise


def _bcc_has_atomic_increment():
    try:
        from bcc import BPF
        BPF(text=r"""
            BPF_HISTOGRAM(t, int, 2);
            int test(void *ctx) { int k = 0; t.atomic_increment(k); return 0; }
        """)
        return True
    except Exception:
        return False


def test_detection_function():
    """_bcc_has_atomic_increment must return bool without crashing."""
    try:
        from bcc import BPF  # noqa: F401
    except ImportError:
        pytest.skip("BCC not installed")
    result = _bcc_has_atomic_increment()
    assert isinstance(result, bool)
