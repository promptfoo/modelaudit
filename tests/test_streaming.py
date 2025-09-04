from modelaudit.scanners.fickling_pickle_scanner import FicklingPickleScanner
from modelaudit.utils.streaming import can_stream_analyze


def test_can_stream_analyze_with_query_params():
    url = "https://example.com/model.pkl?token=abc"
    assert can_stream_analyze(url, FicklingPickleScanner())


def test_can_stream_analyze_rejects_non_pickle_with_query():
    url = "https://example.com/model.zip?token=abc"
    assert not can_stream_analyze(url, FicklingPickleScanner())
