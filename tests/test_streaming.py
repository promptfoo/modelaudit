from modelaudit.scanners.pickle_scanner import PickleScanner
from modelaudit.utils.streaming import can_stream_analyze


def test_can_stream_analyze_with_query_params():
    url = "https://example.com/model.pkl?token=abc"
    assert can_stream_analyze(url, PickleScanner())


def test_can_stream_analyze_rejects_non_pickle_with_query():
    url = "https://example.com/model.zip?token=abc"
    assert not can_stream_analyze(url, PickleScanner())
