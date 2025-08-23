from modelaudit.scanners import IssueSeverity, PickleScanner


def test_nt_alias_detection():
    scanner = PickleScanner()
    result = scanner.scan("tests/assets/pickles/nt_alias_attack.pkl")

    assert len(result.issues) > 0
    nt_issues = [i for i in result.issues if "nt" in i.message.lower()]
    assert len(nt_issues) > 0
    assert nt_issues[0].severity == IssueSeverity.CRITICAL


def test_posix_alias_detection():
    scanner = PickleScanner()
    result = scanner.scan("tests/assets/pickles/posix_alias_attack.pkl")

    assert len(result.issues) > 0
    posix_issues = [i for i in result.issues if "posix" in i.message.lower()]
    assert len(posix_issues) > 0
    assert posix_issues[0].severity == IssueSeverity.CRITICAL
