from modelaudit.scanners import IssueSeverity, PickleScanner


def test_nt_alias_detection():
    scanner = PickleScanner()
    result = scanner.scan("tests/assets/pickles/nt_alias_attack.pkl")

    assert len(result.issues) > 0, "Expected issues but found none in nt_alias_attack.pkl scan"
    nt_issues = [i for i in result.issues if "nt" in i.message.lower()]
    assert len(nt_issues) > 0, (
        f"Expected nt-related issues but found none. Issues found: {[i.message for i in result.issues]}"
    )
    assert nt_issues[0].severity == IssueSeverity.CRITICAL, (
        f"Expected CRITICAL severity for nt issue but got {nt_issues[0].severity}"
    )


def test_posix_alias_detection():
    scanner = PickleScanner()
    result = scanner.scan("tests/assets/pickles/posix_alias_attack.pkl")

    assert len(result.issues) > 0, "Expected issues but found none in posix_alias_attack.pkl scan"
    posix_issues = [i for i in result.issues if "posix" in i.message.lower()]
    assert len(posix_issues) > 0, (
        f"Expected posix-related issues but found none. Issues found: {[i.message for i in result.issues]}"
    )
    assert posix_issues[0].severity == IssueSeverity.CRITICAL, (
        f"Expected CRITICAL severity for posix issue but got {posix_issues[0].severity}"
    )
