from gitsecrets.models import Severity
from gitsecrets.patterns import looks_random, shannon_entropy
from gitsecrets.report import to_html, to_json, to_text
from gitsecrets.scanner import scan_repo
from tests.conftest import AWS_KEY, GENERIC_SECRET


# ---------- entropía ----------
def test_entropy_of_repeated_char_is_zero():
    assert shannon_entropy("aaaaaaaa") == 0.0


def test_placeholder_not_flagged_as_random():
    assert looks_random("changeme") is False
    assert looks_random("aaaaaaaa") is False


def test_random_looking_value_is_flagged():
    assert looks_random(GENERIC_SECRET) is True


# ---------- escaneo de un repo real ----------
def test_finds_aws_key_in_history(demo_repo):
    result = scan_repo(demo_repo)
    aws_findings = [f for f in result.findings if f.kind == "Clave de AWS"]
    assert len(aws_findings) == 1
    f = aws_findings[0]
    assert f.severity == Severity.CRITICAL
    assert f.detection == "firma"
    assert f.file == "config.py"


def test_removed_secret_is_not_marked_as_still_in_head(demo_repo):
    result = scan_repo(demo_repo)
    f = next(x for x in result.findings if x.kind == "Clave de AWS")
    assert f.still_in_head is False  # se quitó en el commit 3


def test_generic_entropy_secret_detected(demo_repo):
    result = scan_repo(demo_repo)
    generic = [f for f in result.findings if f.detection == "entropía"]
    assert len(generic) == 1
    assert generic[0].severity == Severity.HIGH
    assert generic[0].still_in_head is True  # nunca se quitó


def test_placeholder_value_not_reported(demo_repo):
    result = scan_repo(demo_repo)
    assert not any("changeme" in f.evidence for f in result.findings)


def test_full_secret_never_appears_in_findings(demo_repo):
    result = scan_repo(demo_repo)
    for f in result.findings:
        assert AWS_KEY not in f.evidence
        assert GENERIC_SECRET not in f.evidence


def test_commits_scanned_count(demo_repo):
    result = scan_repo(demo_repo)
    assert result.commits_scanned == 4


def test_max_commits_truncates(demo_repo):
    result = scan_repo(demo_repo, max_commits=2)
    assert result.commits_scanned == 2
    assert result.truncated is True


def test_invalid_repo_path_reports_error(tmp_path):
    result = scan_repo(str(tmp_path))  # carpeta vacía, no es un repo git
    assert result.errors


# ---------- reportes: el secreto completo nunca debe aparecer ----------
def test_reports_never_contain_the_full_secret(demo_repo):
    result = scan_repo(demo_repo)
    for text in (to_text(result), to_json(result), to_html(result)):
        assert AWS_KEY not in text
        assert GENERIC_SECRET not in text
    assert "config.py" in to_text(result)
