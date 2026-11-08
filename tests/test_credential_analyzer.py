import pytest
from doppel.core.credential_analyzer import CredentialAnalyzer


@pytest.fixture
def analyzer():
    return CredentialAnalyzer()


def test_empty_password_primary_label(analyzer):
    usernames = ["root", "ubuntu", "admin", "test", "guest", "git", "randomuser"]
    for user in usernames:
        res = analyzer.analyze(user, "")
        assert res["primary_label"] == "empty_password", f"Failed for username: {user}"
        assert res["risk_level"] == "medium"
        assert res["notes"] == "Empty password submitted — scanner testing for passwordless access."
        assert "empty_password" in res["categories"]


def test_empty_password_not_common_or_default(analyzer):
    # Accounts that previously had "" in defaults or common wordlist
    target_users = ["root", "ubuntu", "test", "guest", "git", "admin", "user"]
    for user in target_users:
        res = analyzer.analyze(user, "")
        assert res["is_default"] is False
        assert res["is_common"] is False
        assert "default_credential" not in res["categories"]
        assert "common_password" not in res["categories"]
        assert res["categories"] == ["empty_password"]


def test_empty_password_precedence_with_email(analyzer):
    # When username is an email, credential_stuffing is detected, but empty_password takes precedence
    res = analyzer.analyze("probe@scanner.org", "")
    assert res["primary_label"] == "empty_password"
    assert "empty_password" in res["categories"]
    assert "credential_stuffing" in res["categories"]
    assert res["is_default"] is False
    assert res["is_common"] is False
    assert res["notes"] == "Empty password submitted — scanner testing for passwordless access."


def test_non_empty_common_passwords_retained(analyzer):
    res = analyzer.analyze("alice", "password")
    assert res["is_common"] is True
    assert "common_password" in res["categories"]
    assert res["primary_label"] == "common_password"
    assert "appears in the common-password wordlist" in res["notes"]

    res_123456 = analyzer.analyze("alice", "123456")
    assert res_123456["is_common"] is True
    assert "common_password" in res_123456["categories"]


def test_existing_default_credentials_retained(analyzer):
    res_root = analyzer.analyze("root", "toor")
    assert res_root["is_default"] is True
    assert res_root["primary_label"] == "default_credential"
    assert res_root["risk_level"] == "critical"
    assert "well-known device or service default" in res_root["notes"]

    res_pi = analyzer.analyze("pi", "raspberry")
    assert res_pi["is_default"] is True
    assert res_pi["primary_label"] == "default_credential"

    res_admin = analyzer.analyze("admin", "admin123")
    assert res_admin["is_default"] is True
    assert res_admin["primary_label"] == "default_credential"


def test_same_as_username_retained(analyzer):
    res = analyzer.analyze("customuser", "customuser")
    assert "same_as_username" in res["categories"]
    assert res["primary_label"] == "same_as_username"
    assert res["risk_level"] == "critical"


def test_hash_pattern_retained(analyzer):
    bcrypt_hashes = [
        "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
        "$2b$12$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
        "$2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
    ]
    for h in bcrypt_hashes:
        res = analyzer.analyze("root", h)
        assert res["primary_label"] == "hash_pattern"
        assert res["hash_type"] == "bcrypt"
        assert res["risk_level"] == "high"
        assert "contains a bcrypt digest" in res["notes"]


def test_is_generic_preserves_blank_and_defaults(analyzer):
    assert analyzer.is_generic("root", "") is True
    assert analyzer.is_generic("admin", "") is True
    assert analyzer.is_generic("root", "toor") is True
    assert analyzer.is_generic("alice", "password") is True
    assert analyzer.is_generic("alice", "xK9!mQ2#vL7$zP1@") is False

