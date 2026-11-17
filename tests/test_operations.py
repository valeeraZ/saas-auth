import pytest

from saas_auth.cli import main


def test_bootstrap_is_disabled_by_default(monkeypatch):
    monkeypatch.setenv("SAAS_DATABASE_URL", "postgresql://unused/unused")
    monkeypatch.delenv("SAAS_ENABLE_BOOTSTRAP", raising=False)
    monkeypatch.setattr(
        "sys.argv",
        [
            "saas-auth",
            "grant-app",
            "--user-id",
            "00000000-0000-4000-8000-000000000001",
            "--app-id",
            "00000000-0000-4000-8000-000000000002",
            "--role",
            "viewer",
            "--operation-key",
            "test-operation-key",
        ],
    )
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 2
