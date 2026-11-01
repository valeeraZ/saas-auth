from pathlib import Path

import pytest

from saas_auth.cli import main
from saas_auth.db import migrate


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


def test_migration_checksum_detects_edits(database_url, tmp_path):
    original = Path("src/saas_auth/migrations/001_foundation.sql").read_text()
    (tmp_path / "001_foundation.sql").write_text(original + "\n-- changed\n")
    with pytest.raises(RuntimeError, match="checksum"):
        migrate(database_url, tmp_path)
