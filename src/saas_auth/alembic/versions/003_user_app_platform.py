"""003 user app platform."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "003_user_app_platform"
down_revision = "002_users_and_invitations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS legacy_tenancy")
    op.execute("REVOKE ALL ON SCHEMA legacy_tenancy FROM PUBLIC")
    op.execute("ALTER TABLE tenants SET SCHEMA legacy_tenancy")
    op.execute("ALTER TABLE memberships SET SCHEMA legacy_tenancy")
    op.execute("ALTER TABLE role_definitions SET SCHEMA legacy_tenancy")
    op.execute("ALTER TABLE role_assignments SET SCHEMA legacy_tenancy")
    op.execute("ALTER TABLE service_tenant_grants SET SCHEMA legacy_tenancy")
    op.execute("ALTER TABLE service_app_grants SET SCHEMA legacy_tenancy")
    op.execute("ALTER TABLE idempotency_records SET SCHEMA legacy_tenancy")
    op.execute("ALTER TABLE audit_entries SET SCHEMA legacy_tenancy")
    op.execute("ALTER TABLE outbox SET SCHEMA legacy_tenancy")
    op.execute("ALTER TABLE invitations SET SCHEMA legacy_tenancy")
    op.execute("ALTER TABLE private_tasks SET SCHEMA legacy_tenancy")
    op.create_table(
        "user_app_grants",
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("app_id", sa.Uuid(), nullable=False),
        sa.Column(
            "roles",
            postgresql.ARRAY(sa.Text()),
            sa.CheckConstraint("cardinality(roles) BETWEEN 1 AND 100"),
            nullable=False,
        ),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column(
            "version",
            sa.BigInteger(),
            sa.CheckConstraint("version>0"),
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.PrimaryKeyConstraint("user_id", "app_id"),
    )
    op.create_index("user_app_grants_app_idx", "user_app_grants", ["app_id", "user_id"])
    op.create_table(
        "platform_audit",
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("actor", sa.Text(), nullable=False),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("resource_id", sa.Uuid(), nullable=False),
        sa.Column("request_id", sa.Uuid(), nullable=False),
        sa.Column(
            "details", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")
        ),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_table(
        "app_operations",
        sa.Column("key", sa.Text(), primary_key=True, nullable=False),
        sa.Column("hash", sa.Text(), nullable=False),
        sa.Column("body", postgresql.JSONB(), nullable=False),
    )
    op.create_table(
        "session_tasks",
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("resource_id", sa.Text(), unique=True, nullable=False),
        sa.Column("ciphertext", sa.Text(), nullable=True),
        sa.Column(
            "available_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("lease_id", sa.Uuid(), nullable=True),
        sa.Column("lease_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.execute(
        "INSERT INTO session_tasks SELECT id,resource_id,ciphertext,available_at,lease_id,lease_until,attempts,completed_at FROM legacy_tenancy.private_tasks WHERE kind='session_revoke'"
    )
    op.create_index(
        "session_tasks_pending_idx",
        "session_tasks",
        ["available_at", "id"],
        postgresql_where=sa.text("completed_at IS NULL"),
    )


def downgrade() -> None:
    raise RuntimeError("Historical Auth migrations require a database restore for rollback")
