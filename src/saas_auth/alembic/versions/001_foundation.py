"""001 foundation."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "001_foundation"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column(
            "display_name",
            sa.Text(),
            sa.CheckConstraint("length(display_name) BETWEEN 1 AND 200"),
            nullable=False,
        ),
        sa.Column("email", sa.Text(), nullable=False),
        sa.Column("email_verified", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column(
            "status",
            sa.Text(),
            sa.CheckConstraint("status IN ('active','suspended','deleted')"),
            nullable=False,
            server_default=sa.text("'active'"),
        ),
    )
    op.create_table(
        "external_identities",
        sa.Column("issuer", sa.Text(), nullable=False),
        sa.Column("subject", sa.Text(), nullable=False),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id"), nullable=False),
        sa.PrimaryKeyConstraint("issuer", "subject"),
    )
    op.create_index("external_identities_user_idx", "external_identities", ["user_id"])
    op.create_table(
        "tenants",
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column(
            "name", sa.Text(), sa.CheckConstraint("length(name) BETWEEN 1 AND 200"), nullable=False
        ),
        sa.Column(
            "slug",
            sa.Text(),
            sa.CheckConstraint("length(slug) <= 63 AND slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'"),
            unique=True,
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.Text(),
            sa.CheckConstraint("status IN ('active','suspended','deleting','deleted')"),
            nullable=False,
            server_default=sa.text("'active'"),
        ),
        sa.Column(
            "suspension_source",
            sa.Text(),
            sa.CheckConstraint("suspension_source IN ('none','owner','platform')"),
            nullable=False,
            server_default=sa.text("'none'"),
        ),
        sa.Column(
            "version",
            sa.BigInteger(),
            sa.CheckConstraint("version > 0"),
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.Column(
            "authorization_version",
            sa.BigInteger(),
            sa.CheckConstraint("authorization_version > 0"),
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.Column(
            "lifecycle_sequence",
            sa.BigInteger(),
            sa.CheckConstraint("lifecycle_sequence >= 0"),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.CheckConstraint("(status = 'suspended') = (suspension_source <> 'none')"),
    )
    op.create_table(
        "memberships",
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column(
            "tenant_role",
            sa.Text(),
            sa.CheckConstraint("tenant_role IN ('owner','admin','member')"),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.Text(),
            sa.CheckConstraint("status IN ('active','suspended','revoked')"),
            nullable=False,
            server_default=sa.text("'active'"),
        ),
        sa.Column(
            "version",
            sa.BigInteger(),
            sa.CheckConstraint("version > 0"),
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.PrimaryKeyConstraint("tenant_id", "user_id"),
    )
    op.create_index("memberships_user_idx", "memberships", ["user_id", "tenant_id"])
    op.create_table(
        "role_definitions",
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("app_id", sa.Uuid(), nullable=False),
        sa.Column(
            "key", sa.Text(), sa.CheckConstraint("key ~ '^[a-z][a-z0-9_.-]{0,63}$'"), nullable=False
        ),
        sa.Column(
            "description",
            sa.Text(),
            sa.CheckConstraint("length(description) <= 1000"),
            nullable=False,
        ),
        sa.Column(
            "version",
            sa.BigInteger(),
            sa.CheckConstraint("version > 0"),
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.UniqueConstraint("tenant_id", "app_id", "key"),
        sa.UniqueConstraint("tenant_id", "id"),
    )
    op.create_index("roles_page_idx", "role_definitions", ["tenant_id", "app_id", "id"])
    op.create_table(
        "role_assignments",
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.Column(
            "version",
            sa.BigInteger(),
            sa.CheckConstraint("version > 0"),
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "user_id"], ["memberships.tenant_id", "memberships.user_id"]
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "role_id"],
            ["role_definitions.tenant_id", "role_definitions.id"],
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("tenant_id", "user_id", "role_id"),
    )
    op.create_index("assignments_role_idx", "role_assignments", ["tenant_id", "role_id"])
    op.create_table(
        "service_principals",
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("issuer", sa.Text(), nullable=False),
        sa.Column("subject", sa.Text(), nullable=False),
        sa.Column("client_id", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.UniqueConstraint("issuer", "subject"),
        sa.UniqueConstraint("issuer", "client_id"),
    )
    op.create_table(
        "service_tenant_grants",
        sa.Column(
            "principal_id", sa.Uuid(), sa.ForeignKey("service_principals.id"), nullable=False
        ),
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("snapshot_read", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.PrimaryKeyConstraint("principal_id", "tenant_id"),
    )
    op.create_index("service_tenant_idx", "service_tenant_grants", ["tenant_id"])
    op.create_table(
        "service_app_grants",
        sa.Column("principal_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("app_id", sa.Uuid(), nullable=False),
        sa.Column("roles_read", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("roles_write", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.PrimaryKeyConstraint("principal_id", "tenant_id", "app_id"),
        sa.ForeignKeyConstraint(
            ["principal_id", "tenant_id"],
            ["service_tenant_grants.principal_id", "service_tenant_grants.tenant_id"],
        ),
    )
    op.create_table(
        "idempotency_records",
        sa.Column(
            "principal_id", sa.Uuid(), sa.ForeignKey("service_principals.id"), nullable=False
        ),
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("method", sa.Text(), nullable=False),
        sa.Column("route", sa.Text(), nullable=False),
        sa.Column(
            "key", sa.Text(), sa.CheckConstraint("length(key) BETWEEN 16 AND 128"), nullable=False
        ),
        sa.Column("request_hash", sa.Text(), nullable=False),
        sa.Column("status", sa.Integer(), nullable=False),
        sa.Column("body", postgresql.JSONB(), nullable=True),
        sa.Column("etag", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("principal_id", "tenant_id", "method", "route", "key"),
    )
    op.create_index("idempotency_tenant_idx", "idempotency_records", ["tenant_id"])
    op.create_index("idempotency_created_idx", "idempotency_records", ["created_at"])
    op.create_table(
        "audit_entries",
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("actor", sa.Text(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("resource_id", sa.Uuid(), nullable=False),
        sa.Column("request_id", sa.Uuid(), nullable=False),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index("audit_tenant_idx", "audit_entries", ["tenant_id", "occurred_at"])
    op.create_table(
        "outbox",
        sa.Column("event_id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column(
            "stream",
            sa.Text(),
            sa.CheckConstraint("stream IN ('lifecycle','authorization')"),
            nullable=False,
        ),
        sa.Column("sequence", sa.BigInteger(), sa.CheckConstraint("sequence > 0"), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "available_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("lease_id", sa.Uuid(), nullable=True),
        sa.Column("lease_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("tenant_id", "stream", "sequence"),
    )
    op.create_index(
        "outbox_pending_idx",
        "outbox",
        ["available_at", "created_at"],
        postgresql_where=sa.text("delivered_at IS NULL"),
    )


def downgrade() -> None:
    raise RuntimeError("Historical Auth migrations require a database restore for rollback")
