"""002 users and invitations."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "002_users_and_invitations"
down_revision = "001_foundation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column("audit_entries", "tenant_id", nullable=True)
    op.create_table(
        "auth_sessions",
        sa.Column("issuer", sa.Text(), nullable=False),
        sa.Column("sid", sa.Text(), nullable=False),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("issuer", "sid"),
    )
    op.create_index("sessions_user_idx", "auth_sessions", ["user_id"])
    op.create_table(
        "user_idempotency",
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id"), nullable=False),
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
        sa.PrimaryKeyConstraint("user_id", "method", "route", "key"),
    )
    op.create_index("user_idempotency_created_idx", "user_idempotency", ["created_at"])
    op.create_table(
        "invitations",
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("email", sa.Text(), nullable=False),
        sa.Column("token_hash", sa.Text(), unique=True, nullable=False),
        sa.Column(
            "status",
            sa.Text(),
            sa.CheckConstraint("status IN ('pending','accepted','expired','revoked')"),
            nullable=False,
            server_default=sa.text("'pending'"),
        ),
        sa.Column(
            "expires_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()+interval '7 days'"),
        ),
        sa.Column("accepted_by", sa.Uuid(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column(
            "version",
            sa.BigInteger(),
            sa.CheckConstraint("version>0"),
            nullable=False,
            server_default=sa.text("1"),
        ),
    )
    op.create_index(
        "invitations_pending_idx",
        "invitations",
        ["tenant_id", "email"],
        unique=True,
        postgresql_where=sa.text("status='pending'"),
    )
    op.create_index("invitations_page_idx", "invitations", ["tenant_id", "id"])
    op.create_index("invitations_user_idx", "invitations", ["accepted_by"])
    op.create_table(
        "private_tasks",
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column(
            "kind",
            sa.Text(),
            sa.CheckConstraint("kind IN ('invitation_mail','session_revoke')"),
            nullable=False,
        ),
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id"), nullable=True),
        sa.Column("resource_id", sa.Text(), nullable=False),
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
        sa.UniqueConstraint("kind", "resource_id"),
    )
    op.create_index(
        "private_tasks_pending_idx",
        "private_tasks",
        ["available_at", "id"],
        postgresql_where=sa.text("completed_at IS NULL"),
    )
    op.create_index("private_tasks_tenant_idx", "private_tasks", ["tenant_id"])


def downgrade() -> None:
    raise RuntimeError("Historical Auth migrations require a database restore for rollback")
