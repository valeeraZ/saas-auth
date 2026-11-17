"""004 app access requests."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "004_app_access_requests"
down_revision = "003_user_app_platform"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "app_role_sets",
        sa.Column("app_id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column(
            "version",
            sa.BigInteger(),
            sa.CheckConstraint("version>0"),
            nullable=False,
            server_default=sa.text("1"),
        ),
    )
    op.create_table(
        "app_roles",
        sa.Column("app_id", sa.Uuid(), sa.ForeignKey("app_role_sets.app_id"), nullable=False),
        sa.Column(
            "key", sa.Text(), sa.CheckConstraint("key ~ '^[a-z][a-z0-9_.-]{0,63}$'"), nullable=False
        ),
        sa.Column(
            "name", sa.Text(), sa.CheckConstraint("length(name) BETWEEN 1 AND 200"), nullable=False
        ),
        sa.Column(
            "description",
            sa.Text(),
            sa.CheckConstraint("length(description)<=1000"),
            nullable=False,
            server_default=sa.text("''"),
        ),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.PrimaryKeyConstraint("app_id", "key"),
    )
    op.execute("INSERT INTO app_role_sets(app_id) SELECT DISTINCT app_id FROM user_app_grants")
    op.execute(
        "INSERT INTO app_roles(app_id,key,name)\nSELECT DISTINCT app_id,role,role FROM user_app_grants CROSS JOIN LATERAL unnest(roles) role"
    )
    op.create_table(
        "app_access_requests",
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("app_id", sa.Uuid(), sa.ForeignKey("app_role_sets.app_id"), nullable=False),
        sa.Column(
            "roles",
            postgresql.ARRAY(sa.Text()),
            sa.CheckConstraint("cardinality(roles) BETWEEN 1 AND 100"),
            nullable=False,
        ),
        sa.Column(
            "reason",
            sa.Text(),
            sa.CheckConstraint("length(reason)<=2000"),
            nullable=False,
            server_default=sa.text("''"),
        ),
        sa.Column(
            "status",
            sa.Text(),
            sa.CheckConstraint("status IN ('pending','approved','rejected')"),
            nullable=False,
            server_default=sa.text("'pending'"),
        ),
        sa.Column("reviewer", sa.Text(), nullable=True),
        sa.Column("comment", sa.Text(), sa.CheckConstraint("length(comment)<=2000"), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "(status='pending' AND reviewer IS NULL AND comment IS NULL AND reviewed_at IS NULL)\n       OR (status<>'pending' AND reviewer IS NOT NULL AND comment IS NOT NULL AND reviewed_at IS NOT NULL)"
        ),
    )
    op.create_index(
        "one_pending_app_request",
        "app_access_requests",
        ["user_id", "app_id"],
        unique=True,
        postgresql_where=sa.text("status='pending'"),
    )
    op.create_index("app_request_queue", "app_access_requests", ["status", "id"])
    op.create_index("own_app_requests", "app_access_requests", ["user_id", "app_id", "id"])


def downgrade() -> None:
    raise RuntimeError("Historical Auth migrations require a database restore for rollback")
