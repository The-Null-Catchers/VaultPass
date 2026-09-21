"""Zero knowledge recovery keys."""

import sqlalchemy as sa
from alembic import op

revision = "89c2e6cf741a"
down_revision = "c83bcb1e8f9d"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "recovery_keys",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("auth_hash", sa.String(length=256), nullable=False),
        sa.Column("account_key", sa.JSON(), nullable=False),
        sa.Column("version", sa.Uuid(), nullable=False),
        sa.Column("created", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id"),
    )
    op.create_table(
        "recovery_attempts",
        sa.Column("digest", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("recovery_version", sa.Uuid(), nullable=False),
        sa.Column("expires", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("digest"),
    )
    op.create_index(
        op.f("ix_recovery_attempts_user_id"), "recovery_attempts", ["user_id"], unique=False
    )


def downgrade():
    op.drop_index(op.f("ix_recovery_attempts_user_id"), table_name="recovery_attempts")
    op.drop_table("recovery_attempts")
    op.drop_table("recovery_keys")
