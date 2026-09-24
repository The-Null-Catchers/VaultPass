"""Passkey multi-factor authentication."""

import sqlalchemy as sa
from alembic import op

revision = "a7d18492b650"
down_revision = "89c2e6cf741a"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "passkey_credentials",
        sa.Column("id", sa.String(length=1024), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("public_key", sa.String(length=4096), nullable=False),
        sa.Column("sign_count", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=80), nullable=False),
        sa.Column("transports", sa.JSON(), nullable=False),
        sa.Column("aaguid", sa.String(length=64), nullable=False),
        sa.Column("device_type", sa.String(length=32), nullable=False),
        sa.Column("backed_up", sa.Boolean(), nullable=False),
        sa.Column("created", sa.Integer(), nullable=False),
        sa.Column("latest", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_passkey_credentials_user_id"),
        "passkey_credentials",
        ["user_id"],
        unique=False,
    )
    op.create_table(
        "passkey_challenges",
        sa.Column("digest", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("session_id", sa.Uuid(), nullable=True),
        sa.Column("challenge", sa.String(length=128), nullable=False),
        sa.Column("purpose", sa.String(length=16), nullable=False),
        sa.Column("name", sa.String(length=80), nullable=False),
        sa.Column("expires", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["session_id"], ["sessions.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("digest"),
    )
    op.create_index(
        op.f("ix_passkey_challenges_user_id"),
        "passkey_challenges",
        ["user_id"],
        unique=False,
    )


def downgrade():
    op.drop_index(op.f("ix_passkey_challenges_user_id"), table_name="passkey_challenges")
    op.drop_table("passkey_challenges")
    op.drop_index(op.f("ix_passkey_credentials_user_id"), table_name="passkey_credentials")
    op.drop_table("passkey_credentials")
