"""Staged team key rotation."""

import sqlalchemy as sa
from alembic import op

revision = "e2518dbce132"
down_revision = "d14c4c0f8b91"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "team_rotation_jobs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("team_id", sa.Uuid(), nullable=False),
        sa.Column("initiator_id", sa.Uuid(), nullable=False),
        sa.Column("target_id", sa.Uuid(), nullable=False),
        sa.Column("expected_key_version", sa.Integer(), nullable=False),
        sa.Column("new_key_version", sa.Integer(), nullable=False),
        sa.Column("expires", sa.Integer(), nullable=False),
        sa.Column("created", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["initiator_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["team_id"], ["teams.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("team_id"),
    )
    op.create_index(
        op.f("ix_team_rotation_jobs_initiator_id"),
        "team_rotation_jobs",
        ["initiator_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_team_rotation_jobs_target_id"),
        "team_rotation_jobs",
        ["target_id"],
        unique=False,
    )
    op.create_table(
        "team_rotation_members",
        sa.Column("rotation_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("wrapped_key", sa.String(length=1024), nullable=False),
        sa.ForeignKeyConstraint(["rotation_id"], ["team_rotation_jobs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("rotation_id", "user_id"),
    )
    op.create_table(
        "team_rotation_items",
        sa.Column("rotation_id", sa.Uuid(), nullable=False),
        sa.Column("item_id", sa.Uuid(), nullable=False),
        sa.Column("expected_version", sa.Integer(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["item_id"], ["team_items.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["rotation_id"], ["team_rotation_jobs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("rotation_id", "item_id"),
    )


def downgrade():
    op.drop_table("team_rotation_items")
    op.drop_table("team_rotation_members")
    op.drop_index(op.f("ix_team_rotation_jobs_target_id"), table_name="team_rotation_jobs")
    op.drop_index(op.f("ix_team_rotation_jobs_initiator_id"), table_name="team_rotation_jobs")
    op.drop_table("team_rotation_jobs")
