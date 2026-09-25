"""Zero-knowledge team vaults."""

import sqlalchemy as sa
from alembic import op

revision = "d14c4c0f8b91"
down_revision = "a7d18492b650"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "teams",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=80), nullable=False),
        sa.Column("owner_id", sa.Uuid(), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("created", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_teams_owner_id"), "teams", ["owner_id"], unique=False)
    op.create_table(
        "team_members",
        sa.Column("team_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("wrapped_key", sa.String(length=1024), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False),
        sa.Column("joined", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["team_id"], ["teams.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("team_id", "user_id"),
    )
    op.create_index(op.f("ix_team_members_user_id"), "team_members", ["user_id"], unique=False)
    op.create_table(
        "team_invitations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("team_id", sa.Uuid(), nullable=False),
        sa.Column("inviter_id", sa.Uuid(), nullable=False),
        sa.Column("recipient_id", sa.Uuid(), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("wrapped_key", sa.String(length=1024), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False),
        sa.Column("expires", sa.Integer(), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False),
        sa.Column("accepted", sa.Boolean(), nullable=False),
        sa.Column("created", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["inviter_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["recipient_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["team_id"], ["teams.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_team_invitations_inviter_id"),
        "team_invitations",
        ["inviter_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_team_invitations_recipient_id"),
        "team_invitations",
        ["recipient_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_team_invitations_team_id"),
        "team_invitations",
        ["team_id"],
        unique=False,
    )
    op.create_table(
        "team_items",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("team_id", sa.Uuid(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("deleted", sa.Boolean(), nullable=False),
        sa.Column("purged", sa.Boolean(), nullable=False),
        sa.Column("updated", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["team_id"], ["teams.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_team_items_team_id"), "team_items", ["team_id"], unique=False)
    op.create_table(
        "team_item_versions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("item_id", sa.Uuid(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["item_id"], ["team_items.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("item_id", "version"),
    )
    op.create_index(
        op.f("ix_team_item_versions_item_id"),
        "team_item_versions",
        ["item_id"],
        unique=False,
    )


def downgrade():
    op.drop_index(op.f("ix_team_item_versions_item_id"), table_name="team_item_versions")
    op.drop_table("team_item_versions")
    op.drop_index(op.f("ix_team_items_team_id"), table_name="team_items")
    op.drop_table("team_items")
    op.drop_index(op.f("ix_team_invitations_team_id"), table_name="team_invitations")
    op.drop_index(op.f("ix_team_invitations_recipient_id"), table_name="team_invitations")
    op.drop_index(op.f("ix_team_invitations_inviter_id"), table_name="team_invitations")
    op.drop_table("team_invitations")
    op.drop_index(op.f("ix_team_members_user_id"), table_name="team_members")
    op.drop_table("team_members")
    op.drop_index(op.f("ix_teams_owner_id"), table_name="teams")
    op.drop_table("teams")
