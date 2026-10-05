"""Add staged personal vault rotation tables."""

import sqlalchemy as sa
from alembic import op

revision = "0d8a3a6b5c44"
down_revision = "9b41f0a82c71"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "personal_vault_rotation_jobs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("vault_id", sa.Uuid(), nullable=False),
        sa.Column("initiator_id", sa.Uuid(), nullable=False),
        sa.Column("expected_key_version", sa.Integer(), nullable=False),
        sa.Column("new_key_version", sa.Integer(), nullable=False),
        sa.Column("wrapped_key", sa.JSON(), nullable=False),
        sa.Column("expires", sa.Integer(), nullable=False),
        sa.Column("created", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["initiator_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["vault_id"], ["vaults.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("vault_id"),
    )
    op.create_index(
        "ix_personal_vault_rotation_jobs_vault_id",
        "personal_vault_rotation_jobs",
        ["vault_id"],
    )
    op.create_index(
        "ix_personal_vault_rotation_jobs_initiator_id",
        "personal_vault_rotation_jobs",
        ["initiator_id"],
    )
    op.create_table(
        "personal_vault_rotation_items",
        sa.Column("rotation_id", sa.Uuid(), nullable=False),
        sa.Column("item_id", sa.Uuid(), nullable=False),
        sa.Column("expected_version", sa.Integer(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(
            ["item_id"],
            ["vault_items.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["rotation_id"],
            ["personal_vault_rotation_jobs.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("rotation_id", "item_id"),
    )


def downgrade():
    op.drop_table("personal_vault_rotation_items")
    op.drop_index(
        "ix_personal_vault_rotation_jobs_initiator_id",
        table_name="personal_vault_rotation_jobs",
    )
    op.drop_index(
        "ix_personal_vault_rotation_jobs_vault_id",
        table_name="personal_vault_rotation_jobs",
    )
    op.drop_table("personal_vault_rotation_jobs")
