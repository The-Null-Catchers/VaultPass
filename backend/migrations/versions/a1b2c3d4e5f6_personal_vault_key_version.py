"""Add personal-vault key version."""

import sqlalchemy as sa
from alembic import op

revision = "a1b2c3d4e5f6"
down_revision = "f4c2d9a1e730"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "vaults",
        sa.Column("key_version", sa.Integer(), nullable=False, server_default="1"),
    )
    op.alter_column("vaults", "key_version", server_default=None)


def downgrade():
    op.drop_column("vaults", "key_version")
