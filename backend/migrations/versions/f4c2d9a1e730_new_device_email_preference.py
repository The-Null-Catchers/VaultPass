"""Add new-device email preference."""

import sqlalchemy as sa
from alembic import op

revision = "f4c2d9a1e730"
down_revision = "e2518dbce132"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "users",
        sa.Column(
            "new_device_email_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.true(),
        ),
    )
    op.alter_column("users", "new_device_email_enabled", server_default=None)


def downgrade():
    op.drop_column("users", "new_device_email_enabled")
