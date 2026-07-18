"""Add is_superuser to users

Revision ID: d9a23b567890
Revises: c8f12a456789
Create Date: 2026-07-18 20:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd9a23b567890'
down_revision: Union[str, Sequence[str], None] = 'c8f12a456789'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema to add is_superuser column to users table."""
    op.add_column('users', sa.Column('is_superuser', sa.Boolean(), nullable=False, server_default=sa.text('false')))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('users', 'is_superuser')
