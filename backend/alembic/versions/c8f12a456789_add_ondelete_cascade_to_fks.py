"""Add ondelete CASCADE to foreign keys

Revision ID: c8f12a456789
Revises: 7b3a56a313b4
Create Date: 2026-07-18 19:40:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c8f12a456789'
down_revision: Union[str, Sequence[str], None] = '7b3a56a313b4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema to add ON DELETE CASCADE constraints."""
    # Drop existing FK constraints and recreate with ON DELETE CASCADE
    op.drop_constraint('iocs_incident_id_fkey', 'iocs', type_='foreignkey')
    op.create_foreign_key('iocs_incident_id_fkey', 'iocs', 'incidents', ['incident_id'], ['id'], ondelete='CASCADE')

    op.drop_constraint('incidents_scan_id_fkey', 'incidents', type_='foreignkey')
    op.create_foreign_key('incidents_scan_id_fkey', 'incidents', 'scans', ['scan_id'], ['id'], ondelete='CASCADE')

    op.drop_constraint('scans_user_id_fkey', 'scans', type_='foreignkey')
    op.create_foreign_key('scans_user_id_fkey', 'scans', 'users', ['user_id'], ['id'], ondelete='CASCADE')


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_constraint('scans_user_id_fkey', 'scans', type_='foreignkey')
    op.create_foreign_key('scans_user_id_fkey', 'scans', 'users', ['user_id'], ['id'])

    op.drop_constraint('incidents_scan_id_fkey', 'incidents', type_='foreignkey')
    op.create_foreign_key('incidents_scan_id_fkey', 'incidents', 'scans', ['scan_id'], ['id'])

    op.drop_constraint('iocs_incident_id_fkey', 'iocs', type_='foreignkey')
    op.create_foreign_key('iocs_incident_id_fkey', 'iocs', 'incidents', ['incident_id'], ['id'])
