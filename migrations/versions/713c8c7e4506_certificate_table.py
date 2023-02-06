"""certificate table

Revision ID: 713c8c7e4506
Revises: ee261bf64642
Create Date: 2023-01-30 15:43:08.193380

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '713c8c7e4506'
down_revision = 'ee261bf64642'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('certificate', schema=None) as batch_op:
        batch_op.add_column(sa.Column('timestamp', sa.DateTime(), nullable=True))
        batch_op.create_index(batch_op.f('ix_certificate_timestamp'), ['timestamp'], unique=False)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('certificate', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_certificate_timestamp'))
        batch_op.drop_column('timestamp')

    # ### end Alembic commands ###
