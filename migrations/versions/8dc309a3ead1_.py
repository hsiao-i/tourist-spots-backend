"""empty message

Revision ID: 8dc309a3ead1
Revises: b9a5196cf7d3
Create Date: 2022-12-22 09:56:19.185355

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '8dc309a3ead1'
down_revision = 'b9a5196cf7d3'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('favorite_tourist_Spots')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('favorite_tourist_Spots',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('add_favorite_id', sa.INTEGER(), nullable=True),
    sa.Column('user_id', sa.INTEGER(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###
