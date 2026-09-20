from alembic import context
from sqlalchemy import create_engine, pool
from app.config import settings
from app.models import Base


def run():
    engine = create_engine(settings.database_url, poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=Base.metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


run()
