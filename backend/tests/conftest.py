import os

os.environ.setdefault("DATABASE_URL", "sqlite://")
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import db
from app.main import app
from app.models import Base
from app.security import rate_limit


@pytest.fixture
def client():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )

    @event.listens_for(engine, "connect")
    def foreign_keys(connection, record):
        connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)

    def test_db():
        with factory() as session:
            yield session

    app.dependency_overrides[db] = test_db
    app.dependency_overrides[rate_limit] = lambda: None
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()
    engine.dispose()
