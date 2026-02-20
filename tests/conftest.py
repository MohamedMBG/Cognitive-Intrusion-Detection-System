"""Shared pytest fixtures for CNDS tests."""

import asyncio
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from src.api.models import Base


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture
async def test_db():
    """Create in-memory SQLite database for testing."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async_session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with async_session() as session:
        yield session

    await engine.dispose()


@pytest.fixture
def mock_flow_features():
    """76-element flow feature vector."""
    import numpy as np
    return np.zeros(76, dtype=np.float32)


@pytest.fixture
def mock_host_features():
    """18-element host feature vector."""
    import numpy as np
    return np.array([
        45.2, 5200.0, 115.0, 800.0, 452, 52000,
        0.02, 0.005, 12.0, 10.0, 0.9, 0.1, 0.0,
        3.0, 0.2, 3.5, 80.0, 200.0
    ], dtype=np.float32)
