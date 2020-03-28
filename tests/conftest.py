import pytest

from src.switch import Switch


@pytest.fixture
def switch():
    s = Switch()
    try:
        yield s
    finally:
        s.term()
