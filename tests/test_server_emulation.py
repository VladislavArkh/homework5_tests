import pytest
from unittest.mock import patch
import fakeredis
import redis


from cache import RedisStorage, Storage


@pytest.fixture
def redis_storage():
    with patch('cache.redis.StrictRedis', fakeredis.FakeStrictRedis):
        yield RedisStorage(host="localhost", port=6380, timeout=3)


@pytest.fixture
def storage(redis_storage):
    return Storage(redis_storage)


def test_set_and_get(storage):
    key = "test_key"
    value = "test_value"

    storage.cache_set(key, value)
    result = storage.cache_get(key)

    assert result == value


def test_delete(redis_storage, storage):
    key = "test_key"
    value = "test_value"

    storage.cache_set(key, value)
    result = redis_storage.delete(key)

    # Assert the deletion result
    assert result == 1

    # Try to get the value again
    result = storage.cache_get(key)

    # Assert the value is None
    assert result is None


def test_exists(redis_storage, storage):
    key = "test_key"
    value = "test_value"

    storage.cache_set(key, value)

    # Check if the key exists
    result = redis_storage.exists(key)

    # Assert the existence
    assert result == 1

    # Delete the value
    redis_storage.delete(key)

    # Check if the key exists again
    result = redis_storage.exists(key)

    # Assert the non-existence
    assert result == 0


@patch('cache.retry', lambda *args, **kwargs: lambda func: func)
def test_get_with_retry(redis_storage, storage, mocker):
    key = "test_key"
    value = "test_value"

    # Mock the Redis client to simulate retry behavior
    mock_redis = mocker.patch.object(redis_storage.db, 'get', side_effect=[redis.exceptions.TimeoutError, value])

    result = storage.cache_get(key)

    assert result == value
    assert mock_redis.call_count == 2  # Ensure the method was called twice


@patch('cache.retry', lambda *args, **kwargs: lambda func: func)
def test_get_no_exception(redis_storage, storage, mocker):
    key = "test_key"
    value = "test_value"

    mocker.patch.object(redis_storage.db, 'get', return_value=value)

    try:
        result = storage.cache_get(key)
        assert result == value
    except TimeoutError:
        pytest.fail("TimeoutError was raised unexpectedly for get")
    except ConnectionError:
        pytest.fail("ConnectionError was raised unexpectedly for get")


@patch('cache.retry', lambda *args, **kwargs: lambda func: func)
def test_set_no_exception(redis_storage, storage, mocker):
    key = "test_key"
    value = "test_value"

    mocker.patch.object(redis_storage.db, 'set', return_value=True)

    try:
        storage.cache_set(key, value)
    except TimeoutError:
        pytest.fail("TimeoutError was raised unexpectedly for set")
    except ConnectionError:
        pytest.fail("ConnectionError was raised unexpectedly for set")
