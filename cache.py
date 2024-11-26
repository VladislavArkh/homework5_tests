import redis
import functools
import time


# https://stackoverflow.com/questions/50246304/using-python-decorators-to-retry-request
def retry(exceptions, attempts=3, backoff_factor=0.3):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(attempts):
                try:
                    return func(*args, **kwargs)
                except exceptions:
                    delay = backoff_factor * (2 ** attempt)
                    time.sleep(delay)
        return wrapper
    return decorator


class RedisStorage:

    def __init__(self, host="localhost", port=6380, timeout=3):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.db = redis.StrictRedis(
            host=self.host,
            port=self.port,
            db=0,
            socket_timeout=self.timeout,
            socket_connect_timeout=self.timeout,
            decode_responses=True
        )

    def get(self, key):
        """
        Get value from Redis
        :param key: record key to extract
        :return: key or exception for timeout or connection errors
        """
        try:
            return self.db.get(key)
        except redis.exceptions.TimeoutError:
            raise TimeoutError
        except redis.exceptions.ConnectionError:
            raise ConnectionError

    def set(self, key, value, expires=None):
        """
        Set value to Redis
        :param key: record key to set
        :param value: record value to set
        :param expires: time of life
        :return:
        """
        try:
            return self.db.set(key, value, ex=expires)
        except redis.exceptions.TimeoutError:
            raise TimeoutError
        except redis.exceptions.ConnectionError:
            raise ConnectionError

    def delete(self, key):
        """
        Delete a key from Redis cache.
        :param key: record key to delete
        :return: result of operation
        """
        result = self.db.delete(key)
        return result

    def exists(self, key):
        """
        Check if a key exists in Redis cache.
        :param key: record key to check of existence
        :return: exists or not
        """
        exists = self.db.exists(key)
        return exists


class Storage:
    MAX_RETRIES = 3
    BACKOFF_FACTOR = 0.3

    def __init__(self, storage):
        self.storage = storage

    def get(self, key):
        """
        Gets persistent data from Redis (like a store)
        :param key: key of data content
        :return: data with particular key
        """

        return self.storage.get(key)

    @retry((TimeoutError, ConnectionError), MAX_RETRIES, BACKOFF_FACTOR)
    def cache_get(self, key):
        """
        Gets cached data from Redis (Redis like a cache)
        Use @retry decorator for Redis access attempts
        :param key: key of cached data
        :return: cached data with particular key
        """
        return self.storage.get(key)

    @retry((TimeoutError, ConnectionError), MAX_RETRIES, BACKOFF_FACTOR)
    def cache_set(self, key, value, expires=None):
        """
        Sets data to Redis cache
        Use @retry decorator for Redis access attempts
        :param key: key of cached data
        :param value: cashed data to set
        :param expires: time of life
        :return:
        """
        return self.storage.set(key, value, expires=expires)
