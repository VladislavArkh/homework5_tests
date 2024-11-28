import redis
import getpass

class ConnectToRedis():

	def __init__(self, 
			host='127.0.0.1',  # из Endpoint
		    	port='6379', 
		    	password='',
		    	encoding="utf-8",
		    	decode_responses=True,
		    	socket_timeout=2,
		    	retry_on_timeout=5):

		self.host=host
		self.port=port  
		self.password=password
		self.encoding=encoding
		self.decode_responses=decode_responses
		self.socket_timeout=socket_timeout
		self.retry_on_timeout=retry_on_timeout
		self.errors = []


	def connect_to_redis(self):
		connection = redis.StrictRedis(
		    host=self.host,
		    port=self.port,
		    #password=self.password,
		    encoding=self.encoding,
		    decode_responses=self.decode_responses,
		    socket_timeout=self.socket_timeout,
		    retry_on_timeout = self.retry_on_timeout
		)

		try: 
			connection.ping()
			return connection
		except Exception as e:
			self.errors.append('can`t connect to Redis' + ' ('+str(e)+')')
			return False


	def get(self, key):
		connection = self.connect_to_redis()
		if connection:
			if connection.type(key) == 'list':
				data = [item for item in connection.lrange(key, 0, -1)]
				return data
			return connection.get(key)
		raise Exception("NO CONNECTION TO REDIS") 


	def cache_get(self, key):
		connection = self.connect_to_redis()
		if connection:
			if connection.type(key) == 'list':
				data = [item for item in connection.lrange(key, 0, -1)]
				return data
			return connection.get(key)
		return None
	    

	def cache_set(self, key, value, ttl=300):
		connection = self.connect_to_redis()
		if connection != None:
			if isinstance(value, list):
				connection.lpush(key, *value)
			else:
				connection.set(key, value, ex=ttl)
		else:
			raise  Exception("NO CONNECTION TO REDIS") 


