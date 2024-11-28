from api import *
import unittest  
import functools
import store
import scoring

def cases(cases):
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args):
            for c in cases:
                new_args = args + (c if isinstance(c, tuple) else (c,))
                f(*new_args)
        return wrapper
    return decorator


class TestClasses(unittest.TestCase):

    @cases([
        {"required": False, "nullable": False, "value": ""},
        {"required": False, "nullable": True, "value": ""},
        {"required": True, "nullable": True, "value": ""}
    ])
    def test_field_false(self, test_case):
    	obj = Field(required=test_case['required'], nullable=test_case['nullable'])
    	self.assertEqual(obj.check_valid(test_case['value']), False)


    @cases([
        {"required": False, "nullable": True, "value": "123"},
        {"required": False, "nullable": True, "value": 123},
        {"required": False, "nullable": True, "value": "acb"}
    ])
    def test_field_true(self, test_case):
    	obj = Field(required=test_case['required'], nullable=test_case['nullable'])
    	self.assertEqual(obj.check_valid(test_case['value']), True)

    @cases([
        {"value": "value"},
        {"value": None},
    ])
    def test_char_field_true(self, test_case):
    	obj = CharField()
    	self.assertEqual(obj.check_valid(test_case['value']), test_case['value'])

    @cases([
        {"value": 123},
        {"value": True},
    ])
    def test_char_field_error(self, test_case):
    	obj = CharField()
    	self.assertRaises(ValueError, obj.check_valid, test_case['value'])

    @cases([
        {"value": {"phone": "79161341107", "email": "lipoctsev@otus.ru"}},
        {"value": {"gender": 1, "birthday": "01.01.1998", "first_name": "a", "last_name": "b"}},
        {"value": {"first_name": "c", "last_name": "d"}},
    ])
    def test_arguments_field_true(self, test_case):
    	obj = ArgumentsField()
    	self.assertEqual(obj.check_valid(test_case['value']), test_case['value'])

    @cases([
        {"value": "abc"},
        {"value": 123},
        {"value": [1,2,'abc']},
    ])
    def test_arguments_field_error(self, test_case):
    	obj = ArgumentsField()
    	self.assertRaises(ValueError, obj.check_valid, test_case['value'])

    @cases([
        {"value": "lipoctsev@otus.ru"},
        {"value": "lipoctsev123@otus.ru"},
        {"value": "lipoctsev_ivan@otus.ru"},
    ])
    def test_email_field_true(self, test_case):
    	obj = EmailField()
    	self.assertEqual(obj.check_valid(test_case['value']), test_case['value'])


    @cases([
        {"value": "lipoctsevotus.ru"},
        {"value": "lipoctsev@otus"},
        {"value": "lipoctsev_ivan"},
    ])
    def test_email_field_error(self, test_case):
    	obj = EmailField()
    	self.assertRaises(ValueError, obj.check_valid, test_case['value'])


    @cases([
        {"value": "79161341107"},
        {"value": 79161341107}
    ])
    def test_phone_field_true(self, test_case):
    	obj = PhoneField()
    	self.assertEqual(obj.check_valid(test_case['value']), test_case['value'])


    @cases([
        {"value": "+79161341107"},
        {"value": "791613411"},
        {"value": 791613411}
    ])
    def test_phone_field_error(self, test_case):
    	obj = PhoneField()
    	self.assertRaises(ValueError, obj.check_valid, test_case['value'])


    @cases([
        {"value": "02.06.1990"}
    ])
    def test_date_field_true(self, test_case):
    	obj = DateField()
    	self.assertEqual(obj.check_valid(test_case['value']), test_case['value'])


    @cases([
        {"value": "02.13.1990"},
        {"value": "02.06.199"},
        {"value": "not_date"}
    ])
    def test_date_field_error(self, test_case):
    	obj = DateField()
    	self.assertRaises(ValueError, obj.check_valid, test_case['value'])


    @cases([
        {"value": 1},
        {"value": 2}
    ])
    def test_gender_field_true(self, test_case):
    	obj = GenderField()
    	self.assertEqual(obj.check_valid(test_case['value']), test_case['value'])


    @cases([
        {"value": "2"},
        {"value": 10},
    ])
    def test_gender_field_error(self, test_case):
    	obj = GenderField()
    	self.assertRaises(ValueError, obj.check_valid, test_case['value'])


    @cases([
        {"value": [1,2,3]},
        {"value": [1,2]}
    ])
    def test_clientid_field_true(self, test_case):
    	obj = ClientIDsField()
    	self.assertEqual(obj.check_valid(test_case['value']), test_case['value'])


    @cases([
        {"value": []},
        {"value": '1,2'},
        {"value": ['1','2']},
    ])
    def test_clientid_field_error(self, test_case):
    	obj = ClientIDsField()
    	self.assertRaises(ValueError, obj.check_valid, test_case['value'])


    def test_store_set_get(self):
        con = ConnectToRedis()
        con.cache_set('test1', '1')
        self.assertEqual(con.cache_get('test1'), '1')
        con.cache_set('test3', ['1', '2', '3'])
        self.assertEqual(con.cache_get('test3'), ['3', '2', '1'])

   
    def test_score(self):
        store = ConnectToRedis()
        score = get_score(store, phone="79175002040", email="stupnikov@otus.ru")
        self.assertEqual(float(score), 3.0)
        score = get_score(store, phone="79175002040", email="stupnikov@otus.ru", 
                                gender=1, birthday="01.01.2000", 
                                first_name="a", last_name="b")
        self.assertEqual(float(score), 5.0)
        store = ConnectToRedis(host='8.8.8.8')
        score = get_score(store, phone="79175002040", email="stupnikov@otus.ru", 
                                gender=1, birthday="01.01.2000", 
                                first_name="a", last_name="b")
        self.assertEqual(float(score), 5.0)


    def test_get_interests(self):
        store = ConnectToRedis()
        interests = ['codding', 'swimming']
        store.cache_set('i:4', interests)
        cid = '4'
        interests.reverse()
        self.assertEqual(get_interests(store, cid), interests)

if __name__ == "__main__":
    unittest.main()
