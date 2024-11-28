#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import json
import datetime
import logging
import hashlib
import uuid
import re
from optparse import OptionParser
from http.server import HTTPServer, BaseHTTPRequestHandler
from scoring import *
from store import ConnectToRedis

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}


class Field(object):
    """
    Родительский класс для классов, в которых валидируются поля запроса
    """
    def __init__(self, required=False, nullable=False):
        self.required = required
        self.nullable = nullable

    # Данным методом проверяем пустые значения на то, 
    # могут ли данные значения быть пустыми, и обязательны ли они.
    # Если они пустые и могут быть таковыми - возвращаем True.
    # В каждом наследуемом классе будут проверяться значения
    # для целесообразности дальнейшей валидации значения
    def check_valid(self, value):
        if ((self.required == False and not value) 
            or (self.nullable == True and not value)):
            return False
        return True


class CharField(Field):
    """
    Валидируются поля запроса, которые должны быть строковые
    """
    def check_valid(self, value):
        cant_null = super().check_valid(value)
        if cant_null:
            if isinstance(value, str):
                return value
            raise ValueError("invalid argument type expected str")
        return value


class ArgumentsField(Field):
    """
    Валидируются поля запроса, которые должны быть dict
    """
    def check_valid(self, value):
        cant_null = super().check_valid(value)
        if cant_null:
            if cant_null and isinstance(value, dict):
                return value
            raise ValueError("'invalid argument type expected dict")
        return value


class EmailField(CharField):
    """
    Валидируются поля запроса, которые должны быть "like email"
    """
    def check_valid(self, value):
        value = super().check_valid(value)
        if (re.findall(r'[\w].*@[\w].*\.[\w].*', value) != []):
            return value
        raise ValueError('invalid argument type expected email')


class PhoneField(Field):
    """
    Валидируются поля запроса, которые должны быть "like" номер телефона
    """
    def check_valid(self, value):
        cant_null = super().check_valid(value)
        if cant_null:
            if isinstance(value, (int, str)):
                if (re.findall(r'^7\d{10}$', str(value)) != []):
                    return value
                else:
                    raise ValueError('invalid phone number')
            else:
                raise ValueError('invalid argument type expected int or str')
        return value


class DateField(Field):
    """
    Валидируются поля запроса, которые должны быть "like" дата
    """
    def check_valid(self, value):
        cant_null = super().check_valid(value)
        if cant_null:
            if (re.findall(r'^\d{2}.\d{2}.\d{4}$', str(value)) != []):
                try:
                    date = datetime.datetime.strptime(value, "%d.%m.%Y")
                    return value
                except ValueError:
                    raise ValueError("invalid data, days < 31, month < 12")
            else:
                raise ValueError('incorrect data format, expected DD.MM.YYYY')
        return value


class BirthDayField(DateField):
    """
    Валидируются поля запроса, которые должны быть "like" дата,
    также проверяется, чтобы от указанной даты прошло менее 70-ти лет
    """
    def check_valid(self, value):
        value = super().check_valid(value)
        days = str(datetime.datetime.today().date() - 
                datetime.datetime.strptime(value, "%d.%m.%Y").date()).split(' ')[0]
        if int(days) < 365*70:
            return value
        raise ValueError('max age - 70 years')


class GenderField(Field):
    """
    Валидируются поля запроса, которые должны равняться 0 или 1 или 2
    """
    def check_valid(self, value):
        cant_null = super().check_valid(value)
        if cant_null:
            if value == 0 or value == 1 or value == 2:
                return value
            else:
                raise ValueError('invalid gender, should be int (0 or 1 or 2)')
        return value


class ClientIDsField(Field):
    """
    Валидируются поля запроса, которые должны быть списком с числами
    """
    def check_valid(self, value):
        if isinstance(value, list):
            ids = []
            [ids.append(isinstance(i, int)) for i in value]
            if all(ids) and ids != [] and len(value) > 0:
                return value
            raise ValueError("invalid argument type expected int in list")
        raise ValueError("invalid argument type expected list") 


class Request_meta(type):
    """
        Записывает атрибуты являющиеся предками класса Field в field_list
    """
    def __new__(csl, name, bases, attrs):
        fields = []
        for n, v in attrs.items():
            if isinstance(v, Field):
                v.name = n
                fields.append(v)
        cls = super(Request_meta, csl).__new__(csl, name, bases, attrs)
        cls.fields = fields
        return cls


class Request(metaclass=Request_meta):
    """
    Класс - родитель классов, определяющих структуру запроса
    Проверяет на валидность все поля запроса по отдельности
    """
    def __init__(self, request):
        self.errors = []
        self.request = request

    # основной метод проверки на валидность параметров запроса
    def validate(self):
        # Проверяем тип данных запроса
        if type(self.request) != dict:
            self.errors.append(ERRORS[INVALID_REQUEST])
            return False
        # Цикл по всем данным запроса (проходит по "ключам" запроса)
        for field in self.fields:
            # Получаем значение
            value = self.request.get(field.name)
            # Проерка на существование в "ключах" запроса
            if field.required and field.name not in self.request.keys():
                error = " - {} is not defined".format(field.name)
                self.errors.append(ERRORS[INVALID_REQUEST] + ' ('+error+')')
                continue
            # Проверка на "не нулевое значение", если в запросе данное поле
            # "must have" 
            elif field.required and field.nullable == False and not value:
                error = " - {} has null value".format(field.name)
                self.errors.append(ERRORS[INVALID_REQUEST] + ' ('+error+')')
                continue
            # Если значение в запросе пришло нулевое, но оно может быть нулевым
            # создаем атрибут класса с пустым значением
            elif field.required == False and value == None:
                setattr(self, field.name, "")
            # Если первичные проверки пройдены, то создается атрибут класса
            # в значение которого записывается "провалидированное значение"
            else:
                try:
                    setattr(self, field.name, field.check_valid(value))
                # Если значение не прошло валидацию - записываем ошибку
                except Exception as e:
                    self.errors.append(ERRORS[INVALID_REQUEST] + ' ('+str(e)+')')
                    continue

    # Метод записи всех ошибок из атрибута error в строку
    def write_errors(self):
        return_str = ""
        i = 1
        for error in self.errors:
            return_str+= str(i)+'. '+error+'\n'
            i+=1
        return return_str

    # Метод валидации ошибок
    def valid(self, req=None):
        if self.errors !=[]:
            return False
        return True

class ClientsInterestsRequest(Request):
    """
    Класс, определяющий структуру аргуметов запроса 
    с методом "clients_interests"
    """
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)

    # метод генерации списка интересов
    def answer(self, store):
        return_data = {}
        for ident in self.client_ids:
            return_data[ident] = get_interests(store, ident)
        return return_data


class OnlineScoreRequest(Request):
    """
    Класс, определяющий структуру аргуметов запроса 
    с методом "online_score"
    """
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    # Метод подстчета "score" 
    def answer(self, store):
        scoring_data = {
                'phone': self.phone,
                'email': self.email,
                'birthday': self.birthday,
                'gender': self.gender,
                'first_name': self.first_name,
                'last_name': self.last_name,
            }
        
        score = get_score(store, **scoring_data)
        return {'score':score}

    # Метод проверки пар аргументов запроса на валидность
    def valid(self, req):
        valid = super().valid()
        if (req.method == 'clients_interests' or 
            (self.phone and self.email) or
            (self.first_name and self.last_name) or
            (self.gender in [0, 1, 2] and self.birthday)):
            return True
        self.errors.append(ERRORS[INVALID_REQUEST])
        return False


class MethodRequest(Request):
    """
    Класс, определяющий структуру запроса
    """
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    # Метод записывает в контекст данные
    def write_ctx(self, request_data, ctx):
        #ctx = {}
        if self.method == 'online_score':
            return_data = []
            for arg, value in self.arguments.items():
                if value or (arg == 'gender' and value == 0):
                    return_data.append(arg)
            ctx['has'] = return_data
        if self.method == 'clients_interests':
            ctx['nclients'] = len(request_data.client_ids)
        #return ctx

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


def check_auth(request):
    """
    Функция аутентификации
    """
    if request.is_admin:
        digest = hashlib.sha512(datetime.datetime.now().strftime("%Y%m%d%H").encode('utf-8') + ADMIN_SALT.encode('utf-8')).hexdigest()
    else:
        digest = hashlib.sha512(request.account.encode('utf-8') + request.login.encode('utf-8') + SALT.encode('utf-8')).hexdigest()
    if digest == request.token:
        return True
    return False


def method_handler(request, ctx, store):
    """
    Основная функция обработки запроса
    parameters: 
    - request - тело запроса
    - ctx - некий контекст
    - store - None
    """

    # Определяем два типа методов и связываем их с названием классов 
    # для обработки запроса данного метода
    methods = {
        "online_score": OnlineScoreRequest,
        "clients_interests": ClientsInterestsRequest,
    }

    # Получаем все поля запроса и валидируем их
    request = MethodRequest(request['body'])
    request.validate()
    # Проверяем ошибки при обработке запроса
    if not request.valid():
        error = request.write_errors()
        logging.error(error)
        return error, INVALID_REQUEST
    # Проверяем аутентификацию
    elif check_auth(request) == False:
        logging.error(ERRORS[FORBIDDEN])
        return ERRORS[FORBIDDEN], FORBIDDEN
    # Если проверки пройдены успешно
    else:
        # Проверяем существование указанного метода запроса
        if request.method not in methods:
            logging.error(ERRORS[INVALID_REQUEST])
            return ERRORS[INVALID_REQUEST], INVALID_REQUEST
        # Получаем все поля аргументов запроса и валидируем их
        request_data = methods[request.method](request.arguments)
        request_data.validate()
        # Проверяем ошибки при обработке аргументов запроса
        if request_data.errors != [] or request_data.valid(request) == False:
            error = request_data.write_errors()
            logging.error(error)
            return error, INVALID_REQUEST
        if request.is_admin:
            return {'score':42}, OK
        # Подсчитываем данные для ответа
        response = request_data.answer(store)
        # Создаем контекст
        request.write_ctx(request_data, ctx)
        logging.info("Success request")
        return response, OK


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = ConnectToRedis()

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST
        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)

                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(bytes(json.dumps(r), 'utf-8'))
        return


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    op.add_option("-s", "--store_password", action="store", default=None)
    op.add_option("-u", "--url", action="store", default='localhost')
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer((opts.url, opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
