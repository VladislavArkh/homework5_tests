#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import datetime
import logging
import hashlib
import uuid
from argparse import ArgumentParser
from http.server import HTTPServer, BaseHTTPRequestHandler

from scoring import get_score, get_interests
import cache

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


class AnyField:
    blank_values = (None, "", [], (), {})

    def __init__(self, required=False, nullable=False):
        self.required = required
        self.nullable = nullable

    def verify(self, value):
        if value is None and self.required:
            raise ValueError("Required field!")
        if value in self.blank_values and not self.nullable:
            raise ValueError("Empty field!")

    def validator(self, value):
        pass

    def fieldtype_checker(self, value):
        return value

    def clean(self, value):
        value = self.fieldtype_checker(value)
        self.verify(value)
        if value in self.blank_values:
            return value
        self.validator(value)
        return value


class CharField(AnyField):

    def fieldtype_checker(self, value):
        if value is not None and not isinstance(value, str):
            raise TypeError("String field expected!")
        return value


class ArgumentsField(AnyField):

    def fieldtype_checker(self, value):
        if value is not None and not isinstance(value, dict):
            raise TypeError("Dict field expected!")
        return value


class EmailField(CharField):

    def fieldtype_checker(self, value):
        if value is None:
            return value
        if not isinstance(value, str):
            raise TypeError("String field expected!")
        return str(value)

    def validator(self, value):
        super().validator(value)
        if "@" not in value:
            raise ValueError("Error in E-Mail format!")


class PhoneField(AnyField):

    def fieldtype_checker(self, value):
        if value is None:
            return value
        if not isinstance(value, (str, int)):
            raise TypeError("String or number field expected!")
        return str(value)

    def validator(self, value):
        try:
            int(value)
        except ValueError:
            raise ValueError("Only numbers expected!")
        if not value.startswith("7") or len(value) != 11:
            raise ValueError("Error in phone number!")


class DateField(CharField):

    def fieldtype_checker(self, value):
        value = super().fieldtype_checker(value)
        if value in self.blank_values:
            return value
        try:
            return self.time2str(value, "%d.%m.%Y")
        except ValueError:
            raise ValueError("Date like DD.MM.YYYY expected!")

    def time2str(self, value, format):
        return datetime.datetime.strptime(value, format).date()


class BirthDayField(DateField):

    def validator(self, value):
        super().validator(value)
        today = datetime.date.today()
        delta = today - value
        if delta.days / 365.25 > 70:
            raise ValueError("Date range more than 70 years!")


class GenderField(AnyField):

    def fieldtype_checker(self, value):
        if value is not None and not isinstance(value, int):
            raise TypeError("Positive number field expected!")
        return value

    def validator(self, value):
        if value not in GENDERS:
            raise ValueError("0,1 or 2 expected!")


class ClientIDsField(AnyField):

    def fieldtype_checker(self, value):
        if value is not None:
            if not isinstance(value, list) or not all(
                isinstance(v, int) for v in value
            ):
                raise TypeError("List of digits expected!")
        return value

    def validator(self, value):
        if not all(v >= 0 for v in value):
            raise ValueError("Positive number field expected!")


class BaseMeta(type):

    def __new__(cls, name, bases, nameslist):
        fields = {}
        for field_name, field in nameslist.items():
            if isinstance(field, AnyField):
                fields[field_name] = field

        new_nameslist = nameslist.copy()
        for filed_name in fields:
            del new_nameslist[filed_name]
        new_nameslist["_fields"] = fields
        return super().__new__(cls, name, bases, new_nameslist)


class Request(metaclass=BaseMeta):

    def __init__(self, data=None):
        self._errors = None
        self.data = {} if not data else data
        self.non_empty_fields = []

    @property
    def errors(self):
        if self._errors is None:
            self.validate()
        return self._errors

    def is_valid(self):
        return not self.errors

    def validate(self):
        self._errors = {}

        for name, field in self._fields.items():
            try:
                value = self.data.get(name)
                value = field.clean(value)
                setattr(self, name, value)
                if value not in field.blank_values:
                    self.non_empty_fields.append(name)
            except (TypeError, ValueError) as err:
                self._errors[name] = str(err)


class ClientsInterestsRequest(Request):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)


class OnlineScoreRequest(Request):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def validate(self):
        super().validate()
        if not self._errors:
            if (
                (self.phone and self.email)
                or (self.first_name and self.last_name)
                or (self.gender is not None and self.birthday)
            ):
                return
            self._errors["arguments"] = "Bad arguments!"


class MethodRequest(Request):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512(
            bytes(datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT, "utf-8")
        ).hexdigest()
    else:
        digest = hashlib.sha512(
            bytes(request.account + request.login + SALT, "utf-8")
        ).hexdigest()
    #print(digest) # show calculated token for debug purposes only
    return digest == request.token


class OnlineScoreWorker:

    def processing(self, request, context, store):
        data = OnlineScoreRequest(request.arguments)
        if not data.is_valid():
            return data.errors, INVALID_REQUEST

        if request.is_admin:
            score = 42
        else:
            score = get_score(
                store,
                data.phone,
                data.email,
                data.birthday,
                data.gender,
                data.first_name,
                data.last_name,
            )
        context["has"] = data.non_empty_fields
        return {"score": score}, OK


class ClientsInterestsWorker:

    def processing(self, request, context, store):
        data = ClientsInterestsRequest(request.arguments)
        if not data.is_valid():
            return data.errors, INVALID_REQUEST

        context["nclients"] = len(data.client_ids)
        response = {cid: get_interests(store, cid) for cid in data.client_ids}
        return response, OK


def method_handler(request, ctx, store):
    methods_list = {
        "online_score": OnlineScoreWorker,
        "clients_interests": ClientsInterestsWorker,
    }

    data = MethodRequest(request["body"])
    if not data.is_valid():
        return data.errors, INVALID_REQUEST
    if not check_auth(data):
        return "Forbidden", FORBIDDEN

    handler = methods_list[data.method]()
    return handler.processing(data, ctx, store)


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {"method": method_handler}
    # store = None
    store = cache.Storage(cache.RedisStorage())

    def get_request_id(self, headers):
        return headers.get("HTTP_X_REQUEST_ID", uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers["Content-Length"]))
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path](
                        {"body": request, "headers": self.headers}, context, self.store
                    )
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
        self.wfile.write(json.dumps(r).encode("utf-8"))
        return


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-p", "--port", action="store", type=int, default=8080)
    parser.add_argument("-l", "--log", action="store", default=None)
    args = parser.parse_args()
    logging.basicConfig(
        filename=args.log,
        level=logging.INFO,
        format="[%(asctime)s] %(levelname).1s %(message)s",
        datefmt="%Y.%m.%d %H:%M:%S",
    )
    server = HTTPServer(("localhost", args.port), MainHTTPHandler)
    logging.info("Starting server at %s" % args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
