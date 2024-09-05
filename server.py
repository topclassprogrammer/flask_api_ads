import os

from flask import Flask, Response, request, jsonify
from flask.views import MethodView
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError

from models import Session, User, Advert
from schema import CreateUser, UpdateUser, CreateAdvert, UpdateAdvert

app = Flask('adverts')
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
# Задаем секретный ключ, который будет использоваться при подписи JWT токенов
app.config["JWT_SECRET_KEY"] = os.getenv('JWT_SECRET_KEY')


def hash_password(password: str):
    """Возвращает хеш пароля"""
    password = password.encode()
    password = bcrypt.generate_password_hash(password)
    password = password.decode()
    return password


class HttpError(Exception):
    """Исключение для 400-х ошибок"""
    def __init__(self, status_code: int, error_msg: str | dict | list):
        self.status_code = status_code
        self.error_msg = error_msg


@app.errorhandler(HttpError)
def http_error_handler(err: HttpError):
    """Обработчик исключения HttpError"""
    http_response = jsonify({'status': 'error', 'message': err.error_msg})
    http_response.status_code = err.status_code
    return http_response


@app.before_request
def before_request():
    """Добавляем экземпляр сессии работы с БД
    в объект request перед его получением"""
    session = Session()
    request.session = session


@app.after_request
def after_request(http_response: Response):
    """Закрываем экземпляр сессии работы с БД перед его отправкой клиенту"""
    request.session.close()
    return http_response


class UserView(MethodView):
    """Класс совершения HTTP-методов клиентом над моделью User"""
    def get(self, user_id: int):
        """Запрос от клиента на получение информации из аккаунта"""
        user = get_user(user_id)
        return jsonify(user.json), 200

    def post(self):
        """Запрос от клиента на создание аккаунта"""
        json_data = validate_user_json(request.json, CreateUser)
        json_data['password'] = hash_password(json_data['password'])
        user = User(**json_data)
        user_id = add_user(user)
        token = create_user_token(user_id)
        user.token = token
        request.session.commit()
        return jsonify({'status': 'created', 'token': token}), 201

    @jwt_required()
    def patch(self, user_id: int):
        """Запрос от клиента на обновление информации в аккаунте"""
        json_data = validate_user_json(request.json, UpdateUser)
        check_user_owner(user_id)
        if 'password' in json_data.keys():
            json_data['password'] = hash_password(json_data['password'])
        user = get_user(user_id)
        for key, value in json_data.items():
            setattr(user, key, value)
        request.session.commit()
        return jsonify(user.json), 206

    @jwt_required()
    def delete(self, user_id: int):
        """Запрос от клиента на удаление аккаунта"""
        check_user_owner(user_id)
        user = get_user(user_id)
        request.session.delete(user)
        request.session.commit()
        return jsonify({'status': 'deleted'}), 204


def add_user(user: User):
    """Добавление пользователя в БД"""
    try:
        request.session.add(user)
        request.session.commit()
        return user.id
    except IntegrityError:
        raise HttpError(409, 'The user with this email already exists')


def get_user(user_id: int):
    """Получаем пользователя из БД"""
    user = request.session.get(User, user_id)
    if user is None:
        raise HttpError(404, 'The user has not been found')
    return user


def validate_user_json(
        json_data, schema_cls: type[CreateUser] | type[UpdateUser]
):
    """Проверяем валидность данных пользователя пришедших из запроса клиента"""
    try:
        return schema_cls(**json_data).dict(exclude_unset=True)
    except ValidationError as err:
        errors = err.errors()
        for error in errors:
            error.pop("ctx", None)
        raise HttpError(400, errors)


def check_user_owner(user_id: int):
    """Проверяем, что пользователь совершает действие со своим аккаунтом,
    а не чужим"""
    token_user_id = get_jwt_identity()
    if get_user(user_id) and token_user_id != user_id:
        raise HttpError(403, 'You cannot modify this account '
                             'as it does not belong to you')


def create_user_token(user_id: int):
    """Создание токена доступа"""
    token = create_access_token(identity=user_id, expires_delta=False)
    return token


class AdvertView(MethodView):
    """Класс совершения HTTP-методов клиентом над моделью Advert"""
    def get(self, advert_id: int):
        """Запрос от клиента на получение информации об объявлении"""
        advert = get_advert(advert_id)
        return jsonify(advert.json), 200

    @jwt_required()
    def post(self):
        """Запрос от клиента на создание объявления"""
        json_data = validate_advert_json(request.json, CreateAdvert)
        check_advert_owner()
        advert = Advert(**json_data)
        add_advert(advert)
        return jsonify({'status': 'created'}), 201

    @jwt_required()
    def patch(self, advert_id: int):
        """Запрос от клиента на обновление информации в объявлении"""
        json_data = validate_advert_json(request.json, UpdateAdvert)
        check_advert_owner(advert_id)
        advert = get_advert(advert_id)
        for key, value in json_data.items():
            setattr(advert, key, value)
        request.session.commit()
        return jsonify(advert.json), 206

    @jwt_required()
    def delete(self, advert_id: int):
        """Запрос от клиента на удаление объявления"""
        check_advert_owner(advert_id)
        advert = get_advert(advert_id)
        request.session.delete(advert)
        request.session.commit()
        return jsonify({'status': 'deleted'}), 204


def add_advert(advert: Advert):
    """Добавление объявления в БД"""
    request.session.add(advert)
    request.session.commit()


def get_advert(advert_id: int):
    """Получаем объявление из БД"""
    advert = request.session.get(Advert, advert_id)
    if advert is None:
        raise HttpError(404, 'The advert has not been found')
    return advert


def validate_advert_json(
        json_data: dict,
        schema_cls: type[CreateAdvert] | type[UpdateAdvert]
):
    """Проверяем валидность данных объявления пришедших из запроса клиента"""
    try:
        return schema_cls(**json_data).dict(exclude_unset=True)
    except ValidationError as err:
        errors = err.errors()
        for error in errors:
            error.pop("ctx", None)
        raise HttpError(400, errors)


def check_advert_owner(advert_id: int = None):
    """Проверяем, что пользователь совершает действие над своим объявлением,
    а не чужим"""
    token_user_id = get_jwt_identity()
    if request.method == 'POST':
        owner_id = request.json.get('owner')
        if owner_id and str(owner_id).isdigit() and \
                int(owner_id) != token_user_id:
            raise HttpError(403, 'You cannot create this advert '
                                 'on behalf of someone else')
    elif request.method in ['PATCH', 'DELETE'] and get_advert(advert_id):
        advert_owner_id = request.session.query(Advert).filter(
            Advert.id == advert_id).one().owner
        if advert_owner_id != token_user_id:
            raise HttpError(403, 'You cannot modify this advert '
                                 'as it does not belong to you')


if __name__ == '__main__':
    advert_view = AdvertView.as_view('advert')
    user_view = UserView.as_view('user')

    app.add_url_rule(rule='/user', view_func=user_view, methods=['POST'])
    app.add_url_rule(rule='/user/<int:user_id>', view_func=user_view,
                     methods=['GET', 'PATCH', 'DELETE'])
    app.add_url_rule(rule='/advert', view_func=advert_view, methods=['POST'])
    app.add_url_rule(rule='/advert/<int:advert_id>', view_func=advert_view,
                     methods=['GET', 'PATCH', 'DELETE'])

    app.run()
