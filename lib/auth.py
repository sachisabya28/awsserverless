import hashlib
import hmac
from datetime import datetime, timedelta
from uuid import uuid4
from chalice import UnauthorizedError
import jwt
import os

_SECRET = 'JWT_SECRET_KEY-o7pkWX'


def encode_password(password: str, salt: bytes = None):
    if salt is None:
        salt = os.urandom(16)
    rounds = 100000
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'),
                                 salt, rounds)
    return {
        'hash': 'sha256',
        'salt': salt,
        'rounds': rounds,
        'hashed': hashed,
    }


def get_jwt_token(username: str, password: str, record: dict):
    token_expiration = timedelta(minutes=30)

    actual = hashlib.pbkdf2_hmac(
        record['hash'],
        password.encode('utf-8'),
        record['salt'].value,
        record['rounds']
    )
    expected = record['hashed'].value
    if hmac.compare_digest(actual, expected):
        now = datetime.utcnow()
        unique_id = str(uuid4())
        payload = {
            'sub': username,
            'iat': now,
            'nbf': now,
            'jti': unique_id,
            'exp': datetime.utcnow() + token_expiration
        }

        return jwt.encode(payload, _SECRET, algorithm='HS256')

    raise UnauthorizedError('Invalid password')


def decode_jwt_token(token):
    '''
    RETURNS
    -------
    {
        'sub': 'sabya',
        'iat': 1633226038,
        'nbf': 1633226038,
        'jti': '0d251435-c27a-4387-ad0d-ba0cb38810c8'
    }
    '''
    if not token or token == 'null':
        return {}

    try:
        return jwt.decode(token, _SECRET, algorithms=['HS256'])
    except jwt.exceptions.DecodeError:
        return {}
    except jwt.ExpiredSignatureError:
        '''
        TO-DO: Figure out how to return custom
        response alerting user token is expired
        '''
        return {}
