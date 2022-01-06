# import os
# import jwt
import json
import boto3
# import base64
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
# from io import BytesIO
# import onetimepass
# import pyqrcode
# from boto3.dynamodb.conditions import Key, Attr


'''
create dynamodb resource
'''
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
table = dynamodb.Table('dev-users')

JWT_SECRET = 'secret'
JWT_ALGORITHM = 'HS256'
JWT_DELTA_SECONDS = 172800  # 2 days


# def min_token(a_username):
#     payload = {
#         'username': a_username,
#         'expiresIn': datetime.utcnow() + timedelta(seconds=JWT_DELTA_SECONDS)
#     }
#     jwt_token = jwt.encode(payload, JWT_SECRET, JWT_ALGORITHM)
#     return jwt_token


def get_user_by_username(username):
    '''
    check if user already exists in db
    '''
    try:
        response = table.get_item(
            Key={
                'username': username
            }
        )
        return response
    except Exception:
        return None


def get_user_by_email(email):
    response = table.query(
        IndexName='email',
        KeyConditionExpression='email= :email',
        ExpressionAttributeValues={
            ':email': email,
        },
        Select='ALL_ATTRIBUTES',
    )
    return response


def build_response(statuscode, body=None):
    response = {
        "statusCode": statuscode,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        }
    }
    if body is not None:
        response['body'] = json.dumps(body)
    return response


# def get_totp_uri(username):
#     otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')
#     return 'otpauth://totp/2FA-Demo:{0}?secret={1}&issuer=2FA-Demo' \
#         .format(username, otp_secret)


def verify_password(password):
    return check_password_hash(generate_password_hash(password), password)


# def verify_totp(token, otp_secret):
#     return onetimepass.valid_totp(token, otp_secret)


def create_user(event, context):
    data = json.loads(event['body'])['user']
    if 'username' not in data:
        return build_response(422, body={
            'message': "Validation Failed, empty Username"
            })
    if 'email' not in data:
        return build_response(422, body={
            'message': "Validation Failed, empty email"
            })
    if 'password' not in data:
        return build_response(422, body={
            'message': "Validation Failed, empty password"
            })
    timestamp = str(datetime.utcnow().timestamp())
    '''
    Verify username is not taken
    '''
    user_exists = get_user_by_username(data['username'])
    if 'Item' not in user_exists:
        pass
    else:
        body = {
            'message': 'username already taken'
        }
        return build_response(422, body)
    '''
    Verify email is not taken
    '''
    email_exists = get_user_by_email(data['email'])
    if email_exists['Count'] != 0:
        return build_response(422, body={
            'message': "Validation Failed, email used"
            })
    '''
    Implemented for 2FA
    '''
    # otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')
    # otp = 'otpauth://totp/2FA-Demo:{0}?secret={1}&issuer=2FA-Demo' \
    #     .format(data['username'], otp_secret)
    # token = min_token(data['username'])
    item = {
        # 'id': str(uuid.uuid1()),
        'username': data['username'],
        'email': data['email'],
        'password': generate_password_hash(data['password']),
        # 'token': token,
        'createdAt': timestamp,
        'updatedAt': timestamp
    }
    # create the user to the database
    table.put_item(Item=item)

    # render qrcode for FreeTOTP
    # url = pyqrcode.create(get_totp_uri(data['username']))
    # stream = BytesIO()
    # url.svg(stream, scale=3)
    # return stream.getvalue(), 200, {
    #     'Content-Type': 'image/svg+xml',
    #     'Cache-Control': 'no-cache, no-store, must-revalidate',
    #     'Pragma': 'no-cache',
    #     'Expires': '0'}

    body = {
        'email': data['email'],
        'username': data['username']
        # 'token': token
    }
    return build_response(200, body)


def login_user(event, context):
    data = json.loads(event['body'])['user']
    if not data:
        return build_response(422, body={
            'message': "missing data"
            })
    if 'email' not in data:
        return build_response(422, body={
            'message': "Validation Failed, empty email"
            })
    if 'password' not in data:
        return build_response(422, body={
            'message': "Validation Failed, empty password"
            })

    # Get user with this email
    get_user_with_email = get_user_by_email(data['email'])
    if get_user_with_email['Count'] != 1:
        return build_response(422, body={
            'message': "Validation Failed, email not found"
            })
    if not verify_password(data['password']):
        return build_response(422, body={
            'message': "Validation Failed, inccorect password"
            })
    # print(get_user_with_email['Items'][0]['username'])
    # if not verify_totp(data['token'], get_user_with_email['Item'][0]
    #                    ['otp_secret']):
    #     raise Exception("Wrong token.", 422)

    authenticated_user = {
        'email': data['email'],
        # 'token': min_token(get_user_with_email['Items'][0]['username']),
        'username': get_user_with_email['Items'][0]['username']
    }

    return build_response(200, authenticated_user)
