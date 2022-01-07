import json
import boto3
from boto3.dynamodb.types import Binary
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

from lib import auth
'''
create dynamodb resource
'''
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
table = dynamodb.Table('dev-users')


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


def verify_password(password):
    return check_password_hash(generate_password_hash(password), password)


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
    password_fields = auth.encode_password(data['password'])
    item = {
        'username': data['username'],
        'email': data['email'],
        'createdAt': timestamp,
        'hash': password_fields['hash'],
        'salt': Binary(password_fields['salt']),
        'rounds': password_fields['rounds'],
        'hashed': Binary(password_fields['hashed'])
    }
    # create the user to the database
    table.put_item(Item=item)
    body = {
        'email': data['email'],
        'username': data['username']
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
    jwt_token = auth.get_jwt_token(
        data['username'], data['password'], get_user_with_email['Items'][0])
    
    authenticated_user = {
        'email': data['email'],
        'username': get_user_with_email['Items'][0]['username'],
        'token': jwt_token
    }
    return build_response(200, authenticated_user)
