import os
import json
import base64
import logging
import requests
import re
import jwt
import botocore
import boto3
from urllib.parse import quote
# from requests.adapters import HTTPAdapter
# from requests.packages.urllib3.util.retry import Retry

# Environment Variables
PRIVATE_ENDPOINT = os.environ.get('PRIVATE_ENDPOINT', '').strip()
Amazon_MWAA_ENV_NAME = os.environ.get('Amazon_MWAA_ENV_NAME', '').strip()
AWS_ACCOUNT_ID = os.environ.get('AWS_ACCOUNT_ID', '').strip()
COGNITO_CLIENT_ID = os.environ.get('COGNITO_CLIENT_ID', '').strip()
COGNITO_DOMAIN = os.environ.get('COGNITO_DOMAIN').strip()
AWS_REGION = os.environ.get('AWS_REGION')
IDP_LOGIN_URI = os.environ.get('IDP_LOGIN_URI').strip()
GROUP_TO_ROLE_MAP = json.loads(os.environ.get('GROUP_TO_ROLE_MAP', '{}'))
ALB_COOKIE_NAME = os.environ.get('ALB_COOKIE_NAME', 'AWSELBAuthSessionCookie').strip()
LOGOUT_REDIRECT_DELAY = 10  # seconds

sts = boto3.client('sts')
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    """
    Lambda handler
    """
    try:
        logger.info(json.dumps(event))
        path = event['path']
        headers = event['multiValueHeaders']

        if 'x-amzn-oidc-data' in headers:
            encoded_jwt = headers['x-amzn-oidc-data'][0]
            token_payload = decode_jwt(encoded_jwt)
        else:
            return close(headers)

        if path == '/aws_mwaa/aws-console-sso':
            redirect = login(headers, token_payload)
        elif path == '/logout/':
            redirect = logout(headers, 'Logged out successfully')
        else:
            redirect = logout(headers, '')

        logger.info(json.dumps(redirect))
        return redirect

    except Exception as e:
        logger.error(f'Unhandled exception: {str(e)}', exc_info=True)
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Internal server error'})
        }


def multivalue_to_singlevalue(headers):
    """
    Convert multi-value headers to single value
    """
    return {key: value[0] for (key, value) in headers.items()}


def singlevalue_to_multivalue(headers):
    """
    Convert single value headers to multi-value headers
    """
    return {key: [value] for (key, value) in headers.items()}


def login(headers, jwt_payload):
    """
    Function that returns a redirection to an appropriate URL that includes a web login token.
    """
    try:
        role_arn = get_iam_role_arn(jwt_payload)
        user_name = jwt_payload.get('custom:idp-name', role_arn)
        host = headers['host'][0]

        if role_arn:
            mwaa = get_mwaa_client(role_arn, user_name)
            if mwaa:
                try:
                    mwaa_web_token = mwaa.create_web_login_token(Name=Amazon_MWAA_ENV_NAME)["WebToken"]
                    logger.info('Redirecting with Amazon MWAA WEB TOKEN')
                    redirect = {
                        'statusCode': 302,
                        'statusDescription': '302 Found',
                        'multiValueHeaders': {
                            'Location': [f'https://{host}/aws_mwaa/aws-console-sso?login=true#{mwaa_web_token}']
                        }
                    }
                except botocore.exceptions.ClientError as error:
                    if error.response['Error']['Code'] == 'AccessDeniedException':
                        redirect = logout(headers, f'The role "{role_arn}" assigned to {user_name} does not have access to the environment "{Amazon_MWAA_ENV_NAME}".')
                    elif error.response['Error']['Code'] == 'ResourceNotFoundException':
                        redirect = logout(headers, f'Environment {Amazon_MWAA_ENV_NAME} was not found.')
                    else:
                        redirect = logout(headers, error)
            else:
                redirect = logout(headers, 'There was an error while logging in, please contact your administrator.')
        else:
            redirect = logout(headers, 'There is no valid role associated with your user.')
        # Log the final redirect URL
        logger.info(f"Final Redirect URL: {redirect['multiValueHeaders']['Location'][0]}")
        return redirect

    except Exception as e:
        logger.error(f'Error in login function: {str(e)}', exc_info=True)
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Internal server error'})
        }


def logout(headers, message):
    """
    Logs out from Airflow and expires the ALB cookies. If a message is present, it displays it for a few
    seconds and redirects to Cognito logout.
    """
    try:
        logger.info('LOGGING OUT')
        host = headers['host'][0]
        svheaders = multivalue_to_singlevalue(headers)
        svheaders['host'] = PRIVATE_ENDPOINT

        logger.info(f'CALLING {PRIVATE_ENDPOINT}')
        response = requests.get(f'https://{PRIVATE_ENDPOINT}/logout/', headers=svheaders, allow_redirects=True)
        headers_to_forward = singlevalue_to_multivalue(response.headers)

        redirect_uri = quote(f'https://{host}/logout/close', safe="")
        cognito_logout_uri = f'https://{COGNITO_DOMAIN}.auth.{AWS_REGION}.amazoncognito.com/logout?client_id={COGNITO_CLIENT_ID}&response_type=code&logout_uri={redirect_uri}&scope=openid'

        headers = headers_to_forward
        headers['Location'] = [cognito_logout_uri]
        expire_alb_cookies(headers)

        if message:
            body = error_redirection_body(message, cognito_logout_uri)
            headers['Content-Type'] = ['text/html']
            redirect = {
                'statusCode': 200,
                'multiValueHeaders': headers,
                'body': body,
                'isBase64Encoded': False
            }
        else:
            redirect = {
                'statusCode': 302,
                'statusDescription': '302 Found',
                'multiValueHeaders': headers
            }

        return redirect

    except Exception as e:
        logger.error(f'Error in logout function: {str(e)}', exc_info=True)
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Internal server error'})
        }


def get_mwaa_client(role_arn, user_name):
    """
    Returns an Amazon MWAA client under the given IAM role
    """
    mwaa = None
    try:
        logger.info(f'Assuming role "{role_arn}" with source identity "{user_name}"...')
        sanitized_user_name = sanitize_value(user_name)
        credentials = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=sanitized_user_name,
            DurationSeconds=900,  # This is the minimum allowed
            SourceIdentity=sanitized_user_name
        )['Credentials']

        access_key = credentials['AccessKeyId']
        secret_key = credentials['SecretAccessKey']
        session_token = credentials['SessionToken']

        mwaa = boto3.client(
            'mwaa',
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token
        )
    except botocore.exceptions.ClientError as error:
        logger.error(f'Error while assuming role {role_arn}. {error}')
    except Exception as error:
        logger.error(f'Unknown error while assuming role {role_arn}. {error}')

    return mwaa


def get_iam_role_arn(jwt_payload):
    """
    Returns the name of an IAM role based on the 'custom:idp-groups' contained in the JWT token
    """
    try:
        role_arn = 'arn:aws:iam::955696714113:role/airflow-admin-role' #set default iam role
        logger.info(f'JWT payload: {jwt_payload}')
        if 'custom:idp-groups' in jwt_payload:
            user_groups = parse_groups(jwt_payload['custom:idp-groups'])
            logger.info(f'Parsed user groups: {user_groups}')
            for mapping in GROUP_TO_ROLE_MAP:
                logger.info(f'Checking mapping: {mapping}')
                if mapping['idp-group'] in user_groups:
                    role_name = mapping['iam-role']
                    role_arn = f'arn:aws:iam::{AWS_ACCOUNT_ID}:role/{role_name}'
                    logger.info(f'Found matching role: {role_arn}')
                    break
            if not role_arn:
                logger.warning(f'No matching IAM role found for user groups: {user_groups}')
        else:
            logger.warning('No custom:idp-groups found in JWT payload')
        return role_arn
    except Exception as e:
        logger.error(f'Error in get_iam_role_arn function: {str(e)}', exc_info=True)
        return ''


def parse_groups(groups):
    """
    Converts the groups SAML claim content to a list of strings
    """
    try:
        groups = groups.replace('[', '').replace(']', '').replace(' ', '')
        return groups.split(',')
    except Exception as e:
        logger.error(f'Error in parse_groups function: {str(e)}', exc_info=True)
        return []


def sanitize_value(value):
    """
    Sanitize the value to conform to the required pattern
    """
    return re.sub(r'[^\w+=,.@-]', '_', value)


def decode_jwt(encoded_jwt):
    """
    Decodes a JSON Web Token issued by the ALB after successful authentication against an OIDC IdP (e.g.: Cognito).
    """
    try:
        jwt_headers = encoded_jwt.split('.')[0]
        decoded_jwt_headers = base64.urlsafe_b64decode(jwt_headers + "==")
        decoded_json = json.loads(decoded_jwt_headers)
        kid = decoded_json['kid']

        url = f'https://public-keys.auth.elb.{AWS_REGION}.amazonaws.com/{kid}'

        req = requests.get(url)
        pub_key = req.text

        payload = jwt.decode(encoded_jwt, pub_key, algorithms=[decoded_json['alg']])
        return payload
    except jwt.exceptions.InvalidAlgorithmError as e:
        logger.error(f'Invalid algorithm: {str(e)}', exc_info=True)
        raise Exception("Unsupported JWT algorithm")
    except Exception as e:
        logger.error(f'Error decoding JWT: {str(e)}', exc_info=True)
        raise


def expire_alb_cookies(headers):
    """
    Sets ALB session cookies to expire
    """
    try:
        alb_cookies = [
            f'{ALB_COOKIE_NAME}-1=del;Max-Age=-1;Path=/;',
            f'{ALB_COOKIE_NAME}-0=del;Max-Age=-1;Path=/;'
        ]
        if 'Set-Cookie' in headers:
            headers['Set-Cookie'] += alb_cookies
        else:
            headers['Set-Cookie'] = alb_cookies
    except Exception as e:
        logger.error(f'Error in expire_alb_cookies function: {str(e)}', exc_info=True)


def error_redirection_body(message, logout_uri):
    """
    Returns an HTML string that displays an error message and redirects the browser to the logout_uri
    """
    try:
        body = f'<html><body><h3>{message}</h3><br><br>Closing session in <span id="countdown">{LOGOUT_REDIRECT_DELAY}</span> seconds</body></html>'
        body += '<script type="text/javascript">'
        body += f'var seconds = {LOGOUT_REDIRECT_DELAY};'
        body += 'function countdown() {'
        body += '  seconds -= 1;'
        body += '  if (seconds < 0) {'
        body += f'    window.location = "{logout_uri}?";'
        body += '  } else {'
        body += '    document.getElementById("countdown").innerHTML = seconds;'
        body += '    window.setTimeout("countdown()", 1000);'
        body += '  }'
        body += '}'
        body += 'countdown();'
        body += '</script>'
        return body
    except Exception as e:
        logger.error(f'Error in error_redirection_body function: {str(e)}', exc_info=True)
        return '<html><body><h3>Error occurred. Please try again later.</h3></body></html>'


def close(headers):
    """
    Requests user to close the current tab
    """
    try:
        body = '<html><body><h3>You can now close this tab.</h3></body></html>'
        headers['Content-Type'] = ['text/html']
        return {
            'statusCode': 200,
            'multiValueHeaders': headers,
            'body': body,
            'isBase64Encoded': False
        }
    except Exception as e:
        logger.error(f'Error in close function: {str(e)}', exc_info=True)
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Internal server error'})
        }
