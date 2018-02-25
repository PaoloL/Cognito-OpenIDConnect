__version__     = "1.0.1"
__author__      = "Paolo Latella"
__email__       = "paolo.latella@xpeppers.com"

import hashlib
import os
import re
import httplib2
import webbrowser
import boto3
import requests
import json
from requests_aws4auth import AWS4Auth

oauth2_client_id = os.environ['OAUTH2_CLIENT_ID']
oauth2_client_secret = os.environ['OAUTH2_CLIENT_SECRET']

# To be OpenID-compliant, you must include the openid profile scope in your authentication request.
oauth2_scope = 'openid email profile'

# Set this as the callback URL in your app settings page.
oauth2_redirect_uri = 'https://www.getpostman.com/oauth2/callback'

# You must protect the security of your users by preventing request forgery attacks
def getAntiForgery():
    return hashlib.sha256(os.urandom(1024)).hexdigest()

# forming an HTTPS GET request with the appropriate URI parameters
def getConnectAuthURI(client_id, scope, redirect_uri, state):
    uri = 'https://accounts.google.com/o/oauth2/v2/auth'
    payload = {'client_id': client_id, 'response_type': 'code', 'scope': scope, 'redirect_uri': redirect_uri, 'state': state }
    response = requests.get(uri, params=payload)
    return response.url

# you must confirm that the state received from Google matches the session token you created before
def verifyStateToken(uri,state):
    exp = re.compile(r'.*state=(.*)&code=')
    result = exp.search(uri)
    if (result):
        print (str(result.groups(1)[0]))
        print (state)
        if (result.groups(1)[0] == state):
            return True
        else:
            return False

# The response includes a code parameter, a one-time authorization code that your server can exchange for an access token and ID token
def extractCode(uri):
    exp = re.compile(r'.*code=(.*)&authuser')
    result = exp.search(uri)
    return str(result.groups(1)[0])

# Exchange code with Access Token and Id Token by sending an HTTPS POST request with code
def getAccessOpenIdToken(code, client_id, client_secret, redirect_uri):
    uri = 'https://www.googleapis.com/oauth2/v4/token'
    payload = {'code': code, 'client_id': client_id, 'client_secret': client_secret, 'redirect_uri': redirect_uri, 'grant_type': 'authorization_code'}
    response = requests.post(uri, data=payload)
    return response

#https://docs.aws.amazon.com/cognito/latest/developerguide/authentication-flow.html
def getCredentialsForIdentityWithCognito(id_token):
    cognito_client = boto3.client('cognito-identity',region_name='eu-west-1')
    identity_pool_id='eu-west-1:1ad92bc1-d85d-497b-8d52-db3c4317e614'
    account_id='173349731798'
    # Enhanced (Simplified) Authflow
    # 1.GetId
    # 2.GetCredentialsForIdentity
    print ("Enhanced (Simplified) Authflow")
    response = cognito_client.get_id(AccountId=account_id,IdentityPoolId=identity_pool_id,Logins={'accounts.google.com': id_token})
    identity_id = response['IdentityId']
    print ("Identity ID: %s"%identity_id)
    simplified_authflow = cognito_client.get_credentials_for_identity(IdentityId=identity_id,Logins={'accounts.google.com': id_token})
    secretKey = simplified_authflow['Credentials']['SecretKey']
    accessKey = simplified_authflow['Credentials']['AccessKeyId']
    sessionToken = simplified_authflow['Credentials']['SessionToken']
    expiration = simplified_authflow['Credentials']['Expiration']
    # Basic (Classic) Authflow
    # 1.GetId
    # 2.GetOpenIdToken
    # 3.AssumeRoleWithWebIdentity
    print ("Basic (Classic) Authflow")
    response = cognito_client.get_id(AccountId=account_id,IdentityPoolId=identity_pool_id,Logins={'accounts.google.com': id_token})
    identity_id = response['IdentityId']
    print ("Identity ID: %s"%identity_id)
    classic_authflow = cognito_client.get_open_id_token(IdentityId=identity_id,Logins={'accounts.google.com': id_token})
    token = classic_authflow['Token']
    print("Cognito Token: %s" %token)
    print("Google Token: %s" %id_token)
    RoleARN='arn:aws:iam::173349731798:role/POCSSOAssumeRoleForAuthenticatedUSer'
    sts_client = boto3.client('sts')
    assume_role_response = sts_client.assume_role_with_web_identity(RoleArn=RoleARN,RoleSessionName='invoke',WebIdentityToken=id_token,DurationSeconds=900)
    secretKey = assume_role_response['Credentials']['SecretAccessKey']
    accessKey = assume_role_response['Credentials']['AccessKeyId']
    sessionToken = assume_role_response['Credentials']['SessionToken']
    expiration = assume_role_response['Credentials']['Expiration']

    method = 'GET'
    headers = {}
    body = ''
    service = 'execute-api'
    url = 'https://gj6ma8utnd.execute-api.eu-west-1.amazonaws.com/dev/bike/test'
    region = 'eu-west-1'

    auth = AWS4Auth(accessKey, secretKey, region, service, session_token=sessionToken)
    response = requests.request(method, url, auth=auth, data=body, headers=headers)
    print(response.text)



def main():
    print('[1] Create antiforgery state token')
    state_token = getAntiForgery()
    print('[1.1] Antiforgery state token is ' + state_token  )
    print('[2] Create authentication request')
    uri = getConnectAuthURI(oauth2_client_id, oauth2_scope, oauth2_redirect_uri, state_token)
    print('[2.1] Authentication request is ' + uri)
    callback = input('[3] Paste the callback url here: ')
    print('[4] Verify State Token')
    if verifyStateToken(callback,state_token) is False:
        print('[4.1] State Token mismatch')
        exit(1)
    else:
        print('[4.1] State Token match')
    print('[5] Exchange Code for Access Token and ID Token')
    code = extractCode(callback)
    print('[5.1] Code is ' + code)
    response = getAccessOpenIdToken(code, oauth2_client_id, oauth2_client_secret, oauth2_redirect_uri)
    access_token = response.json()['access_token']
    id_token = response.json()['id_token']
    print('[5.2] Access Token: ' + access_token)
    print('[5.3] OpenID Token: ' + id_token)
    print('[5.4] Call Cognito')
    getCredentialsForIdentityWithCognito(id_token)
    #    response = cognito_client.get_credentials_for_identity(IdentityId=identity_pool_id,Logins={'logins.salesforce.com': id_token}, CustomRoleArn='string')


if __name__ == "__main__":
    main()
