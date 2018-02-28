__version__     = "1.0.1"
__author__      = "Paolo Latella"
__email__       = "paolo.latella@xpeppers.com"

'''
This code implement the authorization code grant.
The authorization code grant type is used to obtain both access
tokens and refresh tokens and is optimized for confidential clients.
Since this is a redirection-based flow, the client must be capable of
interacting with the resource owner's user-agent (typically a web
browser) and capable of receiving incoming requests (via redirection)
from the authorization server.
https://tools.ietf.org/html/rfc6749#section-4.1
'''
import time
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
identity_pool_id = os.environ['COGNITO_POOL_ID']
account_id = os.environ['AWS_ACCOUNT_ID']
region = os.environ['AWS_REGION']
roleARN = os.environ['STS_ROLE_ARN']
uri = os.environ['API_URI']
service = os.environ['AWS_SERVICE']


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
    reply_state = str(result.groups(1)[0])
    if (result):
        if (reply_state == state):
            return True, reply_state
        else:
            return False, reply_state

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

# Exchange google token with Cognito token using Enhanced (Simplified) Authflow
# 1.GetId
# 2.GetCredentialsForIdentity
def getCredentialsForIdentity(client, idp_id_token):
    print ('INFO: Call GetId APIs')
    response = client.get_id(AccountId=account_id,IdentityPoolId=identity_pool_id,Logins={'accounts.google.com': idp_id_token})
    identity_id = response['IdentityId']
    print ('INFO: Identity ID is ', identity_id)
    print ('INFO: Call GetCredentialsForIdentity API')
    # Returns credentials for the provided identity ID.
    # Any provided logins will be validated against supported login providers
    simplified_authflow = client.get_credentials_for_identity(IdentityId=identity_id,Logins={'accounts.google.com': idp_id_token})
    secretKey = simplified_authflow['Credentials']['SecretKey']
    accessKey = simplified_authflow['Credentials']['AccessKeyId']
    sessionToken = simplified_authflow['Credentials']['SessionToken']
    expiration = simplified_authflow['Credentials']['Expiration']
    return accessKey, secretKey, sessionToken, expiration

# Exchange google token with Cognito token using Basic (Classic) Authflow
# 1.GetId
# 2.GetOpenIdToken
# 3.AssumeRoleWithWebIdentity
def assumeRoleWithWebIdentity(client, idp_id_token):
    print ('INFO: Call GetId APIs')
    response = client.get_id(AccountId=account_id,IdentityPoolId=identity_pool_id,Logins={'accounts.google.com': idp_id_token})
    identity_id = response['IdentityId']
    print ('INFO: Identity ID is ', identity_id)
    print ('INFO: Call GetOpenIdToken API')
    classic_authflow = client.get_open_id_token(IdentityId=identity_id,Logins={'accounts.google.com': idp_id_token})
    cognito_token = classic_authflow['Token']
    print ('INFO: Google OpenID Token: ', idp_id_token)
    print ('INFO: Cognito OpenID Token ', cognito_token)
    print ('INFO: Initialize STS Client')
    sts_client = boto3.client('sts')
    print('INFO: Call AssumeRoleWithWebIdentity API')
    assume_role_response = sts_client.assume_role_with_web_identity(RoleArn=roleARN,RoleSessionName='invoke',WebIdentityToken=idp_id_token,DurationSeconds=900)
    secretKey = assume_role_response['Credentials']['SecretAccessKey']
    accessKey = assume_role_response['Credentials']['AccessKeyId']
    sessionToken = assume_role_response['Credentials']['SessionToken']
    expiration = assume_role_response['Credentials']['Expiration']
    return accessKey, secretKey, sessionToken, expiration

def callApiGatewayGet(service, uri, accessKey, secretKey, sessionToken):
    service='execute-api'
    uri='https://eih8r8mog3.execute-api.eu-west-1.amazonaws.com/test/bike/1'
    method = 'GET'
    headers = {}
    body = ''
    auth = AWS4Auth(accessKey, secretKey, region, service, session_token=sessionToken)
    response = requests.request(method, uri, auth=auth, data=body, headers=headers)
    return response.text

def main():
    print('STEP [1] Create antiforgery state token')
    state_token = getAntiForgery()
    print('INFO: Antiforgery state token is ' + state_token  )
    print('STEP [2] Create authentication request')
    uri = getConnectAuthURI(oauth2_client_id, oauth2_scope, oauth2_redirect_uri, state_token)
    print('INFO: Authentication request is ' + uri)
    callback = input('INFO: Paste the callback url here: ')
    print('STEP [3] Verify State Token')
    verified, reply_state = verifyStateToken(callback,state_token)
    if verified is False:
        print('INFO: State Token is ', state_token)
        print('INFO: Reply Token is ', reply_state)
        print('INFO: State Token mismatch')
        exit(1)
    else:
        print('INFO: State Token is', state_token)
        print('INFO: Reply Token is', reply_state)
        print('INFO: State Token match')
    print('STEP [4] Exchange Code for Access Token and ID Token')
    code = extractCode(callback)
    print('INFO: Code is ' + code)
    response = getAccessOpenIdToken(code, oauth2_client_id, oauth2_client_secret, oauth2_redirect_uri)
    access_token = response.json()['access_token']
    idp_id_token = response.json()['id_token']
    print('INFO: Access Token: ', access_token)
    print('INFO: OpenID Token: ', idp_id_token)
    print('STEP [5] Call Cognito')
    cognito_client = boto3.client('cognito-identity',region_name=region)
    print ('INFO: Using Cognito Enhanced (Simplified) Authflow')
    accessKey, secretKey, sessionToken, expiration = getCredentialsForIdentity(cognito_client,idp_id_token)
    print ('INFO: AccessKey ', accessKey)
    print ('INFO: SecretKey ', secretKey)
    print ('STEP [6] Call AWS Services')
    print ('INFO: Invoke Service %s with getCredentialsForIdentity API' % service)
    response = callApiGatewayGet(service,uri,accessKey,secretKey,sessionToken)
    print ('INFO: Response ', response)
    print ('INFO: Using Cognito Basic (Classic) Authflow')
    accessKey, secretKey, sessionToken, expiration = assumeRoleWithWebIdentity(cognito_client,idp_id_token)
    print ('INFO: AccessKey ', accessKey)
    print ('INFO: SecretKey ', secretKey)
    print ('STEP [6] Call AWS Services')
    print ('INFO: Invoke Service %s with assumeRoleWithWebIdentity API' % service)
    response = callApiGatewayGet(service,uri,accessKey,secretKey,sessionToken)
    print ('INFO: Response ', response)

if __name__ == "__main__":
    main()
