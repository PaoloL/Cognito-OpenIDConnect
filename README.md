# Amazon Cognito


## Setting Google Identity Provider
http://docs.aws.amazon.com/cognito/latest/developerguide/google.html
Provider URL: accounts.google.com
Audience: 428995339229-bbb0jict0t2hiaja5jh5j3sqs5uco0gc.apps.googleusercontent.com

Authorized JavaScript origins from S3
http://refopenind.xpeppers.com.s3-website-eu-west-1.amazonaws.com/

Setting S3 Cors ?

Setting OpenID provider
http://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html

## Virtual Environment
virtualenv -p python3 openid
source openid/bin/activate

## Install Dependencies
pip install requests-aws4auth
