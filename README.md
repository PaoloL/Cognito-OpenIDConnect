# Amazon Cognito - Open ID Connect Providers

OpenID Connect is an open standard for authentication that is supported by a number of login providers. Amazon Cognito supports linking of identities with OpenID Connect providers that are configured through AWS Identity and Access Management. OpenID is based on [Oauth2](.OAuth2.md)

## Setting Google Identity Provider
Before your application can use Google's OAuth 2.0 authentication system for user login, you must set up a project in the Google API Console to obtain OAuth 2.0 credentials, set a redirect URI, and (optionally) customize the branding information that your users see on the user-consent screen. Google support [OpenID Connect](
https://developers.google.com/identity/protocols/OpenIDConnect)

### Obtain OAuth 2.0 credentials
You need OAuth 2.0 credentials, including a client ID and client secret, to authenticate users and gain access to Google's APIs.   
This is an example:
- Provider URL: accounts.google.com
- Client ID: 123456789-abcdefghilmnopqrstuvxyz.apps.googleusercontent.com
- Client Secret: abcdefghilmnopqrstuvxy

You need to set an Authorized redirect URIs, for Example https://www.getpostman.com/oauth2/callback

## Adding an OpenID Connect Provider to IAM

OIDC identity providers are entities in IAM that describe an identity provider (IdP) service that supports the OpenID Connect (OIDC) standard. You can create a OpenID Connect Identity Provider as described [here](  
https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html)

## Create Amazon Cognito Federated Identities
Amazon Cognito Federated Identities enable you to create unique identities and assign permissions for users. [More info](
https://docs.aws.amazon.com/cognito/latest/developerguide/getting-started-with-identity-pools.html)

During the Identity Federation Wizard Cognito will create two roles: *Authorized* and *UnAuthorized*.
This two role has a following IAM Policies

**Authenticated IAM Policies**
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "mobileanalytics:PutEvents",
                "cognito-sync:*"
            ],
            "Resource": [
                "*"
            ]
        }
    ]
}
```

**UnAuthenticated IAM Policies**

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "mobileanalytics:PutEvents",
                "cognito-sync:*"
            ],
            "Resource": [
                "*"
            ]
        }
    ]
}
```

You cam configure this policies for add or remove permission on end users
This two role has the following Trusted Relationship

**Authenticated Trust Relationship**

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "cognito-identity.amazonaws.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "cognito-identity.amazonaws.com:aud": "eu-west-1:123456-123456-123456-123456-123456"
        },
        "ForAnyValue:StringLike": {
          "cognito-identity.amazonaws.com:amr": "authenticated"
        }
      }
    }
  ]
}
```

**UnAuthenticated Trust Relationship**

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "cognito-identity.amazonaws.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "cognito-identity.amazonaws.com:aud": "eu-west-1:123456-123456-123456-123456-123456"
        },
        "ForAnyValue:StringLike": {
          "cognito-identity.amazonaws.com:amr": "unauthenticated"
        }
      }
    }
  ]
}
```
This relationship is necessary for guarantee that only users from this Cognito Identity Fedeartion can assume this roles.

### Associating a Provider to Amazon Cognito
Once you've created an OpenID Connect provider in the IAM Console, you can associate it to an identity pool. All configured providers will be visible in the Edit Identity Pool screen in the Amazon Cognito Console under the OpenID Connect Providers header.

![Provider Cognito](img/AuthenticationProvider.png)

### Cognito - GetCredentialsForIdentity API
Returns credentials for the provided identity ID. Any provided logins will be validated against supported login providers. After validation the STS return a default role or custom role (only for identity providers that support role customization as SAML2) to Cognito and Cognito sent this to end user. [More info](https://docs.aws.amazon.com/cognitoidentity/latest/APIReference/API_GetCredentialsForIdentity.html)

![Enhanced Flow](img/amazon-cognito-ext-auth-enhanced-flow.png)

The GetCredentialsForIdentity API can be called after you establish an identity ID. This API is functionally equivalent to calling GetOpenIdToken followed by AssumeRoleWithWebIdentity.

**Note** At this moment Cognito GetCredentialsForIdentity API on OpenID Connect identity provider (as SalesForce) not support role mapping rule then support only two roles: Authenticated and UnAuthenticated.

```
{
    "IdentityPoolId": "eu-west-1:123456789-123456789-123456789-123456789",
    "Roles": {
        "unauthenticated": "arn:aws:iam::123456789:role/Cognito_Test_UnAuthRole",
        "authenticated": "arn:aws:iam::123456789:role/Cognito_Test_AuthRole"
    }
}
```


### STS - AssumeRoleWithWebIdentity API

Returns a set of temporary security credentials for users who have been authenticated in a mobile or web application with a web identity provider, such as Amazon Cognito, Login with Amazon, Facebook, Google, or any OpenID Connect-compatible identity provider. [More info](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html)

If you want to exchange a OpenID token coming from Cognito with STS you need to invoke the [GetOpenIdToken](https://docs.aws.amazon.com/cognitoidentity/latest/APIReference/API_GetOpenIdToken.html) API before

![Enhanced Flow](img/amazon-cognito-ext-auth-basic-flow.png)


## Configure API gateway
You can use the API Gateway Import API feature to import an API from an external definition file into API Gateway. Currently, the Import API feature supports Swagger v2.0 definition files.  

Follow this [instruction](https://docs.aws.amazon.com/apigateway/latest/developerguide/import-export-api-endpoints.html) for import a swagger file [API Gateway json](./apigateway.json)

Follow this [instruction](https://docs.aws.amazon.com/apigateway/latest/developerguide/how-to-mock-integration.html) to create a Mock on API gateway

On Integration Response from Method Execution. Expand the 200 response and then the Body Mapping Templates section. Choose or add an application/json mapping template and type the following response body mapping template in the template editor.

```
{
    "statusCode": 200,
    "message": "Go ahead without me"
}
```
## Configure IAM
In the process of creating an identity pool, you'll be prompted to update the IAM roles that your users assume. IAM roles work like this: When a user logs in to your app, Amazon Cognito generates temporary AWS credentials for the user. These temporary credentials are associated with a specific IAM role. The IAM role lets you define a set of permissions to access your AWS resources.

### Configure IAM for GetCredentialsForIdentity

Now you must to Control who can invoke the protected API, creating an IAM policy document with required permissions. This policie will be attached to **Authenticated Role** created before during Cognito configuration.

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Permission",
      "Action": [
        "execute-api:Invoke"           
      ],
      "Resource": [
        "arn:aws:execute-api:region:account-id:api-id/stage/METHOD_HTTP_VERB/Resource-path"
      ]
    }
  ]
}
```



### Configure Trusted Relationship

When you use Amazon Cognito to manage identities you must set a trust policy to permit user coming from Identity Provider (the issuer of the OpenID Connect token) to assume the role


And The policy associated with This

### Configure IAM Policy
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "accounts.google.com:sub": "111501939861489290614"
                }
            }
        }
    ]
}
```

## Create Virtual Environment

```
virtualenv -p python3 openid
source openid/bin/activate
```

### Install Dependencies
```
pip install httplib2
pip install boto3
pip install requests
pip install requests-aws4auth
```

### Setting OAUTH2 credential
```
export OAUTH2_CLIENT_ID="123456789-abcdefghilmnopqrstuvxyz.apps.googleusercontent.com"  
export OAUTH2_CLIENT_SECRET="abcdefghilmnopqrstuvxy"
export AWS_ACCOUNT_ID="12345678910"
export COGNITO_POOL_ID="eu-west-1:abcdefg-abcdefg-abcdefg-abcdefg-abcdefg"
```

### Launch the Google demo
 ```
 python google-oauth2.py
 ```

### Launch the SalesForce demo
```
python salesforce-oauth2.py
```
