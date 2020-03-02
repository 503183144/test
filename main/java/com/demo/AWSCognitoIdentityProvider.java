// This page is not essential at the moment

package com.ge.cognito;

clientId = 2jkihs1a8su8n4jq0lvihsh3po
userPoolId = us-east-1_3vocxnITQ
endpoint = cognito-idp.us-east-1.amazonaws.com
region = us-east-1
identityPoolId = us-east-1:f2810be3-a906-4a1e-83bc-aa1230b6789

public AWSCognitoIdentityProvider getAmazonCognitoIdentityClient() {
        ClasspathPropertiesFileCredentialsProvider propertiesFileCredentialsProvider =
        new ClasspathPropertiesFileCredentialsProvider();

        return AWSCognitoIdentityProviderClientBuilder.standard()
        .withCredentials(propertiesFileCredentialsProvider)
        .withRegion(cognitoConfig.getRegion())
        .build();

}
