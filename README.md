GENERATING ENCODED SAML TOKEN FROM OAUTH TOKEN AND ISSUER
=========================================================


This is a REST web service that sends a SAML token (plain XML/encoded) on invocation.

INPUT PARAMS
------------

token - Valid OAuth token for which the SAML token is required

issuer - issuer for the SAML token

encoding - whether the resulting SAML response needs to  be encoded, if this parameter is null, SAML is sent plain xml format, if it is set to base64, SAML will be encoded in base64


OUTPUT
------


Generated SAML token either in encoded format OR xml format depending on the request header



Sample curl command to invoke the service
-----------------------------------------

for encoded SAML 
curl -vk -X POST https://localhost:9443/oauth2saml/token -d 'token=${OAuthToken}&issuer=${Issuer}&encoding=base64'

for plain xml SAML
curl -vk -X POST https://localhost:9443/oauth2saml/token -d 'token=${OAuthToken}&issuer=${Issuer}'



LICENSE 
-------

Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
