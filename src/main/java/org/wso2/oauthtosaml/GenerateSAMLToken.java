/*
* Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

package org.wso2.oauthtosaml;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.oauth.cache.CacheEntry;
import org.wso2.carbon.identity.oauth.cache.CacheKey;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO.OAuth2AccessToken;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.tools.saml.validator.SAMLValidatorService;
import org.wso2.carbon.identity.tools.saml.validator.dto.GeneratedResponseDTO;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

public class GenerateSAMLToken {

    public static final String BEARER = "bearer";

    private static Log log = LogFactory.getLog(GenerateSAMLToken.class);

    /**
     * generate the SAML token when oauth token and issuer is given as input
     *
     * @throws AuthenticationFailedException
     */
    protected GeneratedResponseDTO getSAMLAssertionfromOAuth(String token, String issuer)
            throws AuthenticationFailedException {

        boolean cacheHit = false;
        GeneratedResponseDTO sAMLResponse = null;
        try {
            if (OAuthServerConfiguration.getInstance().isCacheEnabled()) {//caching implementation
                CacheEntry resultValue = isEntryInCache(token);
                // cache hit, do the type check.
                if (resultValue instanceof SAMLAssertion) {
                    cacheHit = true;
                    sAMLResponse = ((SAMLAssertion) resultValue).getSamlAssertion();
                }
            }
            if (!cacheHit) { //if the response was not in cache || if cache is not enabled
                OAuth2TokenValidationService validationService = new OAuth2TokenValidationService();
                OAuth2TokenValidationRequestDTO validationReqDTO = new OAuth2TokenValidationRequestDTO();
                OAuth2AccessToken accessToken = validationReqDTO.new OAuth2AccessToken();
                accessToken.setIdentifier(token);
                accessToken.setTokenType(BEARER);
                validationReqDTO.setAccessToken(accessToken);
                OAuth2TokenValidationResponseDTO validationResponse = validationService.validate(validationReqDTO);

                if (!validationResponse.isValid()) {//validate the OAuth token
                    log.error("RequestPath OAuth authentication failed");
                    throw new AuthenticationFailedException("Authentication Failed");
                }

                String user = validationResponse.getAuthorizedUser();// retrieving user from the validation response for OAuth Token..
                String tenantDomain = MultitenantUtils.getTenantDomain(user);

                if (MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
                    user = MultitenantUtils.getTenantAwareUsername(user);
                }

                //get the SAML token for the particular user for the given issuer
                SAMLValidatorService samlValidatorService = new SAMLValidatorService();
                sAMLResponse = samlValidatorService.buildResponse(issuer, user);

                if (OAuthServerConfiguration.getInstance().isCacheEnabled()) {//saving for cache
                    SAMLAssertion samlAssertion = new SAMLAssertion();
                    samlAssertion.setSamlAssertion(sAMLResponse);
                    saveToCache(token, samlAssertion);
                    if (log.isDebugEnabled()) {
                        log.debug("SAML Token encoded String was added to the cache.");
                    }
                }
            }
            return sAMLResponse;

        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
    }

    /**
     * Saving the entries to cache
     *
     * @param tokenKey
     * @param samlAssertion
     */
    private void saveToCache(String tokenKey, SAMLAssertion samlAssertion) {
        OAuthCache oauthCache = OAuthCache.getInstance();
        CacheKey cacheKey = new OAuthCacheKey(tokenKey);
        oauthCache.addToCache(cacheKey, samlAssertion);
    }

    /**
     * Iterating cache to see if entry is available in cache
     *
     * @param tokenKey
     * @return resulting SAML assertion object
     */
    private CacheEntry isEntryInCache(String tokenKey) {
        OAuthCache oauthCache = OAuthCache.getInstance();
        CacheKey cacheKey = new OAuthCacheKey(tokenKey);
        CacheEntry result = oauthCache.getValueFromCache(cacheKey);
        return result;

    }
}

