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

import static org.wso2.carbon.core.util.AdminServicesUtil.getUserRealm;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.signature.XMLSignature;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml2.core.impl.AttributeStatementBuilder;
import org.opensaml.saml2.core.impl.AudienceBuilder;
import org.opensaml.saml2.core.impl.AudienceRestrictionBuilder;
import org.opensaml.saml2.core.impl.AuthnContextBuilder;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnStatementBuilder;
import org.opensaml.saml2.core.impl.ConditionsBuilder;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml2.core.impl.StatusMessageBuilder;
import org.opensaml.saml2.core.impl.SubjectBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationDataBuilder;
import org.opensaml.xml.encryption.EncryptionConstants;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.wso2.carbon.CarbonException;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.context.RegistryType;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationInfoProvider;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.persistence.IdentityPersistenceManager;
import org.wso2.carbon.identity.oauth.cache.CacheEntry;
import org.wso2.carbon.identity.oauth.cache.CacheKey;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO.OAuth2AccessToken;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.SSOServiceProviderConfigManager;
import org.wso2.carbon.identity.sso.saml.builders.SignKeyDataHolder;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.identity.tools.saml.validator.util.SAMLValidatorUtil;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.wso2.oauthtosaml.exception.OAuthSAMLTokenGenException;

public class GenerateSAMLToken {

	public static final String BEARER = "bearer";
	public static final String SAMLSSO = "samlsso";

	private static Log log = LogFactory.getLog(GenerateSAMLToken.class);

	/**
	 * generate the SAML token when oauth token and issuer is given as input
	 *
	 * @throws AuthenticationFailedException
	 */
	protected String getSAMLAssertionFromOAuth(String token, String issuer)
			throws OAuthSAMLTokenGenException {

		boolean cacheHit = false;
		String sAMLXMLResponse = null;
		try {
			if (OAuthServerConfiguration.getInstance().isCacheEnabled()) {//caching implementation
				CacheEntry resultValue = isEntryInCache(token);
				// cache hit, do the type check.
				if (resultValue instanceof SAMLAssertion) {
					sAMLXMLResponse = ((SAMLAssertion) resultValue).getSamlAssertion();
					cacheHit = true;
				}
			}
			if (!cacheHit) { //if the response was not in cache || if cache is not enabled
				//validating the OAuth token received
				OAuth2TokenValidationResponseDTO validationResponse =
						getValidationResultForOAuth(token);

                if (!validationResponse.isValid()) {// validate the OAuth token
                    throw new OAuthSAMLTokenGenException("Authentication Failed. "
                            + validationResponse.getErrorMsg(), ErrorCode.AUTHENTICATION_FAILED);
                }

				// retrieving user and tenant domain from the validation response for OAuth Token..
				String user = validationResponse.getAuthorizedUser();
				String tenantDomain = MultitenantUtils.getTenantDomain(user);

                user = MultitenantUtils.getTenantAwareUsername(user);

				Response samlResponseSample = buildSAMLResponse(issuer, user, tenantDomain);
				sAMLXMLResponse = SAMLSSOUtil.marshall(samlResponseSample);

				if (OAuthServerConfiguration.getInstance().isCacheEnabled()) {//saving for cache
					SAMLAssertion samlAssertion = new SAMLAssertion();
					samlAssertion.setSamlAssertion(sAMLXMLResponse);
					saveToCache(token, samlAssertion);
					if (log.isDebugEnabled()) {
						log.debug("SAML Token was added to cache.");
					}
				}
			}
			return sAMLXMLResponse;

		} catch (IdentityException e) {
			throw new OAuthSAMLTokenGenException(e.getMessage(), e, ErrorCode.CONFIGURATION_ERROR);
		}
	}

	/**
	 * validates the OAuth token received,
	 *
	 * @param token Oauth token
	 * @return validation result for the OAuth token
	 */
	private OAuth2TokenValidationResponseDTO getValidationResultForOAuth(String token) {
		OAuth2TokenValidationService validationService = new OAuth2TokenValidationService();
		OAuth2TokenValidationRequestDTO validationReqDTO =
				new OAuth2TokenValidationRequestDTO();
		OAuth2AccessToken accessToken = validationReqDTO.new OAuth2AccessToken();
		accessToken.setIdentifier(token);
		accessToken.setTokenType(BEARER);
		validationReqDTO.setAccessToken(accessToken);
		return validationService.validate(validationReqDTO);
	}

	/**
	 * Saving the entries to cache
	 *
	 * @param tokenKey      Oauth token
	 * @param samlAssertion assertion object that contains the SAML Response XML
	 */
	private void saveToCache(String tokenKey, SAMLAssertion samlAssertion) {
		OAuthCache oauthCache = OAuthCache.getInstance();
		CacheKey cacheKey = new OAuthCacheKey(tokenKey);
		oauthCache.addToCache(cacheKey, samlAssertion);
	}

	/**
	 * Iterating cache to see if entry is available in cache
	 *
	 * @param tokenKey Oauth token
	 * @return resulting SAML assertion object
	 */
	private CacheEntry isEntryInCache(String tokenKey) {
		OAuthCache oauthCache = OAuthCache.getInstance();
		CacheKey cacheKey = new OAuthCacheKey(tokenKey);
		return oauthCache.getValueFromCache(cacheKey);

	}

	private Response buildSAMLResponse(String issuer, String userName, String tenantDoamin)
			throws OAuthSAMLTokenGenException {

		SSOServiceProviderConfigManager spConfigManager =
				SSOServiceProviderConfigManager.getInstance();
		SAMLSSOServiceProviderDO ssoIdPConfigs = spConfigManager.getServiceProvider(issuer);
		Response response = new org.opensaml.saml2.core.impl.ResponseBuilder().buildObject();

		if (ssoIdPConfigs == null) {
			IdentityPersistenceManager persistenceManager;
			try {
				persistenceManager = IdentityPersistenceManager.getPersistanceManager();
                Registry registry = (Registry) PrivilegedCarbonContext
                        .getThreadLocalCarbonContext().getRegistry(
                                RegistryType.SYSTEM_CONFIGURATION);
                
				assert persistenceManager != null;
				ssoIdPConfigs = persistenceManager.getServiceProvider(registry, issuer);
				
                if (ssoIdPConfigs == null) {
                    throw new OAuthSAMLTokenGenException(
                            "Cannot find the SAML Service Provider configuration for the issuer : "
                                    + issuer, ErrorCode.CONFIGURATION_ERROR);
                }
				
				response.setIssuer(SAMLSSOUtil.getIssuer());
				response.setID(SAMLSSOUtil.createID());
				response.setDestination(ssoIdPConfigs.getAssertionConsumerUrl());
				response.setStatus(buildStatus(SAMLSSOConstants.StatusCodes.SUCCESS_CODE, null));
				response.setVersion(SAMLVersion.VERSION_20);
				DateTime issueInstant = new DateTime();
				DateTime notOnOrAfter =
						new DateTime(issueInstant.getMillis() +
						             SAMLSSOUtil.getSAMLResponseValidityPeriod() * 60 *
						             1000);
				response.setIssueInstant(issueInstant);
				Assertion assertion;
				assertion = buildSAMLAssertion(ssoIdPConfigs, notOnOrAfter, userName, issuer,
				                               tenantDoamin);
				if (ssoIdPConfigs.isDoEnableEncryptedAssertion()) {
					String alias = ssoIdPConfigs.getCertAlias();
                    if (alias != null) {
                        EncryptedAssertion encryptedAssertion;
                        encryptedAssertion = SAMLSSOUtil
                                .setEncryptedAssertion(assertion,
                                        EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256, alias,
                                        tenantDoamin);
                        response.getEncryptedAssertions().add(encryptedAssertion);
                    }
				} else {
					response.getAssertions().add(assertion);
				}
				if (ssoIdPConfigs.isDoSignResponse()) {
					SAMLSSOUtil.setSignature(response, XMLSignature.ALGO_ID_SIGNATURE_RSA,
					                         new SignKeyDataHolder(userName));
				}
			} catch (IdentityException e) {
                throw new OAuthSAMLTokenGenException(e.getMessage(), e,
                        ErrorCode.CONFIGURATION_ERROR);
			} 

		}
		return response;
	}

    private Assertion buildSAMLAssertion(SAMLSSOServiceProviderDO ssoIdPConfigs,
            DateTime notOnOrAfter, String userName, String issuer, String tenantDoamin)
            throws OAuthSAMLTokenGenException {
        
        DateTime currentTime = new DateTime();
        Assertion samlAssertion = new AssertionBuilder().buildObject();
        samlAssertion.setID(SAMLSSOUtil.createID());
        samlAssertion.setVersion(SAMLVersion.VERSION_20);

        try {
            samlAssertion.setIssuer(SAMLSSOUtil.getIssuer());

            samlAssertion.setIssueInstant(currentTime);
            Subject subject = new SubjectBuilder().buildObject();
            NameID nameId = new NameIDBuilder().buildObject();
            String claimValue = null;

            if (ssoIdPConfigs.getNameIdClaimUri() != null) {
                Map<String, String> claims = SAMLValidatorUtil.getUserClaimValues(userName,
                        new String[] { ssoIdPConfigs.getNameIdClaimUri() }, null);
                claimValue = claims.get(ssoIdPConfigs.getNameIdClaimUri());
                nameId.setValue(claimValue);
            }

            if (claimValue == null) {
                if (ssoIdPConfigs.isUseFullyQualifiedUsername()) {
                    nameId.setValue(userName);
                } else {
                    nameId.setValue(userName);
                }
            }

            if (ssoIdPConfigs.getNameIDFormat() != null) {
                nameId.setFormat(ssoIdPConfigs.getNameIDFormat());
            } else {
                nameId.setFormat(NameIdentifier.EMAIL);
            }

            subject.setNameID(nameId);

            SubjectConfirmation subjectConfirmation = new SubjectConfirmationBuilder()
                    .buildObject();
            subjectConfirmation.setMethod(SAMLSSOConstants.SUBJECT_CONFIRM_BEARER);

            SubjectConfirmationData subjectConfirmationData = new SubjectConfirmationDataBuilder()
                    .buildObject();
            subjectConfirmationData.setRecipient(ssoIdPConfigs.getAssertionConsumerUrl());
            subjectConfirmationData.setNotOnOrAfter(notOnOrAfter);

            subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
            subject.getSubjectConfirmations().add(subjectConfirmation);
            samlAssertion.setSubject(subject);

            AuthnStatement authStmt = new AuthnStatementBuilder().buildObject();
            authStmt.setAuthnInstant(new DateTime());

            AuthnContext authContext = new AuthnContextBuilder().buildObject();
            AuthnContextClassRef authCtxClassRef = new AuthnContextClassRefBuilder().buildObject();
            authCtxClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);
            authContext.setAuthnContextClassRef(authCtxClassRef);
            authStmt.setAuthnContext(authContext);
            samlAssertion.getAuthnStatements().add(authStmt);

            Map<String, String> sPClaims = getSPClaims(userName, issuer, tenantDoamin);
            if (sPClaims != null) {
                samlAssertion.getAttributeStatements().add(buildAttributeStatement(sPClaims));
            }

            AudienceRestriction audienceRestriction = new AudienceRestrictionBuilder()
                    .buildObject();
            Audience issuerAudience = new AudienceBuilder().buildObject();
            issuerAudience.setAudienceURI(ssoIdPConfigs.getIssuer());
            audienceRestriction.getAudiences().add(issuerAudience);
            if (ssoIdPConfigs.getRequestedAudiences() != null) {
                for (String requestedAudience : ssoIdPConfigs.getRequestedAudiences()) {
                    Audience audience = new AudienceBuilder().buildObject();
                    audience.setAudienceURI(requestedAudience);
                    audienceRestriction.getAudiences().add(audience);
                }
            }

            Conditions conditions = new ConditionsBuilder().buildObject();
            conditions.setNotBefore(currentTime);
            conditions.setNotOnOrAfter(notOnOrAfter);
            conditions.getAudienceRestrictions().add(audienceRestriction);
            samlAssertion.setConditions(conditions);

            if (ssoIdPConfigs.isDoSignAssertions()) {
                SAMLSSOUtil.setSignature(samlAssertion, XMLSignature.ALGO_ID_SIGNATURE_RSA,
                        new SignKeyDataHolder(userName));
            }

        } catch (IdentityException e) {
            throw new OAuthSAMLTokenGenException(e.getMessage(), e, ErrorCode.CONFIGURATION_ERROR);
        }

        return samlAssertion;
    }

	/**
	 * Retrieving the service providers claims from the back-end
	 *
	 * @param username username of the token
	 * @param issuer   issuer for the SAML
	 * @return map of claims URI s and matching claim values
	 * @throws IdentityException
	 * @throws CarbonException
	 * @throws UserStoreException
	 * @throws IdentityApplicationManagementException
	 */
	private Map<String, String> getSPClaims(String username, String issuer, String tenantDomain)
			throws OAuthSAMLTokenGenException {//exceptions are thrown in this currently
		Map<String, String> spClaimMap = new HashMap<String, String>();
		org.wso2.carbon.identity.application.common.model.ClaimMapping[] claimMappings;
		ApplicationInfoProvider appInfo = ApplicationInfoProvider.getInstance();
		UserRealm realm;
		try {
		    realm = getUserRealm();
            UserStoreManager userStore = realm.getUserStoreManager();
            
			ServiceProvider serviceProvider =
					appInfo.getServiceProviderByClienId(issuer, SAMLSSO, tenantDomain);
			claimMappings = serviceProvider.getClaimConfig().getClaimMappings();
			
            for (int i = 0; i < claimMappings.length; i++) {

                Claim remoteClaim = claimMappings[i].getRemoteClaim();
                Claim localClaim = claimMappings[i].getLocalClaim();
                
                String claimValue = userStore.getUserClaimValue(username, claimMappings[i]
                        .getLocalClaim().getClaimUri(), null);
                
//                Map to remote claims only if remote claims are present.
                if (remoteClaim != null) {
                    spClaimMap.put(remoteClaim.getClaimUri(), claimValue);
                } else {
                    spClaimMap.put(localClaim.getClaimUri(), claimValue);
                }
            }

		} catch (IdentityApplicationManagementException e) {
			throw new OAuthSAMLTokenGenException(e.getMessage(), e, ErrorCode.CONFIGURATION_ERROR);
		} catch (CarbonException e) {
            throw new OAuthSAMLTokenGenException(e.getMessage(), e, ErrorCode.CONFIGURATION_ERROR);
        } catch (UserStoreException e) {
            throw new OAuthSAMLTokenGenException(e.getMessage(), e, ErrorCode.CONFIGURATION_ERROR);
        }

		return spClaimMap;

	}

    private AttributeStatement buildAttributeStatement(Map<String, String> claims)
            throws OAuthSAMLTokenGenException {
        AttributeStatement attStmt = null;
        if (claims != null) {
            attStmt = new AttributeStatementBuilder().buildObject();
            Iterator<String> ite = claims.keySet().iterator();

            for (int i = 0; i < claims.size(); i++) {
                Attribute attrib = new AttributeBuilder().buildObject();
                String claimUri = ite.next();
                attrib.setName(claimUri);
                // setting NAMEFORMAT attribute value to basic attribute profile
                attrib.setNameFormat(SAMLSSOConstants.NAME_FORMAT_BASIC);

                // Try to bootstrap the OpenSAML.
                SAMLSSOUtil.doBootstrap();
                // look
                // https://wiki.shibboleth.net/confluence/display/OpenSAML/OSTwoUsrManJavaAnyTypes
                XSStringBuilder stringBuilder = (XSStringBuilder) Configuration.getBuilderFactory()
                        .getBuilder(XSString.TYPE_NAME);
                if (stringBuilder == null) {
                    throw new OAuthSAMLTokenGenException(
                            "Could not obtain the OpenSAML Configuration.",
                            ErrorCode.CONFIGURATION_ERROR);
                }

                XSString stringValue = stringBuilder.buildObject(
                        AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
                stringValue.setValue(claims.get(claimUri));
                attrib.getAttributeValues().add(stringValue);
                attStmt.getAttributes().add(attrib);
            }
        }
        return attStmt;
    }

	/**
	 * Get status
	 *
	 * @param status  opensaml status
	 * @param statMsg message for the particular status
	 * @return Status object
	 */
	private Status buildStatus(String status, String statMsg) {
		Status stat = new StatusBuilder().buildObject();

		// Set the status code
		StatusCode statCode = new StatusCodeBuilder().buildObject();
		statCode.setValue(status);
		stat.setStatusCode(statCode);

		// Set the status Message
		if (statMsg != null) {
			StatusMessage statMesssage = new StatusMessageBuilder().buildObject();
			statMesssage.setMessage(statMsg);
			stat.setStatusMessage(statMesssage);
		}
		return stat;
	}

}

