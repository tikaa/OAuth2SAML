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
import org.apache.xml.security.signature.XMLSignature;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.core.impl.*;
import org.opensaml.xml.encryption.EncryptionConstants;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.wso2.carbon.CarbonException;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.context.RegistryType;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
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

import java.util.Iterator;
import java.util.Map;

import static org.wso2.carbon.core.util.AdminServicesUtil.getUserRealm;

public class GenerateSAMLToken {

	public static final String BEARER = "bearer";
	public static final String SAMLSSO = "samlsso";
	public static final String CARBON_SUPER = "carbon.super";//since no tenants are used

	private static Log log = LogFactory.getLog(GenerateSAMLToken.class);

	/**
	 * generate the SAML token when oauth token and issuer is given as input
	 *
	 * @throws AuthenticationFailedException
	 */
	protected String getSAMLAssertionFromOAuth(String token, String issuer)
			throws AuthenticationFailedException, IdentityException, CarbonException,
			       UserStoreException, IdentityApplicationManagementException {

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
				OAuth2TokenValidationService validationService = new OAuth2TokenValidationService();
				OAuth2TokenValidationRequestDTO validationReqDTO =
						new OAuth2TokenValidationRequestDTO();
				OAuth2AccessToken accessToken = validationReqDTO.new OAuth2AccessToken();
				accessToken.setIdentifier(token);
				accessToken.setTokenType(BEARER);
				validationReqDTO.setAccessToken(accessToken);
				OAuth2TokenValidationResponseDTO validationResponse =
						validationService.validate(validationReqDTO);

				if (!validationResponse.isValid()) {//validate the OAuth token
					log.error("RequestPath OAuth authentication failed");
					throw new AuthenticationFailedException("Authentication Failed");
				}

				String user = validationResponse
						.getAuthorizedUser();// retrieving user from the validation response for OAuth Token..
				String tenantDomain = MultitenantUtils.getTenantDomain(user);

				if (MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
					user = MultitenantUtils.getTenantAwareUsername(user);
				}

				Response samlResponseSample = buildSAMLResponse(issuer, user);
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
			log.error(e.getMessage(), e);
			throw new IdentityException(e.getMessage(), e);
		} catch (CarbonException e) {
			log.error(e.getMessage(), e);
			throw new CarbonException(e.getMessage(), e);
		} catch (UserStoreException e) {
			log.error(e.getMessage(), e);
			throw new UserStoreException(e.getMessage(), e);
		} catch (IdentityApplicationManagementException e) {
			log.error(e.getMessage(), e);
			throw new IdentityApplicationManagementException(e.getMessage(), e);
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

	private Response buildSAMLResponse(String issuer, String userName)
			throws IdentityException, CarbonException, UserStoreException,
			       IdentityApplicationManagementException {

		SSOServiceProviderConfigManager spConfigManager =
				SSOServiceProviderConfigManager.getInstance();
		SAMLSSOServiceProviderDO ssoIdPConfigs = spConfigManager.getServiceProvider(issuer);
		Response response = new org.opensaml.saml2.core.impl.ResponseBuilder().buildObject();

		if (ssoIdPConfigs == null) {
			IdentityPersistenceManager persistenceManager =
					null;
			try {
				persistenceManager = IdentityPersistenceManager.getPersistanceManager();
				Registry registry = (Registry) PrivilegedCarbonContext.getThreadLocalCarbonContext()
				                                                      .getRegistry(
						                                                      RegistryType.SYSTEM_CONFIGURATION);
				assert persistenceManager != null;
				ssoIdPConfigs = persistenceManager.getServiceProvider(registry, issuer);
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
				Assertion assertion = null;
				assertion = buildSAMLAssertion(ssoIdPConfigs, notOnOrAfter, userName, issuer);
				if (ssoIdPConfigs.isDoEnableEncryptedAssertion()) {
					String domainName = MultitenantUtils.getTenantDomain(userName);
					String alias = ssoIdPConfigs.getCertAlias();
					if (alias != null) {
						EncryptedAssertion encryptedAssertion =
								null;
						encryptedAssertion = SAMLSSOUtil.setEncryptedAssertion(assertion,
						                                                       EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256,
						                                                       alias,
						                                                       domainName);
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
				log.error(e.getMessage(), e);
				throw new IdentityException(e.getMessage(), e);
			} catch (CarbonException e) {
				log.error(e.getMessage(), e);
				throw new CarbonException(e.getMessage(), e);
			} catch (UserStoreException e) {
				log.error(e.getMessage(), e);
				throw new UserStoreException(e.getMessage(), e);
			} catch (IdentityApplicationManagementException e) {
				log.error(e.getMessage(), e);
				throw new IdentityApplicationManagementException(e.getMessage(), e);
			}

		}
		return response;
	}

	private Assertion buildSAMLAssertion(SAMLSSOServiceProviderDO ssoIdPConfigs,
	                                     DateTime notOnOrAfter, String userName, String issuer)
			throws IdentityException, UserStoreException, CarbonException,
			       IdentityApplicationManagementException {
		DateTime currentTime = new DateTime();
		Assertion samlAssertion = new AssertionBuilder().buildObject();
		samlAssertion.setID(SAMLSSOUtil.createID());
		samlAssertion.setVersion(SAMLVersion.VERSION_20);
		samlAssertion.setIssuer(SAMLSSOUtil.getIssuer());
		samlAssertion.setIssueInstant(currentTime);
		Subject subject = new SubjectBuilder().buildObject();
		NameID nameId = new NameIDBuilder().buildObject();
		String claimValue = null;

		if (ssoIdPConfigs.getNameIdClaimUri() != null) {
			Map<String, String> claims =
					SAMLValidatorUtil.getUserClaimValues(userName,
					                                     new String[] { ssoIdPConfigs
							                                                    .getNameIdClaimUri() },
					                                     null);
			claimValue = claims.get(ssoIdPConfigs.getNameIdClaimUri());
			nameId.setValue(claimValue);
		}

		if (claimValue == null) {
			if (ssoIdPConfigs.isUseFullyQualifiedUsername()) {
				nameId.setValue(userName);
			} else {
				nameId.setValue(MultitenantUtils.getTenantAwareUsername(userName));
			}
		}

		if (ssoIdPConfigs.getNameIDFormat() != null) {
			nameId.setFormat(ssoIdPConfigs.getNameIDFormat());
		} else {
			nameId.setFormat(NameIdentifier.EMAIL);
		}

		subject.setNameID(nameId);

		SubjectConfirmation subjectConfirmation = new SubjectConfirmationBuilder().buildObject();
		subjectConfirmation.setMethod(SAMLSSOConstants.SUBJECT_CONFIRM_BEARER);

		SubjectConfirmationData subjectConfirmationData =
				new SubjectConfirmationDataBuilder().buildObject();
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

		Map<String, String> sPClaims = getSPClaims(userName, issuer);
		if (sPClaims != null) {
			samlAssertion.getAttributeStatements().add(buildAttributeStatement(sPClaims));
		}

		AudienceRestriction audienceRestriction = new AudienceRestrictionBuilder().buildObject();
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

		return samlAssertion;
	}

	/**
	 * Retreiving the service providers claims from the back-end
	 *
	 * @param username
	 * @param issuer
	 * @return
	 * @throws IdentityException
	 * @throws CarbonException
	 * @throws UserStoreException
	 * @throws IdentityApplicationManagementException
	 */
	private Map<String, String> getSPClaims(String username, String issuer)
			throws IdentityException, CarbonException, UserStoreException,
			       IdentityApplicationManagementException {//exceptions are thrown in this currently
		Map<String, String> spClaimMap = null;
		int index = 0;

		ApplicationInfoProvider appInfo = ApplicationInfoProvider.getInstance();
		try {
			ServiceProvider serviceProvider =
					appInfo.getServiceProviderByClienId(issuer, SAMLSSO, CARBON_SUPER);
			org.wso2.carbon.identity.application.common.model.ClaimMapping[] claimMappings =
					new org.wso2.carbon.identity.application.common.model.ClaimMapping[serviceProvider
							.getClaimConfig().getClaimMappings().length];
			String[] claims =
					new String[serviceProvider.getClaimConfig().getClaimMappings().length];
			claimMappings = serviceProvider.getClaimConfig().getClaimMappings();
			for (int i = 0; i < claimMappings.length; i++) {
				claims[i] = claimMappings[i].getLocalClaim().getClaimUri();
			}
			UserRealm realm = null;
			try {
				realm = getUserRealm();
				UserStoreManager userStore = realm.getUserStoreManager();
				spClaimMap = userStore.getUserClaimValues(username, claims, null);
			} catch (CarbonException e) {
				log.error(e.getMessage(), e);
				throw new CarbonException(e.getMessage(), e);
			} catch (UserStoreException e) {
				log.error(e.getMessage(), e);
				throw new UserStoreException(e.getMessage(), e);
			}
		} catch (IdentityApplicationManagementException e) {
			log.error(e.getMessage(), e);
			throw new IdentityApplicationManagementException(e.getMessage(), e);
		}

		return spClaimMap;

	}

	private AttributeStatement buildAttributeStatement(Map<String, String> claims) {
		AttributeStatement attStmt = null;
		if (claims != null) {
			attStmt = new AttributeStatementBuilder().buildObject();
			Iterator<String> ite = claims.keySet().iterator();

			for (int i = 0; i < claims.size(); i++) {
				Attribute attrib = new AttributeBuilder().buildObject();
				String claimUri = ite.next();
				attrib.setName(claimUri);
				//setting NAMEFORMAT attribute value to basic attribute profile
				attrib.setNameFormat(SAMLSSOConstants.NAME_FORMAT_BASIC);
				// look
				// https://wiki.shibboleth.net/confluence/display/OpenSAML/OSTwoUsrManJavaAnyTypes
				XSStringBuilder stringBuilder = (XSStringBuilder) Configuration.getBuilderFactory()
				                                                               .getBuilder(
						                                                               XSString.TYPE_NAME);
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
	 * @param status
	 * @param statMsg
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

