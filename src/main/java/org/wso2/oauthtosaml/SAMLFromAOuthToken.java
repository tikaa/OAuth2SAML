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

import org.wso2.carbon.CarbonException;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.user.api.UserStoreException;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

@Path("/")
public class SAMLFromAOuthToken {

	public static final String TOKEN = "token";
	public static final String ISSUER = "issuer";
	public static final String BASE64 = "base64";
	public static final String ENCODING = "encoding";

	@POST
	@Path("/token")
	@Consumes("application/x-www-form-urlencoded")
	@Produces(MediaType.TEXT_PLAIN)
	public Response responseMsgPlainText(@FormParam(TOKEN) String token,
	                                     @FormParam(ISSUER) String issuer,
	                                     @FormParam(ENCODING) String acceptEncoding) {
		GenerateSAMLToken generateSaml = new GenerateSAMLToken();

		String sAMLOutputString = null;

		if (acceptEncoding == null) {
			try {
				sAMLOutputString = generateSaml.getSAMLAssertionFromOAuth(token, issuer);
				return Response.status(200).entity(sAMLOutputString).build();
			} catch (AuthenticationFailedException e) {
				return Response.status(401)
				               .entity("Authentication failed for the given oauth token" + "\n" +
				                       e + "\n").build();
			} catch (CarbonException e) {
				return Response.status(500)
				               .entity("Carbon Server Error has occurred, please refer carbon logs for more details" +
				                       "\n" + e + "\n").build();
			} catch (IdentityException e) {
				return Response.status(500)
				               .entity("Identity Server Error has occurred, please refer carbon logs for more details" +
				                       "\n" + e + "\n").build();
			} catch (UserStoreException e) {
				return Response.status(500)
				               .entity("UserStore Error has occurred, please refer carbon logs for more details" +
				                       "\n" + e + "\n").build();
			} catch (IdentityApplicationManagementException e) {
				return Response.status(500)
				               .entity("Identity Server Error has occurred, please refer carbon logs for more details" +
				                       "\n" + e + "\n").build();
			}
		} else if (acceptEncoding.equals(BASE64)) {
			try {
				SAMLSSOUtil samlssoUtil = new SAMLSSOUtil();
				sAMLOutputString =
						samlssoUtil.encode(generateSaml.getSAMLAssertionFromOAuth(token, issuer));
				return Response.status(200).entity(sAMLOutputString).build();
			} catch (AuthenticationFailedException e) {
				return Response.status(401)
				               .entity("Authentication failed for the given oauth token" + "\n" +
				                       e + "\n").build();
			} catch (CarbonException e) {
				return Response.status(500)
				               .entity("Carbon Server Error has occurred, please refer carbon logs for more details" +
				                       "\n" + e + "\n").build();
			} catch (IdentityException e) {
				return Response.status(500)
				               .entity("Identity Server Error has occurred, please refer carbon logs for more details" +
				                       "\n" + e + "\n").build();
			} catch (UserStoreException e) {
				return Response.status(500)
				               .entity("UserStore Error has occurred, please refer carbon logs for more details" +
				                       "\n" + e + "\n").build();
			} catch (IdentityApplicationManagementException e) {
				return Response.status(500)
				               .entity("Identity Server Error has occurred, please refer carbon logs for more details" +
				                       "\n" + e + "\n").build();
			}
		} else {
			return Response.status(406)
			               .entity("The Encoding type you requested is currently not supported" +
			                       "\n").build();
		}

	}
}
