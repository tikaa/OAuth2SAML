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

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.oauthtosaml.exception.OAuthSAMLTokenGenException;

@Path("/")
public class SAMLFromAOuthToken {

	public static final String TOKEN = "token";
	public static final String ISSUER = "issuer";
	public static final String BASE64 = "base64";
	public static final String ENCODING = "encoding";
	
    private static Log log = LogFactory.getLog(SAMLFromAOuthToken.class);


	@POST
	@Path("/token")
	@Consumes("application/x-www-form-urlencoded")
	@Produces(MediaType.TEXT_PLAIN)
	public Response responseMsgPlainText(@FormParam(TOKEN) String token,
	                                     @FormParam(ISSUER) String issuer,
	                                     @FormParam(ENCODING) String acceptEncoding) {
		GenerateSAMLToken generateSaml = new GenerateSAMLToken();

		String sAMLOutputString;

		if (acceptEncoding == null) {
			try {
				sAMLOutputString = generateSaml.getSAMLAssertionFromOAuth(token, issuer);
				return Response.status(200).entity(sAMLOutputString).build();

            } catch (OAuthSAMLTokenGenException e) {
                log.error("Error occurred while serving the request for issuer : " + issuer, e);

                switch (e.getErrorCode()) {

                case AUTHENTICATION_FAILED:
                    return Response
                            .status(401)
                            .entity("Authentication failed for the given oauth token" + "\n" + e
                                    + "\n").build();

                case CONFIGURATION_ERROR:
                    return Response
                            .status(500)
                            .entity("Error in the configuration. please refer carbon logs for more details"
                                    + "\n" + e + "\n").build();
                default:
                    return Response
                            .status(500)
                            .entity("Identity Server Error has occurred, please refer carbon logs for more details"
                                    + "\n" + e + "\n").build();
                }
            }
		} else if (acceptEncoding.equals(BASE64)) {
			try {
				sAMLOutputString =
						SAMLSSOUtil.encode(generateSaml.getSAMLAssertionFromOAuth(token, issuer));
				return Response.status(200).entity(sAMLOutputString).build();
            } catch (OAuthSAMLTokenGenException e) {
                log.error("Error occurred while serving the request for issuer : " + issuer, e);

                switch (e.getErrorCode()) {

                case AUTHENTICATION_FAILED:
                    return Response
                            .status(401)
                            .entity("Authentication failed for the given oauth token" + "\n" + e
                                    + "\n").build();

                case CONFIGURATION_ERROR:
                    return Response
                            .status(500)
                            .entity("Error in the configuration. please refer carbon logs for more details"
                                    + "\n" + e + "\n").build();
                default:
                    return Response
                            .status(500)
                            .entity("Identity Server Error has occurred, please refer carbon logs for more details"
                                    + "\n" + e + "\n").build();
                }
            }
		} else {
			return Response.status(406)
			               .entity("The Encoding type you requested is currently not supported" +
			                       "\n").build();
		}

	}
}
