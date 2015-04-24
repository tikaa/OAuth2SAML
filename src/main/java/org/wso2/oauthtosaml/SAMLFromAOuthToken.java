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

import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.tools.saml.validator.dto.GeneratedResponseDTO;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

@Path("/")
public class SAMLFromAOuthToken {

    public static final String TOKEN = "token";
    public static final String ISSUER = "issuer";
    public static final String BASE64 = "base64";

    @POST
    @Path("/token")
    @Consumes("application/x-www-form-urlencoded")
    @Produces(MediaType.TEXT_PLAIN)
    public Response responseMsgPlainText(@FormParam(TOKEN) String token,
                                         @FormParam(ISSUER) String issuer,@HeaderParam("Accept-Encoding") String acceptEncoding) {
        //parameter 1 : OAuth Token , parameter 2 : issuer
        GenerateSAMLToken generateSaml = new GenerateSAMLToken();
        GeneratedResponseDTO sAMLOutPUT = null;
        String sAMLOutputString = null;

        if (acceptEncoding == null) {
            try {
                sAMLOutPUT = generateSaml.getSAMLAssertionfromOAuth(token, issuer);
                sAMLOutputString = sAMLOutPUT.getXmlResponse();
                return Response.status(200).entity(sAMLOutputString).build();
            } catch (AuthenticationFailedException e) {
                return Response.status(401).entity("Authentication failed for the given oauth token" + e).build();
            }
        } else if (acceptEncoding.contains(BASE64))  {
            try {
                sAMLOutPUT = generateSaml.getSAMLAssertionfromOAuth(token, issuer);
                sAMLOutputString = sAMLOutPUT.getEncodedResponse();
                return Response.status(200).entity(sAMLOutputString).build();
            } catch (AuthenticationFailedException e) {
                return Response.status(401).entity("Authentication failed for the given oauth token" + e).build();
            }
        } else {
            return Response.status(400).entity("The Encoding type you requested is currently not supported").build();
        }

    }
}
