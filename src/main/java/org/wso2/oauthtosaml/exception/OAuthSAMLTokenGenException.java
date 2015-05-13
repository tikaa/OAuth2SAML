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
package org.wso2.oauthtosaml.exception;

import org.wso2.oauthtosaml.ErrorCode;

public class OAuthSAMLTokenGenException extends Exception {

    private ErrorCode errorCode;

    private static final long serialVersionUID = 1L;

    public OAuthSAMLTokenGenException() {
        super();
        errorCode = ErrorCode.NONE;
    }

    public OAuthSAMLTokenGenException(String message, ErrorCode code) {
        super(message);
        errorCode = code;
    }

    public OAuthSAMLTokenGenException(String message, Throwable cause, ErrorCode code) {
        super(message, cause);
        errorCode = code;
    }

    public ErrorCode getErrorCode() {
        return errorCode;
    }
    
}
