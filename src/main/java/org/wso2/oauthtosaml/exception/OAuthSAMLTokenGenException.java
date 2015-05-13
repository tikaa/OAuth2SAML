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
