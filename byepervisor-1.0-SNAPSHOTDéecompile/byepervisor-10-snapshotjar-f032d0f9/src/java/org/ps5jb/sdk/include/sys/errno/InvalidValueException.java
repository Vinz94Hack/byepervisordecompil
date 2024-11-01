package org.ps5jb.sdk.include.sys.errno;

import org.ps5jb.sdk.core.SdkException;

public class InvalidValueException extends SdkException
{
    private static final long serialVersionUID = 8067711595828305814L;
    
    public InvalidValueException() {
    }
    
    public InvalidValueException(final String message) {
        super(message);
    }
    
    public InvalidValueException(final Throwable cause) {
        super(cause);
    }
    
    public InvalidValueException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
