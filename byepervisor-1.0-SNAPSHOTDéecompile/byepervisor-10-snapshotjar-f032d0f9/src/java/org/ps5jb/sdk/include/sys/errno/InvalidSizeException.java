package org.ps5jb.sdk.include.sys.errno;

import org.ps5jb.sdk.core.SdkException;

public class InvalidSizeException extends SdkException
{
    private static final long serialVersionUID = 8682353427481561476L;
    
    public InvalidSizeException() {
    }
    
    public InvalidSizeException(final String message) {
        super(message);
    }
    
    public InvalidSizeException(final Throwable cause) {
        super(cause);
    }
    
    public InvalidSizeException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
