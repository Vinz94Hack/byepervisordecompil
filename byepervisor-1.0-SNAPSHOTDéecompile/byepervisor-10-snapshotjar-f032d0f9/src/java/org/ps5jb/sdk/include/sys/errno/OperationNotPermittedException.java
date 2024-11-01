package org.ps5jb.sdk.include.sys.errno;

import org.ps5jb.sdk.core.SdkException;

public class OperationNotPermittedException extends SdkException
{
    private static final long serialVersionUID = 3168161600843242728L;
    
    public OperationNotPermittedException() {
    }
    
    public OperationNotPermittedException(final String message) {
        super(message);
    }
    
    public OperationNotPermittedException(final Throwable cause) {
        super(cause);
    }
    
    public OperationNotPermittedException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
