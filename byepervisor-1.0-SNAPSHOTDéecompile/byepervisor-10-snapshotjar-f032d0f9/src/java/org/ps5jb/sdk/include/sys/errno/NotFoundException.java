package org.ps5jb.sdk.include.sys.errno;

import org.ps5jb.sdk.core.SdkException;

public class NotFoundException extends SdkException
{
    private static final long serialVersionUID = 7555246672766984540L;
    
    public NotFoundException() {
    }
    
    public NotFoundException(final String message) {
        super(message);
    }
    
    public NotFoundException(final Throwable cause) {
        super(cause);
    }
    
    public NotFoundException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
