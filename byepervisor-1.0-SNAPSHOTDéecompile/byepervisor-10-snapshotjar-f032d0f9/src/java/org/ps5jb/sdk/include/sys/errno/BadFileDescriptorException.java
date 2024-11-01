package org.ps5jb.sdk.include.sys.errno;

import org.ps5jb.sdk.core.SdkException;

public class BadFileDescriptorException extends SdkException
{
    private static final long serialVersionUID = -6609560787806393785L;
    
    public BadFileDescriptorException() {
    }
    
    public BadFileDescriptorException(final String message) {
        super(message);
    }
    
    public BadFileDescriptorException(final Throwable cause) {
        super(cause);
    }
    
    public BadFileDescriptorException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
