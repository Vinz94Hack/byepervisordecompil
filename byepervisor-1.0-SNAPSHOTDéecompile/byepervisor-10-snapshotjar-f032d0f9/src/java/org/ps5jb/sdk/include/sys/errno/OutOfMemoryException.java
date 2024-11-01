package org.ps5jb.sdk.include.sys.errno;

import org.ps5jb.sdk.core.SdkException;

public class OutOfMemoryException extends SdkException
{
    private static final long serialVersionUID = 2381337152984935037L;
    
    public OutOfMemoryException() {
    }
    
    public OutOfMemoryException(final String message) {
        super(message);
    }
    
    public OutOfMemoryException(final Throwable cause) {
        super(cause);
    }
    
    public OutOfMemoryException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
