package org.ps5jb.sdk.include.sys.errno;

import org.ps5jb.sdk.core.SdkException;

public class DeadlockException extends SdkException
{
    private static final long serialVersionUID = 7109044860280702256L;
    
    public DeadlockException() {
    }
    
    public DeadlockException(final String message) {
        super(message);
    }
    
    public DeadlockException(final Throwable cause) {
        super(cause);
    }
    
    public DeadlockException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
