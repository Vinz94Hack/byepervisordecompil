package org.ps5jb.sdk.include.sys.errno;

import org.ps5jb.sdk.core.SdkException;

public class MemoryFaultException extends SdkException
{
    private static final long serialVersionUID = 2381337152984935037L;
    
    public MemoryFaultException() {
    }
    
    public MemoryFaultException(final String message) {
        super(message);
    }
    
    public MemoryFaultException(final Throwable cause) {
        super(cause);
    }
    
    public MemoryFaultException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
