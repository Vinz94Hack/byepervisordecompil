package org.ps5jb.sdk.core;

public class SdkRuntimeException extends RuntimeException
{
    private static final long serialVersionUID = 7145867944382620029L;
    private final Throwable cause;
    
    public SdkRuntimeException() {
        this(null, null);
    }
    
    public SdkRuntimeException(final String message) {
        this(message, null);
    }
    
    public SdkRuntimeException(final Throwable cause) {
        this(null, cause);
    }
    
    public SdkRuntimeException(final String message, final Throwable cause) {
        super(message);
        this.cause = cause;
    }
    
    public Throwable getCause() {
        return this.cause;
    }
}
