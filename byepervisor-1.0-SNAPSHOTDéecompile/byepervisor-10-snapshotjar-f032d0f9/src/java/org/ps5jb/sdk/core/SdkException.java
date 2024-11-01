package org.ps5jb.sdk.core;

public class SdkException extends Exception
{
    private static final long serialVersionUID = -3777195078835747727L;
    private final Throwable cause;
    
    public SdkException() {
        this(null, null);
    }
    
    public SdkException(final String message) {
        this(message, null);
    }
    
    public SdkException(final Throwable cause) {
        this(null, cause);
    }
    
    public SdkException(final String message, final Throwable cause) {
        super(message);
        this.cause = cause;
    }
    
    public Throwable getCause() {
        return this.cause;
    }
}
