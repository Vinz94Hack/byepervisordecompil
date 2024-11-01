package org.ps5jb.sdk.core;

public class SdkSymbolNotFoundException extends SdkRuntimeException
{
    private static final long serialVersionUID = 2290121626936470596L;
    
    public SdkSymbolNotFoundException() {
    }
    
    public SdkSymbolNotFoundException(final String message) {
        super(message);
    }
    
    public SdkSymbolNotFoundException(final Throwable cause) {
        super(cause);
    }
    
    public SdkSymbolNotFoundException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
