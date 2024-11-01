package org.ps5jb.sdk.core;

public class SdkSoftwareVersionUnsupportedException extends SdkRuntimeException
{
    private static final long serialVersionUID = -2958319099920522L;
    
    public SdkSoftwareVersionUnsupportedException() {
    }
    
    public SdkSoftwareVersionUnsupportedException(final String message) {
        super(message);
    }
    
    public SdkSoftwareVersionUnsupportedException(final Throwable cause) {
        super(cause);
    }
    
    public SdkSoftwareVersionUnsupportedException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
