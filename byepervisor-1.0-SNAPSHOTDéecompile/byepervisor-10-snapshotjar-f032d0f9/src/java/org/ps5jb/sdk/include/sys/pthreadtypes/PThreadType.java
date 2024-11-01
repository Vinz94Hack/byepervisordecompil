package org.ps5jb.sdk.include.sys.pthreadtypes;

import org.ps5jb.sdk.core.Pointer;

public class PThreadType
{
    private Pointer pthread;
    
    public PThreadType(final Pointer pthread) {
        this.pthread = pthread;
    }
    
    public Pointer getPthread() {
        return this.pthread;
    }
}
