package org.ps5jb.sdk.include;

import org.ps5jb.sdk.include.sys.pthreadtypes.PThreadType;
import org.ps5jb.sdk.include.sys.ErrNo;
import org.ps5jb.sdk.lib.LibKernel;

public class PThread
{
    private final LibKernel libKernel;
    private final ErrNo errNo;
    
    public PThread(final LibKernel libKernel) {
        this.libKernel = libKernel;
        this.errNo = new ErrNo(this.libKernel);
    }
    
    public PThreadType self() {
        return new PThreadType(this.libKernel.pthread_self());
    }
}
