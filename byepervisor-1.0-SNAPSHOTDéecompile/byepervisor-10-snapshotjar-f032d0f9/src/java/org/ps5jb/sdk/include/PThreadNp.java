package org.ps5jb.sdk.include;

import org.ps5jb.sdk.core.SdkException;
import org.ps5jb.sdk.core.SdkRuntimeException;
import org.ps5jb.sdk.include.sys.errno.NotFoundException;
import org.ps5jb.sdk.include.sys.pthreadtypes.PThreadType;
import org.ps5jb.sdk.include.sys.ErrNo;
import org.ps5jb.sdk.lib.LibKernel;

public class PThreadNp
{
    private final LibKernel libKernel;
    private final ErrNo errNo;
    
    public PThreadNp(final LibKernel libKernel) {
        this.libKernel = libKernel;
        this.errNo = new ErrNo(this.libKernel);
    }
    
    public void rename(final PThreadType tid, final String name) throws NotFoundException {
        final int ret = this.libKernel.pthread_rename_np(tid.getPthread(), name);
        if (ret == 0) {
            return;
        }
        final SdkException ex = this.errNo.getLastException(this.getClass(), "pthread_rename_np", new Object[0]);
        if (ex instanceof NotFoundException) {
            throw (NotFoundException)ex;
        }
        throw new SdkRuntimeException(ex.getMessage(), (Throwable)ex);
    }
}
