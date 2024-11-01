package org.ps5jb.sdk.include.sys;

import org.ps5jb.sdk.core.SdkException;
import org.ps5jb.sdk.include.sys.fcntl.OpenFlag;
import org.ps5jb.sdk.lib.LibKernel;

public class FCntl
{
    private final LibKernel libKernel;
    private final ErrNo errNo;
    
    public FCntl(final LibKernel libKernel) {
        this.libKernel = libKernel;
        this.errNo = new ErrNo(this.libKernel);
    }
    
    public int open(final String path, final OpenFlag... flags) throws SdkException {
        final int fd = this.libKernel.open(path, OpenFlag.or(flags));
        if (fd == -1) {
            throw this.errNo.getLastException(this.getClass(), "open", path);
        }
        return fd;
    }
    
    public void close(final int fd) throws SdkException {
        final int ret = this.libKernel.close(fd);
        if (ret == -1) {
            throw this.errNo.getLastException(this.getClass(), "close", Integer.toString(fd));
        }
    }
}
