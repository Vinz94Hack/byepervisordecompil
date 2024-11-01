package org.ps5jb.sdk.include.sys;

import org.ps5jb.sdk.core.SdkException;
import org.ps5jb.sdk.core.Pointer;
import org.ps5jb.sdk.include.sys.stat.StatType;
import org.ps5jb.sdk.lib.LibKernel;

public class Stat
{
    private final LibKernel libKernel;
    private final ErrNo errNo;
    
    public Stat(final LibKernel libKernel) {
        this.libKernel = libKernel;
        this.errNo = new ErrNo(this.libKernel);
    }
    
    public StatType getFileStatus(final int fd) throws SdkException {
        final Pointer buf = Pointer.calloc(120L);
        try {
            final int ret = this.libKernel.fstat(fd, buf);
            if (ret == -1) {
                throw this.errNo.getLastException(this.getClass(), "getFileStatus", new Object[0]);
            }
            return new StatType(buf);
        }
        catch (final SdkException | RuntimeException | Error e) {
            buf.free();
            throw e;
        }
    }
    
    public StatType getStatus(final String path) throws SdkException {
        final Pointer buf = Pointer.calloc(120L);
        try {
            final int ret = this.libKernel.stat(path, buf);
            if (ret == -1) {
                throw this.errNo.getLastException(this.getClass(), "getStatus", new Object[0]);
            }
            return new StatType(buf);
        }
        catch (final SdkException | RuntimeException | Error e) {
            buf.free();
            throw e;
        }
    }
}
