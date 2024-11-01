package org.ps5jb.sdk.include.sys;

import org.ps5jb.sdk.core.SdkException;
import org.ps5jb.sdk.lib.LibKernel;

public class IocCom
{
    public static final long IOCPARM_SHIFT = 13L;
    public static final long IOCPARM_MASK = 8191L;
    public static final long IOC_VOID = 536870912L;
    public static final long IOC_OUT = 1073741824L;
    public static final long IOC_IN = -2147483648L;
    private final LibKernel libKernel;
    private final ErrNo errNo;
    
    public IocCom(final LibKernel libKernel) {
        this.libKernel = libKernel;
        this.errNo = new ErrNo(this.libKernel);
    }
    
    public static long _IOC(final long inout, final long group, final long num, final long len) {
        return inout | (len & 0x1FFFL) << 16 | group << 8 | num;
    }
    
    public static long _IOW(final long group, final long num, final long type_size) {
        return _IOC(-2147483648L, group, num, type_size);
    }
    
    public int ioctl(final int fd, final long request, final long argp) throws SdkException {
        final int ret = this.libKernel.ioctl(fd, request, argp);
        if (ret == -1) {
            throw this.errNo.getLastException(this.getClass(), "ioctl", new Object[0]);
        }
        return ret;
    }
}
