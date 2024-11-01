package org.ps5jb.sdk.include;

import org.ps5jb.sdk.include.sys.errno.OutOfMemoryException;
import org.ps5jb.sdk.include.sys.errno.BadFileDescriptorException;
import org.ps5jb.sdk.include.sys.errno.InvalidValueException;
import org.ps5jb.sdk.core.Pointer;
import org.ps5jb.sdk.core.SdkException;
import org.ps5jb.sdk.core.SdkRuntimeException;
import org.ps5jb.sdk.include.sys.errno.OperationNotPermittedException;
import org.ps5jb.sdk.include.sys.ErrNo;
import org.ps5jb.sdk.lib.LibKernel;

public class UniStd
{
    private final LibKernel libKernel;
    private final ErrNo errNo;
    
    public UniStd(final LibKernel libKernel) {
        this.libKernel = libKernel;
        this.errNo = new ErrNo(this.libKernel);
    }
    
    public int getuid() {
        return this.libKernel.getuid();
    }
    
    public void setuid(final int uid) throws OperationNotPermittedException {
        final int ret = this.libKernel.setuid(uid);
        if (ret != -1) {
            return;
        }
        final SdkException ex = this.errNo.getLastException(this.getClass(), "setuid", new Object[0]);
        if (ex instanceof OperationNotPermittedException) {
            throw (OperationNotPermittedException)ex;
        }
        throw new SdkRuntimeException(ex.getMessage(), (Throwable)ex);
    }
    
    public int getpid() {
        return this.libKernel.getpid();
    }
    
    public int[] pipe() throws SdkException {
        final Pointer fildes = Pointer.calloc(8L);
        try {
            final int ret = this.libKernel.pipe(fildes);
            if (ret == -1) {
                throw this.errNo.getLastException(this.getClass(), "pipe", new Object[0]);
            }
            return new int[] { fildes.read4(), fildes.read4(4L) };
        }
        finally {
            fildes.free();
        }
    }
    
    public void ftruncate(final int fd, final long length) throws InvalidValueException, BadFileDescriptorException, OutOfMemoryException {
        final int ret = this.libKernel.ftruncate(fd, length);
        if (ret != -1) {
            return;
        }
        final SdkException ex = this.errNo.getLastException(this.getClass(), "ftruncate", new Object[0]);
        if (ex instanceof InvalidValueException) {
            throw (InvalidValueException)ex;
        }
        if (ex instanceof BadFileDescriptorException) {
            throw (BadFileDescriptorException)ex;
        }
        if (ex instanceof OutOfMemoryException) {
            throw (OutOfMemoryException)ex;
        }
        throw new SdkRuntimeException(ex.getMessage(), (Throwable)ex);
    }
    
    public void usleep(final long microseconds) throws SdkException {
        final int ret = this.libKernel.usleep(microseconds);
        if (ret == -1) {
            throw this.errNo.getLastException(this.getClass(), "usleep", new Object[0]);
        }
    }
}
