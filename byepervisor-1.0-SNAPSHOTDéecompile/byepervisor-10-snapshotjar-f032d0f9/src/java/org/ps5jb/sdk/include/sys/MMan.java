package org.ps5jb.sdk.include.sys;

import org.ps5jb.sdk.include.sys.errno.OperationNotPermittedException;
import org.ps5jb.sdk.core.SdkRuntimeException;
import org.ps5jb.sdk.include.sys.errno.InvalidValueException;
import org.ps5jb.sdk.include.sys.mman.MappingFlag;
import org.ps5jb.sdk.include.sys.mman.ProtectionFlag;
import org.ps5jb.sdk.core.SdkException;
import org.ps5jb.sdk.include.sys.fcntl.OpenFlag;
import org.ps5jb.sdk.lib.LibKernel;
import org.ps5jb.sdk.core.Pointer;

public class MMan
{
    private static final Pointer SHM_ANON;
    private static final Pointer MAP_FAILED;
    private final LibKernel libKernel;
    private final ErrNo errNo;
    
    public MMan(final LibKernel libKernel) {
        this.libKernel = libKernel;
        this.errNo = new ErrNo(this.libKernel);
    }
    
    public int sharedMemoryOpen(final String path, final int mode, final OpenFlag... flags) throws SdkException {
        final Pointer pathPtr = Pointer.fromString(path);
        try {
            return this.shmOpen(pathPtr, flags, mode);
        }
        finally {
            pathPtr.free();
        }
    }
    
    public int sharedMemoryOpenAnonymous(final int mode, final OpenFlag... flags) throws SdkException {
        return this.shmOpen(MMan.SHM_ANON, flags, mode);
    }
    
    private int shmOpen(final Pointer path, final OpenFlag[] flags, final int mode) throws SdkException {
        final int ret = this.libKernel.shm_open(path, OpenFlag.or(flags), mode);
        if (ret == -1) {
            throw this.errNo.getLastException(this.getClass(), "shmOpen", new Object[0]);
        }
        return ret;
    }
    
    public void sharedMemoryUnlink(final String path) throws SdkException {
        final Pointer pathPtr = Pointer.fromString(path);
        try {
            final int ret = this.libKernel.shm_unlink(pathPtr);
            if (ret == -1) {
                throw this.errNo.getLastException(this.getClass(), "sharedMemoryUnlink", new Object[0]);
            }
        }
        finally {
            pathPtr.free();
        }
    }
    
    public Pointer memoryMap(final Pointer addr, final long len, final ProtectionFlag[] prot, final MappingFlag[] flags, final int fd, final long offset) throws SdkException {
        final Pointer ret = this.libKernel.mmap(addr, len, ProtectionFlag.or(prot), MappingFlag.or(flags), fd, offset);
        if (MMan.MAP_FAILED.equals(ret)) {
            throw this.errNo.getLastException(this.getClass(), "memoryMap", new Object[0]);
        }
        return ret;
    }
    
    public void memoryUnmap(final Pointer addr, final long len) throws InvalidValueException {
        final long ret = this.libKernel.munmap(addr, len);
        if (ret != -1L) {
            return;
        }
        final SdkException ex = this.errNo.getLastException(this.getClass(), "memoryUnmap", new Object[0]);
        if (ex instanceof InvalidValueException) {
            throw (InvalidValueException)ex;
        }
        throw new SdkRuntimeException(ex.getMessage(), (Throwable)ex);
    }
    
    public void memoryProtect(final Pointer addr, final long len, final ProtectionFlag... prot) throws InvalidValueException, OperationNotPermittedException {
        final long ret = this.libKernel.mprotect(addr, len, ProtectionFlag.or(prot));
        if (ret != -1L) {
            return;
        }
        final SdkException ex = this.errNo.getLastException(this.getClass(), "memoryProtect", new Object[0]);
        if (ex instanceof InvalidValueException) {
            throw (InvalidValueException)ex;
        }
        if (ex instanceof OperationNotPermittedException) {
            throw (OperationNotPermittedException)ex;
        }
        throw new SdkRuntimeException(ex.getMessage(), (Throwable)ex);
    }
    
    static {
        SHM_ANON = Pointer.valueOf(1L);
        MAP_FAILED = Pointer.valueOf(-1L);
    }
}
