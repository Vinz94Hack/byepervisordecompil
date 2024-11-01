package org.ps5jb.client.payloads.umtx.impl1;

import org.ps5jb.sdk.core.SdkRuntimeException;
import org.ps5jb.client.payloads.umtx.common.DebugStatus;
import org.ps5jb.sdk.core.SdkException;
import org.ps5jb.sdk.include.UniStd;
import org.ps5jb.sdk.core.Pointer;
import org.ps5jb.sdk.include.ErrNo;
import org.ps5jb.sdk.lib.LibKernel;

class CheckMemoryPipe
{
    private static final long CHECK_SIZE = 1L;
    private static volatile CheckMemoryPipe INSTANCE;
    private final LibKernel libKernel;
    private final ErrNo errNo;
    private final int[] checkMemoryPipe;
    private final Pointer checkMemoryBuf;
    
    CheckMemoryPipe() throws SdkException {
        this.libKernel = new LibKernel();
        this.errNo = new ErrNo(this.libKernel);
        final UniStd uniStd = new UniStd(this.libKernel);
        this.checkMemoryPipe = uniStd.pipe();
        this.checkMemoryBuf = Pointer.calloc(4096L);
    }
    
    void free() {
        if (this.checkMemoryBuf != null) {
            this.checkMemoryBuf.free();
        }
        if (this.checkMemoryPipe != null && this.checkMemoryPipe.length > 1) {
            this.libKernel.close(this.checkMemoryPipe[0]);
            this.libKernel.close(this.checkMemoryPipe[1]);
        }
        this.libKernel.closeLibrary();
    }
    
    boolean checkMemoryAccessible(final Pointer ptr) {
        final long checkSize = 1L;
        final long actualWriteSize = this.libKernel.write(this.checkMemoryPipe[1], ptr, checkSize);
        final boolean result = actualWriteSize == checkSize;
        if (!result) {
            DebugStatus.error("Memory read check of size " + checkSize + " bytes failed for address " + ptr + "; Error code: " + this.errNo.getLastError() + "; Return value: " + actualWriteSize);
        }
        if (actualWriteSize > 0L) {
            final long actualReadSize = this.libKernel.read(this.checkMemoryPipe[0], this.checkMemoryBuf, checkSize);
            if (actualReadSize != actualWriteSize) {
                DebugStatus.error("Pipe read failed during memory check of address " + ptr + "; Error code: " + this.errNo.getLastError() + "; Return value: " + actualReadSize);
            }
        }
        return result;
    }
    
    static CheckMemoryPipe getInstance() {
        if (CheckMemoryPipe.INSTANCE == null) {
            synchronized (CheckMemoryPipe.class) {
                if (CheckMemoryPipe.INSTANCE == null) {
                    try {
                        CheckMemoryPipe.INSTANCE = new CheckMemoryPipe();
                    }
                    catch (final SdkException e) {
                        throw new SdkRuntimeException((Throwable)e);
                    }
                }
            }
        }
        return CheckMemoryPipe.INSTANCE;
    }
}
