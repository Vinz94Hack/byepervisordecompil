package org.ps5jb.client.payloads.umtx.common;

import java.io.ObjectOutputStream;
import java.io.IOException;
import java.io.NotActiveException;
import java.io.ObjectInputStream;
import org.ps5jb.sdk.core.SdkRuntimeException;
import org.ps5jb.sdk.core.SdkException;
import org.ps5jb.sdk.include.UniStd;
import org.ps5jb.sdk.lib.LibKernel;
import org.ps5jb.sdk.core.Pointer;
import org.ps5jb.loader.KernelAccessor;

public class KernelAccessorSlow implements KernelAccessor
{
    private static final long OFFSET_IOV_BASE = 0L;
    private static final long OFFSET_IOV_LEN = 8L;
    private static final long SIZE_IOV = 16L;
    private static final long OFFSET_UIO_RESID = 24L;
    private static final long OFFSET_UIO_SEGFLG = 32L;
    private static final long OFFSET_UIO_RW = 36L;
    private final CommandProcessor commandProcessor;
    private final Pointer kstack;
    private final LibKernel libKernel;
    private long kernelBase;
    public int pipeReadFd;
    public int pipeWriteFd;
    public Pointer pipeScratchBuf;
    public Pointer readValue;
    public Pointer writeValue;
    
    public KernelAccessorSlow(final CommandProcessor commandProcessor, final Pointer kstack) throws SdkException {
        this.commandProcessor = commandProcessor;
        this.kstack = kstack;
        this.libKernel = new LibKernel();
        final UniStd unistd = new UniStd(this.libKernel);
        final int[] pipeFds = unistd.pipe();
        this.pipeReadFd = pipeFds[0];
        this.pipeWriteFd = pipeFds[1];
        this.pipeScratchBuf = Pointer.calloc(65552L);
        this.readValue = this.pipeScratchBuf.inc(65536L);
        this.writeValue = this.readValue.inc(8L);
    }
    
    public void free() {
        if (this.pipeScratchBuf != null) {
            this.pipeScratchBuf.free();
            this.pipeScratchBuf = null;
        }
        if (this.pipeReadFd != -1) {
            this.libKernel.close(this.pipeReadFd);
            this.pipeReadFd = -1;
        }
        if (this.pipeWriteFd != -1) {
            this.libKernel.close(this.pipeWriteFd);
            this.pipeWriteFd = -1;
        }
        this.libKernel.closeLibrary();
    }
    
    private void sendCommand(final int cmd, final long uaddr, final long kaddr, final int len) {
        if (DebugStatus.isTraceEnabled()) {
            DebugStatus.trace("Sending command (" + cmd + ", 0x" + Long.toHexString(uaddr) + ", 0x" + Long.toHexString(kaddr) + "), len=" + len + ", read=" + this.commandProcessor.readCounter.get() + ", write=" + this.commandProcessor.writeCounter.get());
        }
        this.commandProcessor.len.set(len);
        this.commandProcessor.cmd.set(cmd);
        this.sleep(100L);
    }
    
    private boolean swapIovInKstack(final long origIovBase, final long newIovBase, final int uioSegFlg, final int uioRw, final int len) {
        if (DebugStatus.isTraceEnabled()) {
            DebugStatus.trace("Searching " + ((uioRw == 0) ? "read" : "write") + " iov pattern 0x" + Long.toHexString(origIovBase) + " (" + len + " bytes)");
        }
        long stack_iov_offset = -1L;
        final long scan_start = 12288L;
        final long scan_max = 16336L;
        for (long i = 12288L; i < 16336L; i += 4L) {
            final long possible_iov_base = this.kstack.read8(i + 0L);
            final long possible_iov_len = this.kstack.read8(i + 8L);
            if (possible_iov_base == origIovBase && possible_iov_len == len) {
                final long possible_uio_resid = this.kstack.read8(i + 16L + 24L);
                final int possible_uio_segflg = this.kstack.read4(i + 16L + 32L);
                final int possible_uio_rw = this.kstack.read4(i + 16L + 36L);
                if (possible_uio_resid == len && possible_uio_segflg == 0 && possible_uio_rw == uioRw) {
                    if (DebugStatus.isDebugEnabled()) {
                        DebugStatus.debug("found iov on stack @ 0x" + Long.toHexString(i));
                    }
                    stack_iov_offset = i;
                    break;
                }
            }
        }
        if (stack_iov_offset < 0L) {
            DebugStatus.trace("iov not found in stack");
            return false;
        }
        this.kstack.write8(stack_iov_offset + 0L, newIovBase);
        this.kstack.write4(stack_iov_offset + 16L + 32L, uioSegFlg);
        return true;
    }
    
    void slowCopyOut(final long kaddr, final Pointer uaddr, final int len) {
        long totalGarbageSize = 0L;
        for (long i = 0L; i < 65536L; i += 4096L) {
            final long writeBytes = this.libKernel.write(this.pipeWriteFd, this.pipeScratchBuf, 4096L);
            if (writeBytes != 4096L) {
                throw new SdkRuntimeException("Unable to fill write pipe with garbage data");
            }
            if (DebugStatus.isTraceEnabled()) {
                DebugStatus.trace("Written " + writeBytes + " to pipe fd #" + this.pipeWriteFd);
            }
            totalGarbageSize += writeBytes;
        }
        if (DebugStatus.isTraceEnabled()) {
            DebugStatus.trace("Total garbage bytes " + totalGarbageSize);
        }
        this.sendCommand(1, uaddr.addr(), kaddr, len);
        if (!this.swapIovInKstack(this.pipeScratchBuf.addr(), kaddr, 1, 1, len)) {
            final SdkRuntimeException rootEx = new SdkRuntimeException("Unable to swap iov, pattern not found");
            final SdkRuntimeException causeEx = new SdkRuntimeException("Unable to unblock the write pipe following a failed read attempt. Deadlock may occur", (Throwable)rootEx);
            if (this.libKernel.read(this.pipeReadFd, this.pipeScratchBuf, totalGarbageSize) != totalGarbageSize) {
                throw causeEx;
            }
            if (this.libKernel.read(this.pipeReadFd, uaddr, len) != len) {
                throw causeEx;
            }
            throw rootEx;
        }
        else {
            final long readGarbageSize = this.libKernel.read(this.pipeReadFd, this.pipeScratchBuf, totalGarbageSize);
            if (readGarbageSize != totalGarbageSize) {
                throw new SdkRuntimeException("Unable to unlock the write pipe. Read: " + readGarbageSize + ". Expected: " + totalGarbageSize);
            }
            if (DebugStatus.isTraceEnabled()) {
                DebugStatus.trace("Read " + readGarbageSize + " garbage bytes");
            }
            final long read = this.libKernel.read(this.pipeReadFd, uaddr, len);
            if (read != len) {
                throw new SdkRuntimeException("Unexpected number of bytes read: " + read + " instead of " + len);
            }
            if (DebugStatus.isDebugEnabled()) {
                DebugStatus.debug("Read " + read + " bytes");
            }
            while (this.commandProcessor.cmd.get() != 0) {
                this.sleep(50L);
            }
        }
    }
    
    void slowCopyIn(final Pointer uaddr, final long kaddr, final int len) {
        this.sendCommand(2, uaddr.addr(), kaddr, len);
        if (!this.swapIovInKstack(this.pipeScratchBuf.addr(), kaddr, 1, 0, len)) {
            final SdkRuntimeException rootEx = new SdkRuntimeException("Unable to swap iov, pattern not found");
            final SdkRuntimeException causeEx = new SdkRuntimeException("Unable to unblock the read pipe following a failed write attempt. Deadlock may occur", (Throwable)rootEx);
            if (this.libKernel.write(this.pipeWriteFd, uaddr, len) != len) {
                throw causeEx;
            }
            throw rootEx;
        }
        else {
            final long written = this.libKernel.write(this.pipeWriteFd, uaddr, len);
            if (written != len) {
                throw new SdkRuntimeException("Unexpected number of bytes written: " + written + " instead of " + len);
            }
            while (this.commandProcessor.cmd.get() != 0) {
                this.sleep(50L);
            }
        }
    }
    
    private void sleep(final long millis) {
        try {
            Thread.sleep(millis);
        }
        catch (final InterruptedException ex) {}
    }
    
    public byte read1(final long kernelAddress) {
        this.slowCopyOut(kernelAddress, this.readValue, 1);
        return this.readValue.read1();
    }
    
    public short read2(final long kernelAddress) {
        this.slowCopyOut(kernelAddress, this.readValue, 2);
        return this.readValue.read2();
    }
    
    public int read4(final long kernelAddress) {
        this.slowCopyOut(kernelAddress, this.readValue, 4);
        return this.readValue.read4();
    }
    
    public long read8(final long kernelAddress) {
        this.slowCopyOut(kernelAddress, this.readValue, 8);
        return this.readValue.read8();
    }
    
    public void write1(final long kernelAddress, final byte value) {
        this.writeValue.write1(value);
        this.slowCopyIn(this.writeValue, kernelAddress, 1);
    }
    
    public void write2(final long kernelAddress, final short value) {
        this.writeValue.write2(value);
        this.slowCopyIn(this.writeValue, kernelAddress, 2);
    }
    
    public void write4(final long kernelAddress, final int value) {
        this.writeValue.write4(value);
        this.slowCopyIn(this.writeValue, kernelAddress, 4);
    }
    
    public void write8(final long kernelAddress, final long value) {
        this.writeValue.write8(value);
        this.slowCopyIn(this.writeValue, kernelAddress, 8);
    }
    
    public long getKernelBase() {
        return this.kernelBase;
    }
    
    public void setKernelBase(final long kernelBase) {
        this.kernelBase = kernelBase;
    }
    
    public Pointer getKstack() {
        return this.kstack;
    }
    
    private void readObject(final ObjectInputStream ois) throws ClassNotFoundException, IOException {
        throw new NotActiveException("Slow kernel accessor cannot be restored");
    }
    
    private void writeObject(final ObjectOutputStream oos) throws IOException {
        throw new NotActiveException("Slow kernel accessor cannot be saved");
    }
}
