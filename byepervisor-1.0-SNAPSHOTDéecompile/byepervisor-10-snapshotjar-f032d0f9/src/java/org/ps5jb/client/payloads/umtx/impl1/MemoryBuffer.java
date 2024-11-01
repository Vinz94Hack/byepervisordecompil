package org.ps5jb.client.payloads.umtx.impl1;

import java.util.Arrays;
import org.ps5jb.client.payloads.umtx.common.MemoryDumper;
import org.ps5jb.sdk.core.kernel.KernelPointer;
import org.ps5jb.sdk.core.Pointer;
import org.ps5jb.sdk.core.AbstractPointer;

public class MemoryBuffer
{
    private final AbstractPointer ptr;
    private byte[] snapshot;
    
    public MemoryBuffer(final AbstractPointer ptr, final long size) {
        if (ptr.size() == null || ptr.size() != size) {
            if (ptr instanceof Pointer) {
                this.ptr = new Pointer(ptr.addr(), new Long(size));
            }
            else {
                this.ptr = new KernelPointer(ptr.addr(), new Long(size));
            }
        }
        else {
            this.ptr = ptr;
        }
    }
    
    public long getAddr() {
        return this.ptr.addr();
    }
    
    public long getSize() {
        return this.ptr.size();
    }
    
    public byte read8(final long offset) {
        return this.ptr.read1(offset);
    }
    
    public short read16(final long offset) {
        return this.ptr.read2(offset);
    }
    
    public long read64(final long offset) {
        return this.ptr.read8(offset);
    }
    
    public void dump() {
        MemoryDumper.dump(this.ptr, this.getSize(), true);
    }
    
    public void snapshot() {
        final long size = this.getSize();
        if (this.snapshot == null) {
            this.snapshot = new byte[(int)size];
        }
        for (int i = 0; i < size; i += 8) {
            if (i + 8 <= size) {
                final long val = this.read64(i);
                for (int j = 0; j < 8; ++j) {
                    this.snapshot[i + j] = (byte)(val >> j * 8 & 0xFFL);
                }
            }
            else {
                for (int k = 0; i + k < size; ++k) {
                    final byte val2 = this.read8(i + k);
                    this.snapshot[i + k] = val2;
                }
            }
        }
    }
    
    public void clearSnapshot() {
        this.snapshot = null;
    }
    
    public long readSnapshot64(final long offset) {
        long result = 0L;
        if (this.snapshot != null) {
            for (long size = this.getSize(), i = 0L; i < 8L && offset + i < size; ++i) {
                result |= (long)(this.snapshot[(int)(offset + i)] & 0xFF) << (int)(i * 8L);
            }
        }
        return result;
    }
    
    public long find(final AbstractPointer pattern, final int size) {
        final byte[] val = pattern.read(size);
        final byte[] nextVal = new byte[size];
        for (long curOffset = 0L; curOffset + size <= this.getSize(); ++curOffset) {
            this.ptr.read(curOffset, nextVal, 0, size);
            if (Arrays.equals(val, nextVal)) {
                return curOffset;
            }
        }
        return -1L;
    }
}
