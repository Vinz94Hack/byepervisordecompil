package org.ps5jb.sdk.include.sys.uio;

import org.ps5jb.sdk.core.kernel.KernelPointer;
import org.ps5jb.sdk.core.AbstractPointer;

public class UioType
{
    public static final long SIZE = 48L;
    public static final long OFFSET_IOV = 0L;
    public static final long OFFSET_IOV_COUNT = 8L;
    public static final long OFFSET_OFFSET = 16L;
    public static final long OFFSET_RESIDUAL_SIZE = 24L;
    public static final long OFFSET_SEGMENT_FLAG = 32L;
    public static final long OFFSET_READ_WRITE = 36L;
    public static final long OFFSET_OWNER = 40L;
    private final AbstractPointer ptr;
    
    public UioType(final AbstractPointer ptr) {
        this.ptr = ptr;
    }
    
    public KernelPointer getIov() {
        return KernelPointer.valueOf(this.ptr.read8(0L));
    }
    
    public int getIovCount() {
        return this.ptr.read4(8L);
    }
    
    public long getOffset() {
        return this.ptr.read8(16L);
    }
    
    public long getResidualSize() {
        return this.ptr.read8(24L);
    }
    
    public UioSegmentFlag getSegmentFlag() {
        return UioSegmentFlag.valueOf(this.ptr.read4(32L));
    }
    
    public void setSegmentFlag(final UioSegmentFlag val) {
        this.ptr.write4(32L, val.value());
    }
    
    public UioReadWrite getReadWrite() {
        return UioReadWrite.valueOf(this.ptr.read4(36L));
    }
    
    public KernelPointer getOwner() {
        return KernelPointer.valueOf(this.ptr.read8(40L));
    }
    
    public AbstractPointer getPointer() {
        return this.ptr;
    }
}
