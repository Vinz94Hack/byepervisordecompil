package org.ps5jb.sdk.include.sys.iovec;

import org.ps5jb.sdk.core.Pointer;
import org.ps5jb.sdk.core.AbstractPointer;

public class IoVecType
{
    public static final long SIZE = 16L;
    public static final long OFFSET_BASE = 0L;
    public static final long OFFSET_LENGTH = 8L;
    private final AbstractPointer ptr;
    private final boolean ownPtr;
    
    public IoVecType() {
        this.ptr = Pointer.calloc(16L);
        this.ownPtr = true;
    }
    
    public IoVecType(final AbstractPointer ptr) {
        this.ptr = ptr;
        this.ownPtr = false;
    }
    
    public AbstractPointer getBase() {
        return Pointer.valueOf(this.ptr.read8(0L));
    }
    
    public void setBase(final AbstractPointer val) {
        this.ptr.write8(0L, val.addr());
    }
    
    public long getLength() {
        return this.ptr.read8(8L);
    }
    
    public void setLength(final long val) {
        this.ptr.write8(8L, val);
    }
    
    @Override
    protected void finalize() throws Throwable {
        try {
            this.free();
        }
        finally {
            super.finalize();
        }
    }
    
    public void free() {
        if (this.ownPtr && this.ptr instanceof Pointer && this.ptr.addr() != 0L) {
            ((Pointer)this.ptr).free();
        }
    }
    
    public AbstractPointer getPointer() {
        return this.ptr;
    }
}
