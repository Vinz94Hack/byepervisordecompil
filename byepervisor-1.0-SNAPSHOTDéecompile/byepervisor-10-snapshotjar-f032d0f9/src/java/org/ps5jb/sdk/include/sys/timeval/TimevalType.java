package org.ps5jb.sdk.include.sys.timeval;

import org.ps5jb.sdk.core.Pointer;

public class TimevalType
{
    public static final long SIZE = 16L;
    public static final long OFFSET_TV_SEC = 0L;
    public static final long OFFSET_TV_USEC = 8L;
    private final Pointer ptr;
    private final boolean ownPtr;
    
    public TimevalType() {
        this.ptr = Pointer.calloc(16L);
        this.ownPtr = true;
    }
    
    public TimevalType(final Pointer ptr) {
        this.ptr = ptr;
        this.ownPtr = false;
    }
    
    public long getSec() {
        return this.ptr.read8(0L);
    }
    
    public long getUsec() {
        return this.ptr.read8(8L);
    }
    
    public void setSec(final long val) {
        this.ptr.write8(0L, val);
    }
    
    public void setUsec(final long val) {
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
        if (this.ownPtr && this.ptr != null && this.ptr.addr() != 0L) {
            this.ptr.free();
        }
    }
    
    public Pointer getPointer() {
        return this.ptr;
    }
}
