package org.ps5jb.sdk.include.sys.lock;

import java.nio.charset.Charset;
import org.ps5jb.sdk.core.AbstractPointer;

public class LockObjectType
{
    public static final long OFFSET_LO_NAME = 0L;
    public static final long OFFSET_LO_FLAGS = 8L;
    public static final long OFFSET_LO_DATA = 12L;
    public static final long OFFSET_LO_WITNESS = 16L;
    public static final long SIZE = 24L;
    private final AbstractPointer ptr;
    
    public LockObjectType(final AbstractPointer ptr) {
        this.ptr = ptr;
    }
    
    public String getName() {
        return this.ptr.readString(0L, null, Charset.defaultCharset().name());
    }
    
    public int getFlags() {
        return this.ptr.read4(8L);
    }
    
    public int getData() {
        return this.ptr.read4(12L);
    }
    
    public long getWitness() {
        return this.ptr.read8(16L);
    }
    
    public AbstractPointer getPointer() {
        return this.ptr;
    }
}
