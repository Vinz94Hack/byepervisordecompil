package org.ps5jb.sdk.include.sys.cpuset;

import org.ps5jb.sdk.core.Pointer;
import org.ps5jb.sdk.include.sys.bitset.BitSetType;

public class CpuSetType extends BitSetType
{
    public static final int CPU_SETSIZE = 128;
    
    public CpuSetType() {
        super(Pointer.calloc(16L), 128);
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
        if (this.getPointer() != null && this.getPointer().addr() != 0L) {
            this.getPointer().free();
        }
    }
}
