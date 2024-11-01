package org.ps5jb.sdk.include.machine.pmap;

import org.ps5jb.sdk.core.AbstractPointer;
import org.ps5jb.sdk.include.sys.mutex.MutexType;
import org.ps5jb.sdk.core.kernel.KernelPointer;

public class PageMap
{
    public static final long OFFSET_PM_MTX = 0L;
    public static final long OFFSET_PM_PML4 = 32L;
    public static final long OFFSET_PM_TYPE = 72L;
    public static final long OFFSET_PM_FLAGS = 120L;
    private final KernelPointer ptr;
    private MutexType mutex;
    
    public PageMap(final KernelPointer ptr) {
        this.ptr = ptr;
    }
    
    public MutexType getMutex() {
        if (this.mutex == null) {
            this.mutex = new MutexType(new KernelPointer(this.ptr.read8(0L), new Long(32L)));
        }
        return this.mutex;
    }
    
    public long getPml4() {
        return this.ptr.read8(32L);
    }
    
    public PageMapType getType() {
        return PageMapType.valueOf(this.ptr.read4(72L));
    }
    
    public PageMapFlag[] getFlags() {
        return PageMapFlag.valueOf(this.ptr.read4(120L));
    }
    
    public KernelPointer getPointer() {
        return this.ptr;
    }
}
