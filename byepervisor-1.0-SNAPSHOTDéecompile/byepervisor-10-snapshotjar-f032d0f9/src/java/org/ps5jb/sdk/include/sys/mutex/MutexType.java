package org.ps5jb.sdk.include.sys.mutex;

import org.ps5jb.sdk.core.Pointer;
import org.ps5jb.sdk.core.kernel.KernelPointer;
import org.ps5jb.sdk.include.sys.lock.LockObjectType;
import org.ps5jb.sdk.core.AbstractPointer;

public class MutexType
{
    public static final long OFFSET_MTX_LOCK_OBJECT = 0L;
    public static final long OFFSET_MTX_LOCK = 24L;
    public static final long SIZE = 32L;
    private final AbstractPointer ptr;
    private LockObjectType lockObjectType;
    
    public MutexType(final AbstractPointer ptr) {
        this.ptr = ptr;
    }
    
    public LockObjectType getLockObject() {
        if (this.lockObjectType == null) {
            final Long lockPointerSize = new Long(24L);
            AbstractPointer lockPointer;
            if (this.ptr instanceof KernelPointer) {
                lockPointer = new KernelPointer(this.ptr.read8(0L), lockPointerSize);
            }
            else {
                lockPointer = new Pointer(this.ptr.read8(0L), lockPointerSize);
            }
            this.lockObjectType = new LockObjectType(lockPointer);
        }
        return this.lockObjectType;
    }
    
    public long getLock() {
        return this.ptr.read8(24L);
    }
    
    public AbstractPointer getPointer() {
        return this.ptr;
    }
}
