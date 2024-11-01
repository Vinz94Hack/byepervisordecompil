package org.ps5jb.sdk.include.sys.proc;

import java.nio.charset.Charset;
import org.ps5jb.sdk.core.AbstractPointer;
import org.ps5jb.sdk.include.sys.mutex.MutexType;
import org.ps5jb.sdk.core.kernel.KernelPointer;

public class Process
{
    public static final long OFFSET_P_LIST_LE_NEXT = 0L;
    public static final long OFFSET_P_LIST_LE_PREV = 8L;
    public static final long OFFSET_P_THREADS_TQH_FIRST = 16L;
    public static final long OFFSET_P_THREADS_TQH_LAST = 24L;
    public static final long OFFSET_P_SLOCK = 32L;
    public static final long OFFSET_P_UCRED = 64L;
    public static final long OFFSET_P_FD = 72L;
    public static final long OFFSET_P_PID = 188L;
    public static final long OFFSET_P_VM_SPACE = 512L;
    public static final long OFFSET_P_COMM = 1080L;
    private final KernelPointer ptr;
    private MutexType slock;
    
    public Process(final KernelPointer ptr) {
        this.ptr = ptr;
    }
    
    public KernelPointer getPreviousProcessPointer() {
        return KernelPointer.valueOf(this.ptr.read8(8L));
    }
    
    public Process getNextProcess() {
        final KernelPointer next = KernelPointer.valueOf(this.ptr.read8(0L));
        if (KernelPointer.NULL.equals(next)) {
            return null;
        }
        return new Process(next);
    }
    
    public MutexType getSpinLock() {
        if (this.slock == null) {
            this.slock = new MutexType(new KernelPointer(this.ptr.read8(32L), new Long(32L)));
        }
        return this.slock;
    }
    
    public KernelPointer getUCred() {
        return KernelPointer.valueOf(this.ptr.read8(64L));
    }
    
    public KernelPointer getFd() {
        return KernelPointer.valueOf(this.ptr.read8(72L));
    }
    
    public int getPid() {
        return this.ptr.read4(188L);
    }
    
    public KernelPointer getVmSpace() {
        return KernelPointer.valueOf(this.ptr.read8(512L));
    }
    
    public String getName() {
        return this.ptr.readString(1080L, new Integer(19), Charset.defaultCharset().name());
    }
    
    public KernelPointer getPointer() {
        return this.ptr;
    }
}
