package org.ps5jb.client.payloads.umtx.impl1;

import org.ps5jb.sdk.core.kernel.KernelPointer;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.List;
import org.ps5jb.sdk.include.sys.timeval.TimevalType;
import org.ps5jb.sdk.core.Pointer;
import org.ps5jb.sdk.include.sys.cpuset.CpuSetType;

public class State
{
    public CpuSetType MAIN_THREAD_CORES;
    public CpuSetType[] DESTROYER_THREAD_CORES;
    public CpuSetType LOOKUP_THREAD_CORES;
    public CpuSetType initialMainThreadAffinity;
    public Pointer scratchBufferAddress;
    public Pointer ioVecAddress;
    public Pointer uioAddress;
    public Pointer primarySharedMemoryKeyAddress;
    public Pointer secondarySharedMemoryKeyAddress;
    public Pointer extraSharedMemoryKeyAddress;
    public Pointer statAddress;
    public TimevalType timeoutAddress;
    public Pointer markerPatternAddress;
    public Pointer threadNameAddress;
    public Pointer reclaimJobStatesAddress;
    public List destroyerThreads;
    public Thread lookupThread;
    public List reclaimJobs;
    public List reclaimThreads;
    public ReclaimJob targetReclaimJob;
    public Thread targetReclaimThread;
    public AtomicBoolean raceDoneFlag;
    public AtomicBoolean readyFlag;
    public AtomicBoolean destroyFlag;
    public AtomicBoolean sprayFlag;
    public AtomicBoolean checkDoneFlag;
    public AtomicBoolean doneFlag;
    public AtomicInteger numReadyThreads;
    public AtomicInteger numCompletedThreads;
    public AtomicInteger numFinishedThreads;
    public AtomicInteger numDestructions;
    public AtomicInteger numSprays;
    public int initialOriginalDescriptor;
    public int originalDescriptor;
    public int lookupDescriptor;
    public int winnerDescriptor;
    public int[] reclaimDescriptors;
    public int destroyerThreadIndex;
    public int[] extraDescriptors;
    public Set usedDescriptors;
    public Set mappedKernelStackAddresses;
    public Pointer mappedReclaimKernelStackAddress;
    public MemoryBuffer stackDataBuffer;
    public boolean exploited;
    public KernelPointer threadAddress;
    public KernelPointer processAddress;
    public KernelPointer ofilesAddress;
    public KernelPointer kbaseAddress;
    
    public State() {
        this.scratchBufferAddress = Pointer.NULL;
        this.ioVecAddress = Pointer.NULL;
        this.uioAddress = Pointer.NULL;
        this.primarySharedMemoryKeyAddress = Pointer.NULL;
        this.secondarySharedMemoryKeyAddress = Pointer.NULL;
        this.extraSharedMemoryKeyAddress = Pointer.NULL;
        this.statAddress = Pointer.NULL;
        this.markerPatternAddress = Pointer.NULL;
        this.threadNameAddress = Pointer.NULL;
        this.reclaimJobStatesAddress = Pointer.NULL;
        this.mappedReclaimKernelStackAddress = Pointer.NULL;
        this.threadAddress = KernelPointer.NULL;
        this.processAddress = KernelPointer.NULL;
        this.ofilesAddress = KernelPointer.NULL;
        this.kbaseAddress = KernelPointer.NULL;
        (this.MAIN_THREAD_CORES = new CpuSetType()).set(0);
        this.DESTROYER_THREAD_CORES = new CpuSetType[] { new CpuSetType(), new CpuSetType() };
        this.DESTROYER_THREAD_CORES[0].set(1);
        this.DESTROYER_THREAD_CORES[1].set(2);
        (this.LOOKUP_THREAD_CORES = new CpuSetType()).set(3);
    }
    
    public void free() {
        this.MAIN_THREAD_CORES.free();
        for (final CpuSetType c : this.DESTROYER_THREAD_CORES) {
            c.free();
        }
        this.LOOKUP_THREAD_CORES.free();
        if (this.scratchBufferAddress != null && !this.scratchBufferAddress.equals(Pointer.NULL)) {
            this.scratchBufferAddress.free();
            this.scratchBufferAddress = null;
        }
        if (this.initialMainThreadAffinity != null) {
            this.initialMainThreadAffinity.free();
            this.initialMainThreadAffinity = null;
        }
    }
}
