package org.ps5jb.client.payloads.umtx.common;

import org.ps5jb.sdk.core.SdkException;
import org.ps5jb.sdk.include.sys.cpuset.CpuSetType;
import org.ps5jb.sdk.include.sys.rtprio.RtPrioType;
import org.ps5jb.sdk.include.sys.rtprio.SchedulingClass;
import org.ps5jb.sdk.include.sys.RtPrio;
import org.ps5jb.sdk.include.sys.CpuSet;
import org.ps5jb.sdk.lib.LibKernel;

public class Executor
{
    private static void sleep(final long millis) {
        try {
            Thread.sleep(millis);
        }
        catch (final InterruptedException ex) {}
    }
    
    public static void runInNewThread(final String threadName, final Runnable job, final FinishEvaluator finishEvaluator, final int parentThreadCore, final short parentThreadPriority) {
        final LibKernel libKernel = new LibKernel();
        final CpuSet cpuSet = new CpuSet(libKernel);
        final RtPrio rtPrio = new RtPrio(libKernel);
        CpuSetType initialRootAffinity = null;
        RtPrioType initialRootPriority = null;
        final RtPrioType newParentPriority = new RtPrioType(SchedulingClass.RTP_PRIO_REALTIME, parentThreadPriority);
        final CpuSetType newParentAffinity = new CpuSetType();
        try {
            initialRootAffinity = cpuSet.getCurrentThreadAffinity();
            initialRootPriority = rtPrio.lookupRtPrio(0);
            newParentAffinity.set(parentThreadCore);
            cpuSet.setCurrentThreadAffinity(newParentAffinity);
            rtPrio.setRtPrio(0, newParentPriority);
        }
        catch (final SdkException | RuntimeException | Error e) {
            DebugStatus.error("Unable to set parent thread core or priority", e);
        }
        finally {
            newParentAffinity.free();
        }
        final Thread mainThread = new Thread(job, threadName);
        mainThread.start();
        sleep(1000L);
        while (!finishEvaluator.isFinished(job)) {
            sleep(2000L);
        }
        try {
            if (initialRootAffinity != null) {
                cpuSet.setCurrentThreadAffinity(initialRootAffinity);
            }
            if (initialRootPriority != null) {
                rtPrio.setRtPrio(0, initialRootPriority);
            }
        }
        catch (final SdkException | RuntimeException | Error e2) {
            DebugStatus.error("Unable to recover parent thread core or priority", e2);
        }
    }
    
    public interface FinishEvaluator
    {
        boolean isFinished(final Runnable p0);
    }
}
