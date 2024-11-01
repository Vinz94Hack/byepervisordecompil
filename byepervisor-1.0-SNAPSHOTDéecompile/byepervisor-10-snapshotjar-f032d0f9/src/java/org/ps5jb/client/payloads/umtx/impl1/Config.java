package org.ps5jb.client.payloads.umtx.impl1;

import org.ps5jb.sdk.include.sys.rtprio.SchedulingClass;
import org.ps5jb.sdk.include.sys.rtprio.RtPrioType;

public class Config
{
    public static final boolean dumpKernelStackPartially = true;
    public static final boolean dumpKernelStackOfReclaimThread = false;
    public static final boolean toggleSetThreadPriorities = false;
    public static final boolean toggleEnableThreadPriorityForReclaimThreads = false;
    public static final boolean toggleStoppingWorkingThreadsBeforeRemap = true;
    public static final boolean toggleReclaimCpuAffinityMask = false;
    public static final boolean toggleDestroyerAffinityOnReclaimThread = false;
    public static final boolean toggleUnmappingOnFailure = true;
    public static final boolean toggleSprayOnDestroyThread = true;
    public static final boolean toggleMainThreadWait = false;
    public static final int MAX_EXPLOITATION_ATTEMPTS = 100000;
    public static final int MAX_RACING_ITERATIONS = 50000;
    public static int MAX_DUMMY_SHARED_MEMORY_OBJECTS;
    public static final int MAX_DESTROYER_THREADS = 2;
    public static int MAX_SPRAY_MUTEXES_PER_THREAD;
    public static int MAX_RECLAIM_THREADS;
    public static final int MAX_SEARCH_LOOP_INVOCATIONS = 2;
    public static final int MAX_EXTRA_USER_MUTEXES = 0;
    public static final int MAX_DESCRIPTORS = 1023;
    public static final long INITIAL_WAIT_PERIOD = 50L;
    public static final long KERNEL_STACK_WAIT_PERIOD = 100L;
    public static final long TINY_WAIT_PERIOD = 50L;
    public static final int RECLAIM_THREAD_MARKER_BASE = 4919;
    public static final long MAX_PIPE_BUFFER_SIZE = 4096L;
    public static final long MARKER_SIZE = 8L;
    public static final long STATE_SIZE = 16L;
    public static RtPrioType MAIN_THREAD_PRIORITY;
    public static RtPrioType DESTROYER_THREAD_PRIORITY;
    public static RtPrioType LOOKUP_THREAD_PRIORITY;
    public static RtPrioType RECLAIM_THREAD_PRIORITY;
    public static int MAX_RECLAIM_THREAD_NAME_SIZE;
    
    static {
        Config.MAX_DUMMY_SHARED_MEMORY_OBJECTS = 0;
        Config.MAX_SPRAY_MUTEXES_PER_THREAD = 35;
        Config.MAX_RECLAIM_THREADS = 250;
        Config.MAIN_THREAD_PRIORITY = new RtPrioType(SchedulingClass.RTP_PRIO_REALTIME, (short)256);
        Config.DESTROYER_THREAD_PRIORITY = new RtPrioType(SchedulingClass.RTP_PRIO_REALTIME, (short)256);
        Config.LOOKUP_THREAD_PRIORITY = new RtPrioType(SchedulingClass.RTP_PRIO_REALTIME, (short)767);
        Config.RECLAIM_THREAD_PRIORITY = new RtPrioType(SchedulingClass.RTP_PRIO_REALTIME, (short)450);
        Config.MAX_RECLAIM_THREAD_NAME_SIZE = 16;
    }
}
