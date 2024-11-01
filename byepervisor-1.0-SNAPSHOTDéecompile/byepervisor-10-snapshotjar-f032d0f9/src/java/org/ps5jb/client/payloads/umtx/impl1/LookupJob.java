package org.ps5jb.client.payloads.umtx.impl1;

import org.ps5jb.sdk.include.sys.errno.NotFoundException;
import org.ps5jb.client.payloads.umtx.common.DebugStatus;
import org.ps5jb.sdk.include.sys.Umtx;
import org.ps5jb.sdk.core.SdkException;
import org.ps5jb.sdk.include.sys.CpuSet;

public class LookupJob extends CommonJob
{
    private final State state;
    
    public LookupJob(final State state) {
        this.jobName = "lookup";
        this.state = state;
    }
    
    @Override
    protected void prepare() throws SdkException {
        super.prepare();
        final CpuSet cpuSet = new CpuSet(this.libKernel);
        cpuSet.setCurrentThreadAffinity(this.state.LOOKUP_THREAD_CORES);
    }
    
    @Override
    protected void work() {
        final Umtx umtx = new Umtx(this.libKernel);
        while (!this.state.raceDoneFlag.get()) {
            DebugStatus.debug("Starting loop");
            DebugStatus.debug("Waiting for ready flag");
            while (!this.state.readyFlag.get()) {
                this.thread_yield();
            }
            this.state.numReadyThreads.incrementAndGet();
            DebugStatus.debug("Waiting for destroy flag");
            while (!this.state.destroyFlag.get()) {
                this.thread_yield();
            }
            try {
                this.state.lookupDescriptor = umtx.userMutexLookup(this.state.primarySharedMemoryKeyAddress);
                if (DebugStatus.isNoticeEnabled()) {
                    DebugStatus.notice("Lookup descriptor of primary shared memory object: " + this.state.lookupDescriptor);
                }
            }
            catch (final NotFoundException e) {
                this.state.lookupDescriptor = -1;
            }
            catch (final SdkException e2) {
                this.state.lookupDescriptor = -1;
                DebugStatus.error("Performing lookup operation failed", (Throwable)e2);
            }
            this.state.numCompletedThreads.incrementAndGet();
            DebugStatus.debug("Waiting for check done flag");
            while (!this.state.checkDoneFlag.get()) {
                this.thread_yield();
            }
            this.state.numReadyThreads.incrementAndGet();
            DebugStatus.debug("Waiting for done flag");
            while (!this.state.doneFlag.get()) {
                this.thread_yield();
            }
            this.state.numFinishedThreads.incrementAndGet();
        }
        DebugStatus.debug("Waiting for destroy flag");
        while (!this.state.destroyFlag.get()) {
            this.thread_yield();
        }
        DebugStatus.notice("Finishing loop");
    }
}
