package org.ps5jb.client.payloads.umtx.impl1;

import org.ps5jb.sdk.include.sys.pthreadtypes.PThreadType;
import org.ps5jb.sdk.core.SdkException;
import org.ps5jb.sdk.core.SdkRuntimeException;
import org.ps5jb.sdk.include.PThreadNp;
import org.ps5jb.sdk.include.PThread;
import org.ps5jb.sdk.lib.LibKernel;

public class CommonJob implements Runnable
{
    LibKernel libKernel;
    PThread pthread;
    PThreadNp pthreadNp;
    String jobName;
    
    protected CommonJob() {
        this.libKernel = new LibKernel();
        this.pthread = new PThread(this.libKernel);
        this.pthreadNp = new PThreadNp(this.libKernel);
    }
    
    public void run() {
        try {
            this.prepare();
            this.work();
            this.postprocess();
        }
        catch (final SdkException e) {
            throw new SdkRuntimeException((Throwable)e);
        }
    }
    
    protected void prepare() throws SdkException {
        final PThreadType pthread = this.pthread.self();
        this.pthreadNp.rename(pthread, this.jobName);
    }
    
    protected void work() throws SdkException {
        this.thread_yield();
    }
    
    protected void sleep(final long millis) {
        try {
            Thread.sleep(millis);
        }
        catch (final InterruptedException ex) {}
    }
    
    protected void thread_yield() {
        Thread.yield();
    }
    
    protected void postprocess() {
        this.libKernel.closeLibrary();
    }
    
    public String getJobName() {
        return this.jobName;
    }
}
