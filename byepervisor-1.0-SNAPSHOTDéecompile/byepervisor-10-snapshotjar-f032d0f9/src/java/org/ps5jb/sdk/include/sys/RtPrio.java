package org.ps5jb.sdk.include.sys;

import org.ps5jb.sdk.core.SdkException;
import org.ps5jb.sdk.include.sys.rtprio.SchedulingClass;
import org.ps5jb.sdk.core.Pointer;
import org.ps5jb.sdk.include.sys.rtprio.RtPrioType;
import org.ps5jb.sdk.lib.LibKernel;

public class RtPrio
{
    private final LibKernel libKernel;
    private final ErrNo errNo;
    
    public RtPrio(final LibKernel libKernel) {
        this.libKernel = libKernel;
        this.errNo = new ErrNo(this.libKernel);
    }
    
    public RtPrioType lookupRtPrio(final int lwpid) throws SdkException {
        final Pointer buf = Pointer.calloc(4L);
        try {
            final int ret = this.libKernel.rtprio_thread(0, lwpid, buf);
            if (ret == -1) {
                throw this.errNo.getLastException(this.getClass(), "lookupRtPrio", new Object[0]);
            }
            return new RtPrioType(SchedulingClass.valueOf(buf.read2()), buf.read2(2L));
        }
        finally {
            buf.free();
        }
    }
    
    public void setRtPrio(final int lwpid, final RtPrioType rtp) throws SdkException {
        final Pointer buf = Pointer.calloc(4L);
        try {
            buf.write2(rtp.getType().value());
            buf.write2(2L, rtp.getPriority());
            final int ret = this.libKernel.rtprio_thread(1, lwpid, buf);
            if (ret == -1) {
                throw this.errNo.getLastException(this.getClass(), "setRtPrio", new Object[0]);
            }
        }
        finally {
            buf.free();
        }
    }
}
