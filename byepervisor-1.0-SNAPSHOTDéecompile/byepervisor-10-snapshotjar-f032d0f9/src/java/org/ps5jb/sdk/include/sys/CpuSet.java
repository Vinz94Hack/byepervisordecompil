package org.ps5jb.sdk.include.sys;

import org.ps5jb.sdk.core.SdkRuntimeException;
import org.ps5jb.sdk.core.SdkException;
import org.ps5jb.sdk.include.sys.cpuset.CpuSetType;
import org.ps5jb.sdk.include.sys.cpuset.CpuWhichType;
import org.ps5jb.sdk.include.sys.cpuset.CpuLevelType;
import org.ps5jb.sdk.lib.LibKernel;

public class CpuSet
{
    private final LibKernel libKernel;
    private final ErrNo errNo;
    
    public CpuSet(final LibKernel libKernel) {
        this.libKernel = libKernel;
        this.errNo = new ErrNo(this.libKernel);
    }
    
    public CpuSetType getAffinity(final CpuLevelType cpuLevel, final CpuWhichType cpuWhich, final int id) throws SdkException {
        final CpuSetType result = new CpuSetType();
        try {
            final int ret = this.libKernel.cpuset_getaffinity(cpuLevel.value(), cpuWhich.value(), id, result.getSize(), result.getPointer());
            if (ret == -1) {
                throw this.errNo.getLastException(this.getClass(), "getAffinity", new Object[0]);
            }
            result.refresh();
            return result;
        }
        catch (final SdkException | SdkRuntimeException e) {
            result.free();
            throw e;
        }
    }
    
    public void setAffinity(final CpuLevelType cpuLevel, final CpuWhichType cpuWhich, final int id, final CpuSetType cpuSetType) throws SdkException {
        final int ret = this.libKernel.cpuset_setaffinity(cpuLevel.value(), cpuWhich.value(), id, cpuSetType.getSize(), cpuSetType.getPointer());
        if (ret == -1) {
            throw this.errNo.getLastException(this.getClass(), "setAffinity", new Object[0]);
        }
    }
    
    public CpuSetType getCurrentThreadAffinity() throws SdkException {
        return this.getAffinity(CpuLevelType.CPU_LEVEL_WHICH, CpuWhichType.CPU_WHICH_TID, -1);
    }
    
    public void setCurrentThreadAffinity(final CpuSetType affinity) throws SdkException {
        this.setAffinity(CpuLevelType.CPU_LEVEL_WHICH, CpuWhichType.CPU_WHICH_TID, -1, affinity);
    }
}
