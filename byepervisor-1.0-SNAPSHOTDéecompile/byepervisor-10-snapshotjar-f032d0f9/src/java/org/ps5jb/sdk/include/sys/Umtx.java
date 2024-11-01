package org.ps5jb.sdk.include.sys;

import org.ps5jb.sdk.core.SdkException;
import org.ps5jb.sdk.include.sys.umtx.UmtxShmFlag;
import org.ps5jb.sdk.include.sys.umtx.UmtxOpcodeType;
import org.ps5jb.sdk.core.Pointer;
import org.ps5jb.sdk.lib.LibKernel;

public class Umtx
{
    private final LibKernel libKernel;
    private final ErrNo errNo;
    
    public Umtx(final LibKernel libKernel) {
        this.libKernel = libKernel;
        this.errNo = new ErrNo(this.libKernel);
    }
    
    public int userMutexOperation(final Pointer obj, final UmtxOpcodeType operation, final UmtxShmFlag flag, final Pointer uaddr, final Pointer uaddr2) throws SdkException {
        final int ret = this.libKernel._umtx_op(obj, operation.value(), flag.value(), uaddr, uaddr2);
        if (ret == -1) {
            throw this.errNo.getLastException(this.getClass(), "userMutexOperation", new Object[0]);
        }
        return ret;
    }
    
    public int userMutexCreate(final Pointer key) throws SdkException {
        return this.userMutexOperation(Pointer.NULL, UmtxOpcodeType.UMTX_OP_SHM, UmtxShmFlag.UMTX_SHM_CREAT, key, Pointer.NULL);
    }
    
    public int userMutexLookup(final Pointer key) throws SdkException {
        return this.userMutexOperation(Pointer.NULL, UmtxOpcodeType.UMTX_OP_SHM, UmtxShmFlag.UMTX_SHM_LOOKUP, key, Pointer.NULL);
    }
    
    public int userMutexDestroy(final Pointer key) throws SdkException {
        return this.userMutexOperation(Pointer.NULL, UmtxOpcodeType.UMTX_OP_SHM, UmtxShmFlag.UMTX_SHM_DESTROY, key, Pointer.NULL);
    }
}
