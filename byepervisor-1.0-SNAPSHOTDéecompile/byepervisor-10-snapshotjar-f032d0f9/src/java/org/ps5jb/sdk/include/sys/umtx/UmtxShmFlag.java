package org.ps5jb.sdk.include.sys.umtx;

import org.ps5jb.sdk.res.ErrorMessages;

public final class UmtxShmFlag implements Comparable
{
    public static final UmtxShmFlag UMTX_SHM_CREAT;
    public static final UmtxShmFlag UMTX_SHM_LOOKUP;
    public static final UmtxShmFlag UMTX_SHM_DESTROY;
    public static final UmtxShmFlag UMTX_SHM_ALIVE;
    private static final UmtxShmFlag[] values;
    private long value;
    private String name;
    
    private UmtxShmFlag(final long value, final String name) {
        this.value = value;
        this.name = name;
    }
    
    public static UmtxShmFlag[] values() {
        return UmtxShmFlag.values;
    }
    
    public static UmtxShmFlag valueOf(final long value) {
        for (final UmtxShmFlag shmFlag : UmtxShmFlag.values) {
            if (value == shmFlag.value()) {
                return shmFlag;
            }
        }
        throw new IllegalArgumentException(ErrorMessages.getClassErrorMessage(UmtxShmFlag.class, "invalidValue", Long.toString(value)));
    }
    
    public long value() {
        return this.value;
    }
    
    public int compareTo(final Object o) {
        return (int)this.value - (int)((UmtxShmFlag)o).value;
    }
    
    @Override
    public boolean equals(final Object o) {
        final boolean result = o instanceof UmtxShmFlag && this.value == ((UmtxShmFlag)o).value;
        return result;
    }
    
    @Override
    public int hashCode() {
        return (int)this.value;
    }
    
    @Override
    public String toString() {
        return this.name;
    }
    
    static {
        UMTX_SHM_CREAT = new UmtxShmFlag(1L, "UMTX_SHM_CREAT");
        UMTX_SHM_LOOKUP = new UmtxShmFlag(2L, "UMTX_SHM_LOOKUP");
        UMTX_SHM_DESTROY = new UmtxShmFlag(4L, "UMTX_SHM_DESTROY");
        UMTX_SHM_ALIVE = new UmtxShmFlag(8L, "UMTX_SHM_ALIVE");
        values = new UmtxShmFlag[] { UmtxShmFlag.UMTX_SHM_CREAT, UmtxShmFlag.UMTX_SHM_LOOKUP, UmtxShmFlag.UMTX_SHM_DESTROY, UmtxShmFlag.UMTX_SHM_ALIVE };
    }
}
