package org.ps5jb.sdk.include.machine;

public class VmParam
{
    public static final long VM_MIN_KERNEL_ADDRESS;
    public static long DMAP_MIN_ADDRESS;
    public static long DMAP_MAX_ADDRESS;
    public static final long KERN_BASE;
    
    public static final long PHYS_TO_DMAP(final long x) {
        return x | VmParam.DMAP_MIN_ADDRESS;
    }
    
    public static final long DMAP_TO_PHYS(final long x) {
        return x & ~VmParam.DMAP_MIN_ADDRESS;
    }
    
    static {
        VM_MIN_KERNEL_ADDRESS = PMap.KVADDR(511L, 0L, 0L, 0L);
        VmParam.DMAP_MIN_ADDRESS = PMap.KVADDR(PMap.DMPML4I, PMap.DMPDPI, 0L, 0L);
        VmParam.DMAP_MAX_ADDRESS = PMap.KVADDR(PMap.DMPML4I + 1L, 0L, 0L, 0L);
        KERN_BASE = PMap.KVADDR(511L, 510L, 0L, 0L);
    }
}
