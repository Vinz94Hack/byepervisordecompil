package org.ps5jb.sdk.include.machine;

public class Param
{
    public static final int MAX_CPU = 64;
    public static final long NPTEPGSHIFT = 9L;
    public static final long PHYS_PAGE_SHIFT = 12L;
    public static final long PHYS_PAGE_SIZE = 4096L;
    public static final long PHYS_PAGE_MASK = 4095L;
    public static final long PAGE_SHIFT = 14L;
    public static final long PAGE_SIZE = 16384L;
    public static final long PAGE_MASK = 16383L;
    public static final long NPDPEPG = 512L;
    public static final long NPDEPGSHIFT = 9L;
    public static final long PDRSHIFT = 21L;
    public static final long NBPDR = 2097152L;
    public static final long PDRMASK = 2097151L;
    public static final long NPDPEPGSHIFT = 9L;
    public static final long PDPSHIFT = 30L;
    public static final long NPML4EPG = 512L;
    public static final long NPML4EPGSHIFT = 9L;
    public static final long PML4SHIFT = 39L;
    public static final long KSTACK_PAGES = 1L;
    
    public static long atop(final long x) {
        return x >> 14;
    }
    
    public static long ptoa(final long x) {
        return x << 14;
    }
}
