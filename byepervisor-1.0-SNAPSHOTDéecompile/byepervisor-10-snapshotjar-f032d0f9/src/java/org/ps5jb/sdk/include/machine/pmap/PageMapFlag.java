package org.ps5jb.sdk.include.machine.pmap;

import java.util.List;
import java.util.ArrayList;

public final class PageMapFlag implements Comparable
{
    public static final PageMapFlag PMAP_NESTED_IPIMASK;
    public static final PageMapFlag PMAP_PDE_SUPERPAGE;
    public static final PageMapFlag PMAP_EMULATE_AD_BITS;
    public static final PageMapFlag PMAP_SUPPORTS_EXEC_ONLY;
    private static final PageMapFlag[] values;
    private int value;
    private String name;
    
    private PageMapFlag(final int value, final String name) {
        this.value = value;
        this.name = name;
    }
    
    public static PageMapFlag[] values() {
        return PageMapFlag.values;
    }
    
    public static PageMapFlag[] valueOf(final int value) {
        final List result = (List)new ArrayList();
        for (final PageMapFlag flag : PageMapFlag.values) {
            if ((value & flag.value) == flag.value) {
                result.add((Object)flag);
            }
        }
        return (PageMapFlag[])result.toArray((Object[])new PageMapFlag[result.size()]);
    }
    
    public int value() {
        return this.value;
    }
    
    public static short or(final PageMapFlag... flags) {
        short result = 0;
        for (final PageMapFlag flag : flags) {
            result |= (short)flag.value;
        }
        return result;
    }
    
    public int compareTo(final Object o) {
        return this.value - ((PageMapFlag)o).value;
    }
    
    @Override
    public boolean equals(final Object o) {
        final boolean result = o instanceof PageMapFlag && this.value == ((PageMapFlag)o).value;
        return result;
    }
    
    @Override
    public int hashCode() {
        return this.value;
    }
    
    @Override
    public String toString() {
        return this.name;
    }
    
    static {
        PMAP_NESTED_IPIMASK = new PageMapFlag(255, "PMAP_NESTED_IPIMASK");
        PMAP_PDE_SUPERPAGE = new PageMapFlag(256, "PMAP_PDE_SUPERPAGE");
        PMAP_EMULATE_AD_BITS = new PageMapFlag(512, "PMAP_EMULATE_AD_BITS");
        PMAP_SUPPORTS_EXEC_ONLY = new PageMapFlag(1024, "PMAP_SUPPORTS_EXEC_ONLY");
        values = new PageMapFlag[] { PageMapFlag.PMAP_NESTED_IPIMASK, PageMapFlag.PMAP_PDE_SUPERPAGE, PageMapFlag.PMAP_EMULATE_AD_BITS, PageMapFlag.PMAP_SUPPORTS_EXEC_ONLY };
    }
}
