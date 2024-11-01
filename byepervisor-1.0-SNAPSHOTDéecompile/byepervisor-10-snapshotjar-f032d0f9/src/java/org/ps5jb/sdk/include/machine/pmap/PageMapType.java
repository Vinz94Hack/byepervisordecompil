package org.ps5jb.sdk.include.machine.pmap;

import org.ps5jb.sdk.res.ErrorMessages;

public final class PageMapType implements Comparable
{
    public static final PageMapType PT_X86;
    public static final PageMapType PT_EPT;
    public static final PageMapType PT_RVI;
    private static final PageMapType[] values;
    private int value;
    private String name;
    
    private PageMapType(final int value, final String name) {
        this.value = value;
        this.name = name;
    }
    
    public static PageMapType[] values() {
        return PageMapType.values;
    }
    
    public static PageMapType valueOf(final int value) {
        for (final PageMapType pageMapType : PageMapType.values) {
            if (value == pageMapType.value()) {
                return pageMapType;
            }
        }
        throw new IllegalArgumentException(ErrorMessages.getClassErrorMessage(PageMapType.class, "invalidValue", Integer.toString(value)));
    }
    
    public int value() {
        return this.value;
    }
    
    public int compareTo(final Object o) {
        return this.value - ((PageMapType)o).value;
    }
    
    @Override
    public boolean equals(final Object o) {
        final boolean result = o instanceof PageMapType && this.value == ((PageMapType)o).value;
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
        PT_X86 = new PageMapType(0, "PT_X86");
        PT_EPT = new PageMapType(1, "PT_EPT");
        PT_RVI = new PageMapType(2, "PT_RVI");
        values = new PageMapType[] { PageMapType.PT_X86, PageMapType.PT_EPT, PageMapType.PT_RVI };
    }
}
