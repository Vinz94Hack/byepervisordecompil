package org.ps5jb.sdk.include.sys.uio;

import org.ps5jb.sdk.res.ErrorMessages;

public final class UioSegmentFlag implements Comparable
{
    public static final UioSegmentFlag UIO_USERSPACE;
    public static final UioSegmentFlag UIO_SYSSPACE;
    public static final UioSegmentFlag UIO_NOCOPY;
    private static final UioSegmentFlag[] values;
    private int value;
    private String name;
    
    private UioSegmentFlag(final int value, final String name) {
        this.value = value;
        this.name = name;
    }
    
    public static UioSegmentFlag[] values() {
        return UioSegmentFlag.values;
    }
    
    public static UioSegmentFlag valueOf(final int value) {
        for (final UioSegmentFlag segFlag : UioSegmentFlag.values) {
            if (value == segFlag.value()) {
                return segFlag;
            }
        }
        throw new IllegalArgumentException(ErrorMessages.getClassErrorMessage(UioSegmentFlag.class, "invalidValue", Integer.toString(value)));
    }
    
    public int value() {
        return this.value;
    }
    
    public int compareTo(final Object o) {
        return this.value - ((UioSegmentFlag)o).value;
    }
    
    @Override
    public boolean equals(final Object o) {
        final boolean result = o instanceof UioSegmentFlag && this.value == ((UioSegmentFlag)o).value;
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
        UIO_USERSPACE = new UioSegmentFlag(0, "UIO_USERSPACE");
        UIO_SYSSPACE = new UioSegmentFlag(1, "UIO_SYSSPACE");
        UIO_NOCOPY = new UioSegmentFlag(2, "UIO_NOCOPY");
        values = new UioSegmentFlag[] { UioSegmentFlag.UIO_USERSPACE, UioSegmentFlag.UIO_SYSSPACE, UioSegmentFlag.UIO_NOCOPY };
    }
}
