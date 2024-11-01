package org.ps5jb.sdk.include.sys.cpuset;

import org.ps5jb.sdk.res.ErrorMessages;

public final class CpuLevelType implements Comparable
{
    public static final CpuLevelType CPU_LEVEL_ROOT;
    public static final CpuLevelType CPU_LEVEL_CPUSET;
    public static final CpuLevelType CPU_LEVEL_WHICH;
    private static final CpuLevelType[] values;
    private int value;
    private String name;
    
    private CpuLevelType(final int value, final String name) {
        this.value = value;
        this.name = name;
    }
    
    public static CpuLevelType[] values() {
        return CpuLevelType.values;
    }
    
    public static CpuLevelType valueOf(final int value) {
        for (final CpuLevelType cpuLevel : CpuLevelType.values) {
            if (value == cpuLevel.value()) {
                return cpuLevel;
            }
        }
        throw new IllegalArgumentException(ErrorMessages.getClassErrorMessage(CpuLevelType.class, "invalidValue", Integer.toString(value)));
    }
    
    public int value() {
        return this.value;
    }
    
    public int compareTo(final Object o) {
        return this.value - ((CpuLevelType)o).value;
    }
    
    @Override
    public boolean equals(final Object o) {
        final boolean result = o instanceof CpuLevelType && this.value == ((CpuLevelType)o).value;
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
        CPU_LEVEL_ROOT = new CpuLevelType(1, "CPU_LEVEL_ROOT");
        CPU_LEVEL_CPUSET = new CpuLevelType(2, "CPU_LEVEL_CPUSET");
        CPU_LEVEL_WHICH = new CpuLevelType(3, "CPU_LEVEL_WHICH");
        values = new CpuLevelType[] { CpuLevelType.CPU_LEVEL_ROOT, CpuLevelType.CPU_LEVEL_CPUSET, CpuLevelType.CPU_LEVEL_WHICH };
    }
}
