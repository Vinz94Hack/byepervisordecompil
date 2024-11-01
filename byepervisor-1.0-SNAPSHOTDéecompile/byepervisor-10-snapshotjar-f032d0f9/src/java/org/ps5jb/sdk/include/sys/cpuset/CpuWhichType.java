package org.ps5jb.sdk.include.sys.cpuset;

import org.ps5jb.sdk.res.ErrorMessages;

public final class CpuWhichType implements Comparable
{
    public static final CpuWhichType CPU_WHICH_TID;
    public static final CpuWhichType CPU_WHICH_PID;
    public static final CpuWhichType CPU_WHICH_CPUSET;
    public static final CpuWhichType CPU_WHICH_IRQ;
    public static final CpuWhichType CPU_WHICH_JAIL;
    public static final CpuWhichType CPU_WHICH_DOMAIN;
    private static final CpuWhichType[] values;
    private int value;
    private String name;
    
    private CpuWhichType(final int value, final String name) {
        this.value = value;
        this.name = name;
    }
    
    public static CpuWhichType[] values() {
        return CpuWhichType.values;
    }
    
    public static CpuWhichType valueOf(final int value) {
        for (final CpuWhichType cpuWhich : CpuWhichType.values) {
            if (value == cpuWhich.value()) {
                return cpuWhich;
            }
        }
        throw new IllegalArgumentException(ErrorMessages.getClassErrorMessage(CpuWhichType.class, "invalidValue", Integer.toString(value)));
    }
    
    public int value() {
        return this.value;
    }
    
    public int compareTo(final Object o) {
        return this.value - ((CpuWhichType)o).value;
    }
    
    @Override
    public boolean equals(final Object o) {
        final boolean result = o instanceof CpuWhichType && this.value == ((CpuWhichType)o).value;
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
        CPU_WHICH_TID = new CpuWhichType(1, "CPU_WHICH_TID");
        CPU_WHICH_PID = new CpuWhichType(2, "CPU_WHICH_PID");
        CPU_WHICH_CPUSET = new CpuWhichType(3, "CPU_WHICH_CPUSET");
        CPU_WHICH_IRQ = new CpuWhichType(4, "CPU_WHICH_IRQ");
        CPU_WHICH_JAIL = new CpuWhichType(5, "CPU_WHICH_JAIL");
        CPU_WHICH_DOMAIN = new CpuWhichType(6, "CPU_WHICH_DOMAIN");
        values = new CpuWhichType[] { CpuWhichType.CPU_WHICH_TID, CpuWhichType.CPU_WHICH_PID, CpuWhichType.CPU_WHICH_CPUSET, CpuWhichType.CPU_WHICH_IRQ, CpuWhichType.CPU_WHICH_JAIL, CpuWhichType.CPU_WHICH_DOMAIN };
    }
}
