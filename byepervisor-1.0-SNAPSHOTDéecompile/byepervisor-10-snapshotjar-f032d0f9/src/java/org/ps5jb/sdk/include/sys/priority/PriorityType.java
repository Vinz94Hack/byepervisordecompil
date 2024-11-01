package org.ps5jb.sdk.include.sys.priority;

import org.ps5jb.sdk.res.ErrorMessages;

public final class PriorityType implements Comparable
{
    public static final PriorityType PRI_ITHD;
    public static final PriorityType PRI_REALTIME;
    public static final PriorityType PRI_TIMESHARE;
    public static final PriorityType PRI_IDLE;
    public static final PriorityType PRI_FIFO_BIT;
    public static final PriorityType PRI_FIFO;
    private static final PriorityType[] values;
    private int value;
    private String name;
    
    private PriorityType(final int value, final String name) {
        this.value = value;
        this.name = name;
    }
    
    public static PriorityType[] values() {
        return PriorityType.values;
    }
    
    public static PriorityType valueOf(final int value) {
        for (final PriorityType priorityType : PriorityType.values) {
            if (value == priorityType.value()) {
                return priorityType;
            }
        }
        throw new IllegalArgumentException(ErrorMessages.getClassErrorMessage(PriorityType.class, "invalidValue", Integer.toString(value)));
    }
    
    public int value() {
        return this.value;
    }
    
    public int compareTo(final Object o) {
        return this.value - ((PriorityType)o).value;
    }
    
    @Override
    public boolean equals(final Object o) {
        final boolean result = o instanceof PriorityType && this.value == ((PriorityType)o).value;
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
        PRI_ITHD = new PriorityType(1, "PRI_ITHD");
        PRI_REALTIME = new PriorityType(2, "PRI_REALTIME");
        PRI_TIMESHARE = new PriorityType(3, "PRI_TIMESHARE");
        PRI_IDLE = new PriorityType(4, "PRI_IDLE");
        PRI_FIFO_BIT = new PriorityType(8, "PRI_FIFO_BIT");
        PRI_FIFO = new PriorityType(PriorityType.PRI_FIFO_BIT.value() | PriorityType.PRI_REALTIME.value(), "PRI_FIFO");
        values = new PriorityType[] { PriorityType.PRI_ITHD, PriorityType.PRI_REALTIME, PriorityType.PRI_TIMESHARE, PriorityType.PRI_IDLE, PriorityType.PRI_FIFO };
    }
}
