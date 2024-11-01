package org.ps5jb.sdk.include.sys.rtprio;

import org.ps5jb.sdk.res.ErrorMessages;

public final class SchedulingClass implements Comparable
{
    public static final SchedulingClass RTP_PRIO_REALTIME;
    public static final SchedulingClass RTP_PRIO_NORMAL;
    public static final SchedulingClass RTP_PRIO_IDLE;
    public static final SchedulingClass RTP_PRIO_FIFO;
    private static final SchedulingClass[] values;
    private short value;
    private String name;
    
    private SchedulingClass(final short value, final String name) {
        this.value = value;
        this.name = name;
    }
    
    public static SchedulingClass[] values() {
        return SchedulingClass.values;
    }
    
    public static SchedulingClass valueOf(final short value) {
        for (final SchedulingClass rtPrioType : SchedulingClass.values) {
            if (value == rtPrioType.value()) {
                return rtPrioType;
            }
        }
        throw new IllegalArgumentException(ErrorMessages.getClassErrorMessage(SchedulingClass.class, "invalidValue", Integer.toString((int)value)));
    }
    
    public short value() {
        return this.value;
    }
    
    public int compareTo(final Object o) {
        return this.value - ((SchedulingClass)o).value;
    }
    
    @Override
    public boolean equals(final Object o) {
        final boolean result = o instanceof SchedulingClass && this.value == ((SchedulingClass)o).value;
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
        RTP_PRIO_REALTIME = new SchedulingClass((short)2, "RTP_PRIO_REALTIME");
        RTP_PRIO_NORMAL = new SchedulingClass((short)3, "RTP_PRIO_NORMAL");
        RTP_PRIO_IDLE = new SchedulingClass((short)4, "RTP_PRIO_IDLE");
        RTP_PRIO_FIFO = new SchedulingClass((short)(0x8 | SchedulingClass.RTP_PRIO_REALTIME.value), "RTP_PRIO_FIFO");
        values = new SchedulingClass[] { SchedulingClass.RTP_PRIO_REALTIME, SchedulingClass.RTP_PRIO_NORMAL, SchedulingClass.RTP_PRIO_IDLE, SchedulingClass.RTP_PRIO_FIFO };
    }
}
