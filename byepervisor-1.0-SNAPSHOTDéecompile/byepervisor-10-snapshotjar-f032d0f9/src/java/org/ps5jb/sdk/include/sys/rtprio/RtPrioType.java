package org.ps5jb.sdk.include.sys.rtprio;

public class RtPrioType
{
    public static final short RTP_PRIO_MIN = 0;
    public static final short RTP_PRIO_MAX = 31;
    public static final int RTP_LOOKUP = 0;
    public static final int RTP_SET = 1;
    private SchedulingClass type;
    private short priority;
    
    public RtPrioType(final SchedulingClass type, final short priority) {
        this.type = type;
        this.priority = priority;
    }
    
    public SchedulingClass getType() {
        return this.type;
    }
    
    public short getPriority() {
        return this.priority;
    }
    
    @Override
    public String toString() {
        return this.getType().toString() + ": " + this.getPriority();
    }
}
