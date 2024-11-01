package org.ps5jb.sdk.include.inet.in;

import org.ps5jb.sdk.res.ErrorMessages;

public final class ProtocolType implements Comparable
{
    public static final ProtocolType IPPROTO_IP;
    public static final ProtocolType IPPROTO_ICMP;
    public static final ProtocolType IPPROTO_TCP;
    public static final ProtocolType IPPROTO_UDP;
    public static final ProtocolType IPPROTO_IPV6;
    public static final ProtocolType IPPROTO_RAW;
    private static final ProtocolType[] values;
    private int value;
    private String name;
    
    private ProtocolType(final int value, final String name) {
        this.value = value;
        this.name = name;
    }
    
    public static ProtocolType[] values() {
        return ProtocolType.values;
    }
    
    public static ProtocolType valueOf(final int value) {
        for (final ProtocolType protocolType : ProtocolType.values) {
            if (value == protocolType.value()) {
                return protocolType;
            }
        }
        throw new IllegalArgumentException(ErrorMessages.getClassErrorMessage(ProtocolType.class, "invalidValue", Integer.toString(value)));
    }
    
    public int value() {
        return this.value;
    }
    
    public int compareTo(final Object o) {
        return this.value - ((ProtocolType)o).value;
    }
    
    @Override
    public boolean equals(final Object o) {
        final boolean result = o instanceof ProtocolType && this.value == ((ProtocolType)o).value;
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
        IPPROTO_IP = new ProtocolType(0, "IPPROTO_IP");
        IPPROTO_ICMP = new ProtocolType(1, "IPPROTO_ICMP");
        IPPROTO_TCP = new ProtocolType(6, "IPPROTO_TCP");
        IPPROTO_UDP = new ProtocolType(17, "IPPROTO_UDP");
        IPPROTO_IPV6 = new ProtocolType(41, "IPPROTO_IPV6");
        IPPROTO_RAW = new ProtocolType(255, "IPPROTO_RAW");
        values = new ProtocolType[] { ProtocolType.IPPROTO_IP, ProtocolType.IPPROTO_ICMP, ProtocolType.IPPROTO_TCP, ProtocolType.IPPROTO_UDP, ProtocolType.IPPROTO_IPV6, ProtocolType.IPPROTO_RAW };
    }
}
