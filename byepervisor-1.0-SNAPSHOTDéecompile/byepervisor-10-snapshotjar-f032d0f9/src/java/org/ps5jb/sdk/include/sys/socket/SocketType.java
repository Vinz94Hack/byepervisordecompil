package org.ps5jb.sdk.include.sys.socket;

import org.ps5jb.sdk.res.ErrorMessages;

public final class SocketType implements Comparable
{
    public static final SocketType SOCK_STREAM;
    public static final SocketType SOCK_DGRAM;
    public static final SocketType SOCK_RAW;
    public static final SocketType SOCK_RDM;
    public static final SocketType SOCK_SEQPACKET;
    private static final SocketType[] values;
    private final int value;
    private final String name;
    
    private SocketType(final int value, final String name) {
        this.value = value;
        this.name = name;
    }
    
    public static SocketType[] values() {
        return SocketType.values;
    }
    
    public static SocketType valueOf(final int value) {
        for (final SocketType socketType : SocketType.values) {
            if (value == socketType.value()) {
                return socketType;
            }
        }
        throw new IllegalArgumentException(ErrorMessages.getClassErrorMessage(SocketType.class, "invalidValue", Integer.toString(value)));
    }
    
    public int value() {
        return this.value;
    }
    
    public int compareTo(final Object o) {
        return this.value - ((SocketType)o).value;
    }
    
    @Override
    public boolean equals(final Object o) {
        final boolean result = o instanceof SocketType && this.value == ((SocketType)o).value;
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
        SOCK_STREAM = new SocketType(1, "SOCK_STREAM");
        SOCK_DGRAM = new SocketType(2, "SOCK_DGRAM");
        SOCK_RAW = new SocketType(3, "SOCK_RAW");
        SOCK_RDM = new SocketType(4, "SOCK_RDM");
        SOCK_SEQPACKET = new SocketType(5, "SOCK_SEQPACKET");
        values = new SocketType[] { SocketType.SOCK_STREAM, SocketType.SOCK_DGRAM, SocketType.SOCK_RAW, SocketType.SOCK_RDM, SocketType.SOCK_SEQPACKET };
    }
}
