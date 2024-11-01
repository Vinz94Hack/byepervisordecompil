package org.ps5jb.sdk.include.netinet6.in6;

import org.ps5jb.sdk.res.ErrorMessages;

public final class OptionIPv6 implements Comparable
{
    public static final OptionIPv6 IPV6_OPTIONS;
    public static final OptionIPv6 IPV6_PKTINFO;
    private static final OptionIPv6[] values;
    private int value;
    private String name;
    
    private OptionIPv6(final int value, final String name) {
        this.value = value;
        this.name = name;
    }
    
    public static OptionIPv6[] values() {
        return OptionIPv6.values;
    }
    
    public static OptionIPv6 valueOf(final int value) {
        for (final OptionIPv6 opt : OptionIPv6.values) {
            if (value == opt.value()) {
                return opt;
            }
        }
        throw new IllegalArgumentException(ErrorMessages.getClassErrorMessage(OptionIPv6.class, "invalidValue", Integer.toString(value)));
    }
    
    public int value() {
        return this.value;
    }
    
    public int compareTo(final Object o) {
        return this.value - ((OptionIPv6)o).value;
    }
    
    @Override
    public boolean equals(final Object o) {
        final boolean result = o instanceof OptionIPv6 && this.value == ((OptionIPv6)o).value;
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
        IPV6_OPTIONS = new OptionIPv6(1, "IPV6_OPTIONS");
        IPV6_PKTINFO = new OptionIPv6(46, "IPV6_PKTINFO");
        values = new OptionIPv6[] { OptionIPv6.IPV6_OPTIONS, OptionIPv6.IPV6_PKTINFO };
    }
}
