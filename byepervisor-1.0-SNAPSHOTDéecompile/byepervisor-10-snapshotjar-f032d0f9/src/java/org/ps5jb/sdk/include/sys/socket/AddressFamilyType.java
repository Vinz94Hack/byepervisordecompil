package org.ps5jb.sdk.include.sys.socket;

import org.ps5jb.sdk.res.ErrorMessages;

public final class AddressFamilyType implements Comparable
{
    public static final AddressFamilyType AF_UNSPEC;
    public static final AddressFamilyType AF_UNIX;
    public static final AddressFamilyType AF_LOCAL;
    public static final AddressFamilyType AF_INET;
    public static final AddressFamilyType AF_INET6;
    private static final AddressFamilyType[] values;
    private final int value;
    private final String name;
    
    private AddressFamilyType(final int value, final String name) {
        this.value = value;
        this.name = name;
    }
    
    public static AddressFamilyType[] values() {
        return AddressFamilyType.values;
    }
    
    public static AddressFamilyType valueOf(final short value) {
        for (final AddressFamilyType rtPrioType : AddressFamilyType.values) {
            if (value == rtPrioType.value()) {
                return rtPrioType;
            }
        }
        throw new IllegalArgumentException(ErrorMessages.getClassErrorMessage(AddressFamilyType.class, "invalidValue", Integer.toString((int)value)));
    }
    
    public int value() {
        return this.value;
    }
    
    public int compareTo(final Object o) {
        return this.value - ((AddressFamilyType)o).value;
    }
    
    @Override
    public boolean equals(final Object o) {
        final boolean result = o instanceof AddressFamilyType && this.value == ((AddressFamilyType)o).value;
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
        AF_UNSPEC = new AddressFamilyType(0, "AF_UNSPEC");
        AF_UNIX = new AddressFamilyType(1, "AF_UNIX");
        AF_LOCAL = new AddressFamilyType(AddressFamilyType.AF_UNIX.value, "AF_LOCAL");
        AF_INET = new AddressFamilyType(2, "AF_INET");
        AF_INET6 = new AddressFamilyType(28, "AF_INET6");
        values = new AddressFamilyType[] { AddressFamilyType.AF_UNSPEC, AddressFamilyType.AF_UNIX, AddressFamilyType.AF_LOCAL, AddressFamilyType.AF_INET, AddressFamilyType.AF_INET6 };
    }
}
