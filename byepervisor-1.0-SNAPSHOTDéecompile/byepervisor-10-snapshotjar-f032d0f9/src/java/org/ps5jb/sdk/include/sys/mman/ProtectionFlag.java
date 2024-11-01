package org.ps5jb.sdk.include.sys.mman;

import org.ps5jb.sdk.res.ErrorMessages;

public final class ProtectionFlag implements Comparable
{
    public static final ProtectionFlag PROT_NONE;
    public static final ProtectionFlag PROT_READ;
    public static final ProtectionFlag PROT_WRITE;
    public static final ProtectionFlag PROT_EXEC;
    private static final ProtectionFlag[] values;
    private int value;
    private String name;
    
    private ProtectionFlag(final int value, final String name) {
        this.value = value;
        this.name = name;
    }
    
    public static ProtectionFlag[] values() {
        return ProtectionFlag.values;
    }
    
    public static ProtectionFlag valueOf(final int value) {
        for (final ProtectionFlag protectionFlag : ProtectionFlag.values) {
            if (value == protectionFlag.value()) {
                return protectionFlag;
            }
        }
        throw new IllegalArgumentException(ErrorMessages.getClassErrorMessage(ProtectionFlag.class, "invalidValue", Integer.toString(value)));
    }
    
    public int value() {
        return this.value;
    }
    
    public static int or(final ProtectionFlag... flags) {
        int result = 0;
        for (final ProtectionFlag flag : flags) {
            result |= flag.value;
        }
        return result;
    }
    
    public int compareTo(final Object o) {
        return this.value - ((ProtectionFlag)o).value;
    }
    
    @Override
    public boolean equals(final Object o) {
        final boolean result = o instanceof ProtectionFlag && this.value == ((ProtectionFlag)o).value;
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
        PROT_NONE = new ProtectionFlag(0, "PROT_NONE");
        PROT_READ = new ProtectionFlag(1, "PROT_READ");
        PROT_WRITE = new ProtectionFlag(2, "PROT_WRITE");
        PROT_EXEC = new ProtectionFlag(4, "PROT_EXEC");
        values = new ProtectionFlag[] { ProtectionFlag.PROT_NONE, ProtectionFlag.PROT_READ, ProtectionFlag.PROT_WRITE, ProtectionFlag.PROT_EXEC };
    }
}
