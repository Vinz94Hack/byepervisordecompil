package org.ps5jb.sdk.include.sys.dirent;

import org.ps5jb.sdk.res.ErrorMessages;

public final class DirType implements Comparable
{
    public static final DirType DT_UNKNOWN;
    public static final DirType DT_FIFO;
    public static final DirType DT_CHR;
    public static final DirType DT_DIR;
    public static final DirType DT_BLK;
    public static final DirType DT_REG;
    public static final DirType DT_LNK;
    public static final DirType DT_SOCK;
    public static final DirType DT_WHT;
    private static final DirType[] values;
    private int value;
    private String name;
    
    private DirType(final int value, final String name) {
        this.value = value;
        this.name = name;
    }
    
    public static DirType[] values() {
        return DirType.values;
    }
    
    public static DirType valueOf(final int value) {
        for (final DirType dirType : DirType.values) {
            if (value == dirType.value()) {
                return dirType;
            }
        }
        throw new IllegalArgumentException(ErrorMessages.getClassErrorMessage(DirType.class, "invalidValue", Integer.toString(value)));
    }
    
    public int value() {
        return this.value;
    }
    
    public static int or(final DirType... flags) {
        int result = 0;
        for (final DirType flag : flags) {
            result |= flag.value;
        }
        return result;
    }
    
    public int compareTo(final Object o) {
        return this.value - ((DirType)o).value;
    }
    
    @Override
    public boolean equals(final Object o) {
        final boolean result = o instanceof DirType && this.value == ((DirType)o).value;
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
        DT_UNKNOWN = new DirType(0, "DT_UNKNOWN");
        DT_FIFO = new DirType(1, "DT_FIFO");
        DT_CHR = new DirType(2, "DT_CHR");
        DT_DIR = new DirType(4, "DT_DIR");
        DT_BLK = new DirType(6, "DT_BLK");
        DT_REG = new DirType(8, "DT_REG");
        DT_LNK = new DirType(10, "DT_LNK");
        DT_SOCK = new DirType(12, "DT_SOCK");
        DT_WHT = new DirType(14, "DT_WHT");
        values = new DirType[] { DirType.DT_UNKNOWN, DirType.DT_FIFO, DirType.DT_CHR, DirType.DT_DIR, DirType.DT_BLK, DirType.DT_REG, DirType.DT_LNK, DirType.DT_SOCK, DirType.DT_WHT };
    }
}
