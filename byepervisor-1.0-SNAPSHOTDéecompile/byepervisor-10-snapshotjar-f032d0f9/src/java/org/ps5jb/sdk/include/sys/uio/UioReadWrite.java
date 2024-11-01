package org.ps5jb.sdk.include.sys.uio;

import org.ps5jb.sdk.res.ErrorMessages;

public final class UioReadWrite implements Comparable
{
    public static final UioReadWrite UIO_READ;
    public static final UioReadWrite UIO_WRITE;
    private static final UioReadWrite[] values;
    private int value;
    private String name;
    
    private UioReadWrite(final int value, final String name) {
        this.value = value;
        this.name = name;
    }
    
    public static UioReadWrite[] values() {
        return UioReadWrite.values;
    }
    
    public static UioReadWrite valueOf(final int value) {
        for (final UioReadWrite urw : UioReadWrite.values) {
            if (value == urw.value()) {
                return urw;
            }
        }
        throw new IllegalArgumentException(ErrorMessages.getClassErrorMessage(UioReadWrite.class, "invalidValue", Integer.toString(value)));
    }
    
    public int value() {
        return this.value;
    }
    
    public int compareTo(final Object o) {
        return this.value - ((UioReadWrite)o).value;
    }
    
    @Override
    public boolean equals(final Object o) {
        final boolean result = o instanceof UioReadWrite && this.value == ((UioReadWrite)o).value;
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
        UIO_READ = new UioReadWrite(0, "UIO_READ");
        UIO_WRITE = new UioReadWrite(1, "UIO_WRITE");
        values = new UioReadWrite[] { UioReadWrite.UIO_READ, UioReadWrite.UIO_WRITE };
    }
}
