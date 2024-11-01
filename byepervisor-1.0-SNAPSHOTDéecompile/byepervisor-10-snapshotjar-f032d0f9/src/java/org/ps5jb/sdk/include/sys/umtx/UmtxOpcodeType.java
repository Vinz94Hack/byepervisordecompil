package org.ps5jb.sdk.include.sys.umtx;

import org.ps5jb.sdk.res.ErrorMessages;

public final class UmtxOpcodeType implements Comparable
{
    public static final UmtxOpcodeType UMTX_OP_SHM;
    private static final UmtxOpcodeType[] values;
    private int value;
    private String name;
    
    private UmtxOpcodeType(final int value, final String name) {
        this.value = value;
        this.name = name;
    }
    
    public static UmtxOpcodeType[] values() {
        return UmtxOpcodeType.values;
    }
    
    public static UmtxOpcodeType valueOf(final int value) {
        for (final UmtxOpcodeType opcodeType : UmtxOpcodeType.values) {
            if (value == opcodeType.value()) {
                return opcodeType;
            }
        }
        throw new IllegalArgumentException(ErrorMessages.getClassErrorMessage(UmtxOpcodeType.class, "invalidValue", Integer.toString(value)));
    }
    
    public int value() {
        return this.value;
    }
    
    public int compareTo(final Object o) {
        return this.value - ((UmtxOpcodeType)o).value;
    }
    
    @Override
    public boolean equals(final Object o) {
        final boolean result = o instanceof UmtxOpcodeType && this.value == ((UmtxOpcodeType)o).value;
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
        UMTX_OP_SHM = new UmtxOpcodeType(26, "UMTX_OP_SHM");
        values = new UmtxOpcodeType[] { UmtxOpcodeType.UMTX_OP_SHM };
    }
}
