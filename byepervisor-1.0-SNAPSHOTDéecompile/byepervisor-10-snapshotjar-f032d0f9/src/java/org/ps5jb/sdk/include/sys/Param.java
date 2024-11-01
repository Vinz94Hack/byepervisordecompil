package org.ps5jb.sdk.include.sys;

public class Param
{
    public static final int MAXCOMLEN = 19;
    
    public static long rounddown(final long x, final long y) {
        return x / y * y;
    }
}
