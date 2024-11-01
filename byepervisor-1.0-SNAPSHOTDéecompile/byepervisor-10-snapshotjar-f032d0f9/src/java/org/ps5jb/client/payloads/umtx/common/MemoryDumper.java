package org.ps5jb.client.payloads.umtx.common;

import org.ps5jb.sdk.core.AbstractPointer;

public class MemoryDumper
{
    public static void dump(final AbstractPointer buf, final long size, final boolean relative) {
        final StringBuffer sb = new StringBuffer(110);
        for (int j = 0; j < size; j += 16) {
            sb.append(AbstractPointer.toString(relative ? ((long)j) : (buf.addr() + j)));
            sb.append(":   ");
            for (int i = 0; i < 2; ++i) {
                if (j + i * 8 + 8 <= size) {
                    final long value = buf.read8(j + i * 8);
                    for (int k = 0; k < 8; ++k) {
                        final String hex = Long.toHexString(value >> k * 8 & 0xFFL);
                        if (k != 0) {
                            sb.append(" ");
                        }
                        else if (i == 1) {
                            sb.append("      ");
                        }
                        if (hex.length() == 1) {
                            sb.append("0");
                        }
                        sb.append(hex);
                    }
                }
                else {
                    for (int l = 0; j + i * 8 + l < size; ++l) {
                        final byte val = buf.read1(j + i * 8 + l);
                        final String hex2 = Integer.toHexString(val & 0xFF);
                        if (l != 0) {
                            sb.append(" ");
                        }
                        else if (i == 1) {
                            sb.append("      ");
                        }
                        if (hex2.length() == 1) {
                            sb.append("0");
                        }
                        sb.append(hex2);
                    }
                }
            }
            DebugStatus.info(sb.toString());
            sb.setLength(0);
        }
    }
}
