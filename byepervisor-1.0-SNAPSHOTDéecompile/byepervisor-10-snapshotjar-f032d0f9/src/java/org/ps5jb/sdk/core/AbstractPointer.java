package org.ps5jb.sdk.core;

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.io.Serializable;

public abstract class AbstractPointer implements Serializable
{
    private static final long serialVersionUID = 5085573430112354497L;
    protected long addr;
    protected Long size;
    
    public static AbstractPointer nonNull(final AbstractPointer pointer, final String errorMessage) {
        if (pointer == null || pointer.addr() == 0L) {
            throw new NullPointerException(errorMessage);
        }
        return pointer;
    }
    
    public static void overflow(final AbstractPointer pointer, final long offset, final long size) {
        if (pointer.size != null) {
            if (offset < 0L) {
                throw new IndexOutOfBoundsException(Long.toString(offset));
            }
            if (offset + size > pointer.size) {
                throw new IndexOutOfBoundsException(Long.toString(offset + size));
            }
        }
    }
    
    protected AbstractPointer(final long addr) {
        this(addr, null);
    }
    
    protected AbstractPointer(final long addr, final Long size) {
        this.addr = addr;
        this.size = size;
    }
    
    public byte read1(final long offset) {
        overflow(this, offset, 1L);
        return this.read1impl(offset);
    }
    
    public byte read1() {
        return this.read1(0L);
    }
    
    protected abstract byte read1impl(final long p0);
    
    public short read2(final long offset) {
        overflow(this, offset, 2L);
        return this.read2impl(offset);
    }
    
    public short read2() {
        return this.read2(0L);
    }
    
    protected abstract short read2impl(final long p0);
    
    public int read4(final long offset) {
        overflow(this, offset, 4L);
        return this.read4impl(offset);
    }
    
    public int read4() {
        return this.read4(0L);
    }
    
    protected abstract int read4impl(final long p0);
    
    public long read8(final long offset) {
        overflow(this, offset, 8L);
        return this.read8impl(offset);
    }
    
    public long read8() {
        return this.read8(0L);
    }
    
    protected abstract long read8impl(final long p0);
    
    public byte[] read(final int size) {
        final byte[] result = new byte[size];
        this.read(0L, result, 0, size);
        return result;
    }
    
    public void read(final long offset, final byte[] value, final int valueOffset, final int size) {
        overflow(this, offset, size);
        int bufferLen;
        for (int i = 0; i < size; i += bufferLen) {
            long buffer;
            if (i + 8 <= size) {
                buffer = this.read8impl(offset + i);
                bufferLen = 8;
            }
            else if (i + 4 <= size) {
                buffer = this.read4impl(offset + i);
                bufferLen = 4;
            }
            else if (i + 2 <= size) {
                buffer = this.read2impl(offset + i);
                bufferLen = 2;
            }
            else {
                buffer = this.read1impl(offset + i);
                bufferLen = 1;
            }
            for (int j = 0; j < bufferLen; ++j) {
                value[valueOffset + i + j] = (byte)(buffer >> j * 8 & 0xFFL);
            }
        }
    }
    
    public String readString(final long offset, final Integer maxLength, final String charset) {
        try {
            final ByteArrayOutputStream buf = new ByteArrayOutputStream();
            try {
                int curSize = 0;
                byte[] buffer;
                if (maxLength == null) {
                    buffer = new byte[] { 0 };
                }
                else {
                    buffer = new byte[8];
                }
                while (maxLength == null || maxLength > curSize) {
                    int readLen;
                    if (maxLength == null) {
                        readLen = 1;
                    }
                    else if (this.size != null && offset + curSize + 8L >= this.size) {
                        readLen = (int)(this.size - offset - curSize);
                    }
                    else {
                        readLen = Math.min(8, maxLength - curSize);
                    }
                    this.read(offset + curSize, buffer, 0, readLen);
                    boolean eos = false;
                    for (int i = 0; i < readLen; ++i) {
                        if (buffer[i] == 0) {
                            eos = true;
                            break;
                        }
                        buf.write((int)buffer[i]);
                        ++curSize;
                    }
                    if (eos) {
                        break;
                    }
                }
                return buf.toString(charset);
            }
            finally {
                buf.close();
            }
        }
        catch (final IOException e) {
            throw new SdkRuntimeException((Throwable)e);
        }
    }
    
    public String readString(final Integer maxLength) {
        return this.readString(0L, maxLength, Charset.defaultCharset().name());
    }
    
    public void write1(final long offset, final byte value) {
        overflow(this, offset, 1L);
        this.write1impl(offset, value);
    }
    
    public void write1(final byte value) {
        this.write1(0L, value);
    }
    
    protected abstract void write1impl(final long p0, final byte p1);
    
    public void write2(final long offset, final short value) {
        overflow(this, offset, 2L);
        this.write2impl(offset, value);
    }
    
    public void write2(final short value) {
        this.write2(0L, value);
    }
    
    protected abstract void write2impl(final long p0, final short p1);
    
    public void write4(final long offset, final int value) {
        overflow(this, offset, 4L);
        this.write4impl(offset, value);
    }
    
    public void write4(final int value) {
        this.write4(0L, value);
    }
    
    protected abstract void write4impl(final long p0, final int p1);
    
    public void write8(final long offset, final long value) {
        overflow(this, offset, 8L);
        this.write8impl(offset, value);
    }
    
    public void write8(final long value) {
        this.write8(0L, value);
    }
    
    protected abstract void write8impl(final long p0, final long p1);
    
    public void write(final byte[] value) {
        this.write(0L, value, 0, value.length);
    }
    
    public void write(final long offset, final byte[] value, final int valueOffset, final int count) {
        overflow(this, offset, count);
        int bufferLen;
        for (int i = 0; i < count; i += bufferLen) {
            if (i + 8 <= count) {
                bufferLen = 8;
            }
            else if (i + 4 <= count) {
                bufferLen = 4;
            }
            else if (i + 2 <= count) {
                bufferLen = 2;
            }
            else {
                bufferLen = 1;
            }
            long buffer = 0L;
            for (int j = 0; j < bufferLen; ++j) {
                buffer |= (long)(value[valueOffset + i + j] & 0xFF) << j * 8;
            }
            if (bufferLen == 8) {
                this.write8impl(offset + i, buffer);
            }
            else if (bufferLen == 4) {
                this.write4impl(offset + i, (int)(buffer & 0xFFFFFFFFL));
            }
            else if (bufferLen == 2) {
                this.write2impl(offset + i, (short)(buffer & 0xFFFFL));
            }
            else {
                this.write1impl(offset + i, (byte)(buffer & 0xFFL));
            }
        }
    }
    
    public void writeString(final long offset, final String string, final String charset) {
        byte[] stringBuffer;
        try {
            stringBuffer = string.getBytes(charset);
        }
        catch (final UnsupportedEncodingException e) {
            throw new SdkRuntimeException((Throwable)e);
        }
        this.write(offset, stringBuffer, 0, stringBuffer.length);
        this.write1(offset + stringBuffer.length, (byte)0);
    }
    
    public void writeString(final String string) {
        this.writeString(0L, string, Charset.defaultCharset().name());
    }
    
    public long addr() {
        return this.addr;
    }
    
    public Long size() {
        return this.size;
    }
    
    @Override
    public boolean equals(final Object obj) {
        boolean result = false;
        if (obj instanceof AbstractPointer) {
            result = (((AbstractPointer)obj).addr == this.addr);
        }
        return result;
    }
    
    @Override
    public int hashCode() {
        return new Long(this.addr).hashCode();
    }
    
    @Override
    public String toString() {
        return toString(this.addr);
    }
    
    public static String toString(final long addr) {
        int padLength;
        if (addr > 4294967295L) {
            padLength = 16;
        }
        else {
            padLength = 8;
        }
        final StringBuffer buf = new StringBuffer(padLength);
        buf.append("0x");
        final String hexAddr = Long.toHexString(addr);
        for (int padCount = padLength - hexAddr.length(), i = 0; i < padCount; ++i) {
            buf.append("0");
        }
        buf.append(hexAddr);
        return buf.toString();
    }
}
