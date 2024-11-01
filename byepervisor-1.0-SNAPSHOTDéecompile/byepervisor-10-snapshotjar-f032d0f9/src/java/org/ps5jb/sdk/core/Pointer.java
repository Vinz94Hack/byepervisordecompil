package org.ps5jb.sdk.core;

import java.security.PrivilegedActionException;
import java.lang.reflect.InvocationTargetException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import jdk.internal.misc.Unsafe;

public class Pointer extends AbstractPointer
{
    private static final long serialVersionUID = 2230199156786175114L;
    public static final Pointer NULL;
    
    protected static Unsafe getUnsafe() {
        return UnsafeHolder.unsafe;
    }
    
    private static long getLongValueOffset() {
        return UnsafeHolder.longValueOffset;
    }
    
    public static Pointer malloc(final long size) {
        return new Pointer(getUnsafe().allocateMemory(size), new Long(size));
    }
    
    public static Pointer calloc(final long size) {
        final Pointer result = malloc(size);
        try {
            int i;
            for (i = 0; i + 8 <= size; i += 8) {
                result.write8(i, 0L);
            }
            while (i < size) {
                result.write1(i, (byte)0);
                ++i;
            }
        }
        catch (final RuntimeException | Error e) {
            result.free();
            throw e;
        }
        return result;
    }
    
    public static Pointer fromString(final String string) {
        return fromString(string, Charset.defaultCharset().name());
    }
    
    public static Pointer fromString(final String string, final String charset) {
        byte[] stringBuffer;
        try {
            stringBuffer = string.getBytes(charset);
        }
        catch (final UnsupportedEncodingException e) {
            throw new SdkRuntimeException((Throwable)e);
        }
        final Pointer result = malloc(stringBuffer.length + 1);
        result.write(stringBuffer);
        result.write1(stringBuffer.length, (byte)0);
        return result;
    }
    
    static Pointer addrOf(final Object object) {
        final Long val = new Long(0L);
        getUnsafe().putObject((Object)val, getLongValueOffset(), object);
        return valueOf(getUnsafe().getLong((Object)val, getLongValueOffset()));
    }
    
    public static Pointer valueOf(final long addr) {
        return (addr == 0L) ? Pointer.NULL : new Pointer(addr);
    }
    
    public Pointer(final long addr) {
        super(addr);
    }
    
    public Pointer(final long addr, final Long size) {
        super(addr, size);
    }
    
    @Override
    protected byte read1impl(final long offset) {
        return getUnsafe().getByte(this.addr + offset);
    }
    
    @Override
    protected short read2impl(final long offset) {
        return getUnsafe().getShort(this.addr + offset);
    }
    
    @Override
    protected int read4impl(final long offset) {
        return getUnsafe().getInt(this.addr + offset);
    }
    
    @Override
    protected long read8impl(final long offset) {
        return getUnsafe().getLong(this.addr + offset);
    }
    
    @Override
    protected void write1impl(final long offset, final byte value) {
        getUnsafe().putByte(this.addr + offset, value);
    }
    
    @Override
    protected void write2impl(final long offset, final short value) {
        getUnsafe().putShort(this.addr + offset, value);
    }
    
    @Override
    protected void write4impl(final long offset, final int value) {
        getUnsafe().putInt(this.addr + offset, value);
    }
    
    @Override
    protected void write8impl(final long offset, final long value) {
        getUnsafe().putLong(this.addr + offset, value);
    }
    
    public void copyTo(final Pointer dest, final long offset, final int size) {
        final byte[] data = new byte[size];
        this.read(offset, data, 0, size);
        dest.write(0L, data, 0, size);
    }
    
    public void free() {
        getUnsafe().freeMemory(this.addr);
        this.addr = 0L;
        this.size = null;
    }
    
    public Pointer inc(final long delta) {
        return valueOf(this.addr + delta);
    }
    
    static {
        NULL = new Pointer(0L);
    }
    
    private static class UnsafeHolder
    {
        private static final Unsafe unsafe;
        private static final long longValueOffset;
        
        static {
            try {
                OpenModuleAction.execute("jdk.internal.misc.Unsafe");
                unsafe = Unsafe.getUnsafe();
                longValueOffset = UnsafeHolder.unsafe.objectFieldOffset(Long.class.getDeclaredField("value"));
            }
            catch (final PrivilegedActionException e) {
                if (e.getException() instanceof InvocationTargetException) {
                    throw new SdkRuntimeException(((InvocationTargetException)e.getException()).getTargetException());
                }
                throw new SdkRuntimeException((Throwable)e.getException());
            }
            catch (final NoSuchFieldException | RuntimeException | Error e2) {
                throw new SdkRuntimeException(e2);
            }
        }
    }
}
