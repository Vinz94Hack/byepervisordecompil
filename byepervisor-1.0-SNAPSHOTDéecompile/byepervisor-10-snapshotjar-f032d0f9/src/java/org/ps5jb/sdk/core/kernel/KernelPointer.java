package org.ps5jb.sdk.core.kernel;

import org.ps5jb.loader.KernelAccessor;
import org.ps5jb.loader.KernelReadWrite;
import org.ps5jb.sdk.core.AbstractPointer;

public class KernelPointer extends AbstractPointer
{
    private static final long serialVersionUID = 3445279334363239500L;
    private static final long KERNEL_ADDR_MASK = -140737488355328L;
    private boolean rangeValidated;
    public static final KernelPointer NULL;
    
    public static KernelPointer valueOf(final long addr) {
        return (addr == 0L) ? KernelPointer.NULL : new KernelPointer(addr);
    }
    
    public static KernelPointer validRange(final KernelPointer pointer) {
        if ((pointer.addr() & 0xFFFF800000000000L) != 0xFFFF800000000000L || pointer.addr() == -1L) {
            throw new IllegalAccessError(pointer.toString());
        }
        return pointer;
    }
    
    public KernelPointer(final long addr) {
        super(addr);
        this.rangeValidated = false;
    }
    
    public KernelPointer(final long addr, final Long size) {
        super(addr, size);
        this.rangeValidated = false;
    }
    
    protected void checkRange() {
        if (!this.rangeValidated) {
            validRange(this);
            this.rangeValidated = true;
        }
    }
    
    @Override
    public byte read1(final long offset) {
        this.checkRange();
        return super.read1(offset);
    }
    
    @Override
    public short read2(final long offset) {
        this.checkRange();
        return super.read2(offset);
    }
    
    @Override
    public int read4(final long offset) {
        this.checkRange();
        return super.read4(offset);
    }
    
    @Override
    public long read8(final long offset) {
        this.checkRange();
        return super.read8(offset);
    }
    
    @Override
    public void read(final long offset, final byte[] value, final int valueOffset, final int size) {
        this.checkRange();
        final KernelAccessor ka = KernelReadWrite.getAccessor();
        if (ka instanceof KernelAccessorIPv6) {
            final KernelAccessorIPv6 kaIpv6 = (KernelAccessorIPv6)ka;
            kaIpv6.read(this.addr + offset, value, valueOffset, size);
        }
        else {
            super.read(offset, value, valueOffset, size);
        }
    }
    
    @Override
    public void write1(final long offset, final byte value) {
        this.checkRange();
        super.write1(offset, value);
    }
    
    @Override
    public void write2(final long offset, final short value) {
        this.checkRange();
        super.write2(offset, value);
    }
    
    @Override
    public void write4(final long offset, final int value) {
        this.checkRange();
        super.write4(offset, value);
    }
    
    @Override
    public void write8(final long offset, final long value) {
        this.checkRange();
        super.write8(offset, value);
    }
    
    @Override
    public void write(final long offset, final byte[] value, final int valueOffset, final int count) {
        this.checkRange();
        final KernelAccessor ka = KernelReadWrite.getAccessor();
        if (ka instanceof KernelAccessorIPv6) {
            final KernelAccessorIPv6 kaIpv6 = (KernelAccessorIPv6)ka;
            kaIpv6.write(this.addr + offset, value, valueOffset, count);
        }
        else {
            super.write(offset, value, valueOffset, count);
        }
    }
    
    @Override
    protected byte read1impl(final long offset) {
        return KernelReadWrite.getAccessor().read1(this.addr + offset);
    }
    
    @Override
    protected short read2impl(final long offset) {
        return KernelReadWrite.getAccessor().read2(this.addr + offset);
    }
    
    @Override
    protected int read4impl(final long offset) {
        return KernelReadWrite.getAccessor().read4(this.addr + offset);
    }
    
    @Override
    protected long read8impl(final long offset) {
        return KernelReadWrite.getAccessor().read8(this.addr + offset);
    }
    
    @Override
    protected void write1impl(final long offset, final byte value) {
        KernelReadWrite.getAccessor().write1(this.addr + offset, value);
    }
    
    @Override
    protected void write2impl(final long offset, final short value) {
        KernelReadWrite.getAccessor().write2(this.addr + offset, value);
    }
    
    @Override
    protected void write4impl(final long offset, final int value) {
        KernelReadWrite.getAccessor().write4(this.addr + offset, value);
    }
    
    @Override
    protected void write8impl(final long offset, final long value) {
        KernelReadWrite.getAccessor().write8(this.addr + offset, value);
    }
    
    public void copyTo(final KernelPointer dest, final long offset, final int size) {
        final byte[] data = new byte[size];
        this.read(offset, data, 0, size);
        dest.write(0L, data, 0, size);
    }
    
    public KernelPointer inc(final long delta) {
        return valueOf(this.addr + delta);
    }
    
    static {
        NULL = new KernelPointer(0L);
    }
}
