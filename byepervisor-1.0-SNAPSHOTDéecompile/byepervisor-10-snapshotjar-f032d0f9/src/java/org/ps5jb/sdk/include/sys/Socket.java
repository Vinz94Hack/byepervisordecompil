package org.ps5jb.sdk.include.sys;

import org.ps5jb.sdk.core.Pointer;
import org.ps5jb.sdk.include.netinet6.in6.OptionIPv6;
import org.ps5jb.sdk.core.SdkException;
import org.ps5jb.sdk.include.inet.in.ProtocolType;
import org.ps5jb.sdk.include.sys.socket.SocketType;
import org.ps5jb.sdk.include.sys.socket.AddressFamilyType;
import org.ps5jb.sdk.lib.LibKernel;

public class Socket
{
    private final LibKernel libKernel;
    private final ErrNo errNo;
    
    public Socket(final LibKernel libKernel) {
        this.libKernel = libKernel;
        this.errNo = new ErrNo(this.libKernel);
    }
    
    public int createSocket(final AddressFamilyType domain, final SocketType socketType, final ProtocolType protocol) throws SdkException {
        final int ret = this.libKernel.socket(domain.value(), socketType.value(), protocol.value());
        if (ret == -1) {
            throw this.errNo.getLastException(this.getClass(), "createSocket", new Object[0]);
        }
        return ret;
    }
    
    public void setSocketOptionsIPv6(final int socket, final OptionIPv6 optionName, final Pointer optionValue) throws SdkException {
        final int ret = this.libKernel.setsockopt(socket, ProtocolType.IPPROTO_IPV6.value(), optionName.value(), optionValue, optionValue.size());
        if (ret == -1) {
            throw this.errNo.getLastException(this.getClass(), "setSocketOptionsIPv6", new Object[0]);
        }
    }
    
    public Pointer getSocketOptionsIPv6(final int socket, final OptionIPv6 optionName, final Pointer optionValue) throws SdkException {
        final Pointer optlen = Pointer.calloc(4L);
        try {
            optlen.write4(optionValue.size().intValue());
            final int ret = this.libKernel.getsockopt(socket, ProtocolType.IPPROTO_IPV6.value(), optionName.value(), optionValue, optlen);
            if (ret == -1) {
                throw this.errNo.getLastException(this.getClass(), "getSocketOptionsIPv6", new Object[0]);
            }
            final int newLen = optlen.read4();
            Pointer pointer;
            if (newLen == optionValue.size().intValue()) {
                pointer = optionValue;
            }
            else {
                final long addr;
                final Long size;
                pointer = new Pointer(addr, size);
                addr = optionValue.addr();
                size = new Long((long)newLen);
            }
            return pointer;
        }
        finally {
            optlen.free();
        }
    }
}
