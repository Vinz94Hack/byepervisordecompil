package org.ps5jb.sdk.lib;

import org.ps5jb.sdk.core.SdkRuntimeException;
import org.ps5jb.sdk.res.ErrorMessages;
import org.ps5jb.sdk.core.Pointer;
import org.ps5jb.sdk.core.Library;

public class LibKernel extends Library
{
    private Pointer __error;
    private Pointer cpuset_getaffinity;
    private Pointer cpuset_setaffinity;
    private Pointer sceKernelSendNotificationRequest;
    private Pointer getuid;
    private Pointer setuid;
    private Pointer getpid;
    private Pointer open;
    private Pointer close;
    private Pointer getdents;
    private Pointer stat;
    private Pointer fstat;
    private Pointer sceKernelCheckReachability;
    private Pointer pthread_rename_np;
    private Pointer pthread_self;
    private Pointer rtprio_thread;
    private Pointer pipe;
    private Pointer shm_open;
    private Pointer shm_unlink;
    private Pointer mmap;
    private Pointer munmap;
    private Pointer ftruncate;
    private Pointer select;
    private Pointer ioctl;
    private Pointer read;
    private Pointer write;
    private Pointer _umtx_op;
    private Pointer mprotect;
    private Pointer sched_yield;
    private Pointer sceKernelGetCurrentCpu;
    private Pointer sceKernelGetProsperoSystemSwVersion;
    private Pointer socket;
    private Pointer setsockopt;
    private Pointer getsockopt;
    private Pointer usleep;
    private Pointer is_in_sandbox;
    private Pointer sceKernelNotifySystemSuspendStart;
    private Pointer sceKernelSetEventFlag;
    private Pointer sceKernelOpenEventFlag;
    private Pointer sceKernelCloseEventFlag;
    
    public LibKernel() {
        super(8193L);
    }
    
    public int sceKernelSendNotificationRequest(final String msg) {
        final long size = 3120L;
        final Pointer buf = Pointer.calloc(3120L);
        try {
            buf.write4(16L, -1);
            buf.inc(45L).writeString(msg);
            if (this.sceKernelSendNotificationRequest == null) {
                this.sceKernelSendNotificationRequest = this.addrOf("sceKernelSendNotificationRequest");
            }
            return (int)this.call(this.sceKernelSendNotificationRequest, 0L, buf.addr(), 3120L, 0L);
        }
        finally {
            buf.free();
        }
    }
    
    public int cpuset_getaffinity(final int level, final int which, final long id, final long setsize, final Pointer mask) {
        if (this.cpuset_getaffinity == null) {
            this.cpuset_getaffinity = this.addrOf("cpuset_getaffinity");
        }
        return (int)this.call(this.cpuset_getaffinity, level, which, id, setsize, mask.addr());
    }
    
    public int cpuset_setaffinity(final int level, final int which, final long id, final long setsize, final Pointer mask) {
        if (this.cpuset_setaffinity == null) {
            this.cpuset_setaffinity = this.addrOf("cpuset_setaffinity");
        }
        return (int)this.call(this.cpuset_setaffinity, level, which, id, setsize, mask.addr());
    }
    
    public Pointer __error() {
        if (this.__error == null) {
            this.__error = this.addrOf("__error");
        }
        return Pointer.valueOf(this.call(this.__error, new long[0]));
    }
    
    public int getuid() {
        if (this.getuid == null) {
            this.getuid = this.addrOf("getuid");
        }
        return (int)this.call(this.getuid, new long[0]);
    }
    
    public int setuid(final int uid) {
        if (this.setuid == null) {
            this.setuid = this.addrOf("setuid");
        }
        return (int)this.call(this.setuid, uid);
    }
    
    public int getpid() {
        if (this.getpid == null) {
            this.getpid = this.addrOf("getpid");
        }
        return (int)this.call(this.getpid, new long[0]);
    }
    
    public int open(final String path, final int flags) {
        if (this.open == null) {
            this.open = this.addrOf("open");
        }
        final Pointer buf = Pointer.fromString(path);
        try {
            return (int)this.call(this.open, buf.addr(), flags);
        }
        finally {
            buf.free();
        }
    }
    
    public int close(final int fd) {
        if (this.close == null) {
            this.close = this.addrOf("close");
        }
        return (int)this.call(this.close, fd);
    }
    
    public int getdents(final int fd, final Pointer buf, final long nbytes) {
        if (this.getdents == null) {
            this.getdents = this.addrOf("getdents");
        }
        return (int)this.call(this.getdents, fd, buf.addr(), nbytes);
    }
    
    public int stat(final String path, final Pointer sb) {
        if (this.stat == null) {
            this.stat = this.addrOf("stat");
        }
        final Pointer buf = Pointer.fromString(path);
        try {
            return (int)this.call(this.stat, buf.addr(), sb.addr());
        }
        finally {
            buf.free();
        }
    }
    
    public int fstat(final int fd, final Pointer sb) {
        if (this.fstat == null) {
            this.fstat = this.addrOf("fstat");
        }
        return (int)this.call(this.fstat, fd, sb.addr());
    }
    
    public int sceKernelCheckReachability(final String path) {
        if (this.sceKernelCheckReachability == null) {
            this.sceKernelCheckReachability = this.addrOf("sceKernelCheckReachability");
        }
        final Pointer buf = Pointer.fromString(path);
        try {
            return (int)this.call(this.sceKernelCheckReachability, buf.addr());
        }
        finally {
            buf.free();
        }
    }
    
    public int pthread_rename_np(final Pointer thread, final String name) {
        if (this.pthread_rename_np == null) {
            this.pthread_rename_np = this.addrOf("pthread_rename_np");
        }
        final Pointer buf = Pointer.fromString(name);
        try {
            return (int)this.call(this.pthread_rename_np, thread.addr(), buf.addr());
        }
        finally {
            buf.free();
        }
    }
    
    public Pointer pthread_self() {
        if (this.pthread_self == null) {
            this.pthread_self = this.addrOf("pthread_self");
        }
        return Pointer.valueOf(this.call(this.pthread_self, new long[0]));
    }
    
    public int rtprio_thread(final int function, final int lwpid, final Pointer rtprio) {
        if (this.rtprio_thread == null) {
            this.rtprio_thread = this.addrOf("rtprio_thread");
        }
        return (int)this.call(this.rtprio_thread, function, lwpid, rtprio.addr());
    }
    
    public int pipe(final Pointer fildes) {
        if (this.pipe == null) {
            this.pipe = this.addrOf("pipe");
        }
        return (int)this.call(this.pipe, fildes.addr());
    }
    
    public int shm_open(final Pointer path, final int flags, final int mode) {
        if (this.shm_open == null) {
            this.shm_open = this.addrOf("shm_open");
        }
        return (int)this.call(this.shm_open, path.addr(), flags, mode);
    }
    
    public int shm_unlink(final Pointer path) {
        if (this.shm_unlink == null) {
            this.shm_unlink = this.addrOf("shm_unlink");
        }
        return (int)this.call(this.shm_unlink, path.addr());
    }
    
    public Pointer mmap(final Pointer addr, final long len, final int prot, final int flags, final int fd, final long offset) {
        if (this.mmap == null) {
            this.mmap = this.addrOf("mmap");
        }
        return new Pointer(this.call(this.mmap, addr.addr(), len, prot, flags, fd, offset), new Long(len));
    }
    
    public int munmap(final Pointer addr, final long len) {
        if (this.munmap == null) {
            this.munmap = this.addrOf("munmap");
        }
        return (int)this.call(this.munmap, addr.addr(), len);
    }
    
    public int ftruncate(final int fd, final long length) {
        if (this.ftruncate == null) {
            this.ftruncate = this.addrOf("ftruncate");
        }
        return (int)this.call(this.ftruncate, fd, length);
    }
    
    public int select(final int nfds, final Pointer readfds, final Pointer writefds, final Pointer exceptfds, final Pointer timeout) {
        if (this.select == null) {
            this.select = this.addrOf("select");
        }
        return (int)this.call(this.select, nfds, readfds.addr(), writefds.addr(), exceptfds.addr(), timeout.addr());
    }
    
    public int ioctl(final int fd, final long request, final long argp) {
        if (this.ioctl == null) {
            this.ioctl = this.addrOf("ioctl");
        }
        return (int)this.call(this.ioctl, fd, request, argp);
    }
    
    public long read(final int fd, final Pointer buf, final long nbytes) {
        if (this.read == null) {
            this.read = this.addrOf("read");
        }
        return this.call(this.read, fd, buf.addr(), nbytes);
    }
    
    public long write(final int fd, final Pointer buf, final long nbytes) {
        if (this.write == null) {
            this.write = this.addrOf("write");
        }
        return this.call(this.write, fd, buf.addr(), nbytes);
    }
    
    public int socket(final int domain, final int type, final int protocol) {
        if (this.socket == null) {
            this.socket = this.addrOf("socket");
        }
        return (int)this.call(this.socket, domain, type, protocol);
    }
    
    public int getsockopt(final int s, final int level, final int optname, final Pointer optval, final Pointer optlen) {
        if (this.getsockopt == null) {
            this.getsockopt = this.addrOf("getsockopt");
        }
        return (int)this.call(this.getsockopt, s, level, optname, optval.addr(), optlen.addr());
    }
    
    public int setsockopt(final int s, final int level, final int optname, final Pointer optval, final long optlen) {
        if (this.setsockopt == null) {
            this.setsockopt = this.addrOf("setsockopt");
        }
        return (int)this.call(this.setsockopt, s, level, optname, optval.addr(), optlen);
    }
    
    public int _umtx_op(final Pointer obj, final int op, final long val, final Pointer uaddr, final Pointer uaddr2) {
        if (this._umtx_op == null) {
            this._umtx_op = this.addrOf("_umtx_op");
        }
        return (int)this.call(this._umtx_op, obj.addr(), op, val, uaddr.addr(), uaddr2.addr());
    }
    
    public int mprotect(final Pointer addr, final long len, final int prot) {
        if (this.mprotect == null) {
            this.mprotect = this.addrOf("mprotect");
        }
        return (int)this.call(this.mprotect, addr.addr(), len, prot);
    }
    
    public int sched_yield() {
        return this.sched_yield(0L);
    }
    
    public int sched_yield(final long unused) {
        if (this.sched_yield == null) {
            this.sched_yield = this.addrOf("sched_yield");
        }
        return (int)this.call(this.sched_yield, unused);
    }
    
    public int sceKernelGetCurrentCpu() {
        if (this.sceKernelGetCurrentCpu == null) {
            this.sceKernelGetCurrentCpu = this.addrOf("sceKernelGetCurrentCpu");
        }
        return (int)this.call(this.sceKernelGetCurrentCpu, new long[0]);
    }
    
    public int usleep(final long microseconds) {
        if (this.usleep == null) {
            this.usleep = this.addrOf("usleep");
        }
        return (int)this.call(this.usleep, microseconds);
    }
    
    public byte[] sceKernelGetProsperoSystemSwVersion() {
        final long size = 40L;
        final Pointer buf = Pointer.calloc(40L);
        try {
            buf.write8(40L);
            if (this.sceKernelGetProsperoSystemSwVersion == null) {
                this.sceKernelGetProsperoSystemSwVersion = this.addrOf("sceKernelGetProsperoSystemSwVersion");
            }
            final int ret = (int)this.call(this.sceKernelGetProsperoSystemSwVersion, buf.addr());
            if (ret != 0) {
                throw new SdkRuntimeException(ErrorMessages.getClassErrorMessage(LibKernel.class, "sceKernelGetProsperoSystemSwVersion", "0x" + Integer.toHexString(ret)));
            }
            final long resultOffset = 8L;
            final int resultSize = 32;
            final byte[] result = new byte[32];
            buf.read(8L, result, 0, 32);
            return result;
        }
        finally {
            buf.free();
        }
    }
    
    public int getSystemSoftwareVersion() {
        final byte[] swVer = this.sceKernelGetProsperoSystemSwVersion();
        return swVer[31] << 8 | swVer[30];
    }
    
    public boolean is_in_sandbox() {
        if (this.is_in_sandbox == null) {
            this.is_in_sandbox = this.addrOf("is_in_sandbox");
        }
        return this.call(this.is_in_sandbox, new long[0]) != 0L;
    }
    
    public void sceKernelNotifySystemSuspendStart() {
        if (this.sceKernelNotifySystemSuspendStart == null) {
            this.sceKernelNotifySystemSuspendStart = this.addrOf("sceKernelNotifySystemSuspendStart");
        }
        this.call(this.sceKernelNotifySystemSuspendStart, new long[0]);
    }
    
    public int sceKernelSetEventFlag(final long event, final int flag) {
        if (this.sceKernelSetEventFlag == null) {
            this.sceKernelSetEventFlag = this.addrOf("sceKernelSetEventFlag");
        }
        return (int)this.call(this.sceKernelSetEventFlag, event, flag);
    }
    
    public int sceKernelOpenEventFlag(final Pointer eventFlag, final String flagName) {
        if (this.sceKernelOpenEventFlag == null) {
            this.sceKernelOpenEventFlag = this.addrOf("sceKernelOpenEventFlag");
        }
        final Pointer flagNameParam = Pointer.fromString(flagName);
        try {
            return (int)this.call(this.sceKernelOpenEventFlag, eventFlag.addr(), flagNameParam.addr());
        }
        finally {
            flagNameParam.free();
        }
    }
    
    public int sceKernelCloseEventFlag(final Pointer eventFlag) {
        if (this.sceKernelCloseEventFlag == null) {
            this.sceKernelCloseEventFlag = this.addrOf("sceKernelCloseEventFlag");
        }
        return (int)this.call(this.sceKernelCloseEventFlag, eventFlag.addr());
    }
}
