package org.ps5jb.client.payloads.umtx.common;

import org.ps5jb.loader.KernelReadWrite;
import org.ps5jb.sdk.core.Pointer;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicBoolean;
import org.ps5jb.sdk.lib.LibKernel;

public class CommandProcessor
{
    private final LibKernel libKernel;
    public static final int CMD_NOP = 0;
    public static final int CMD_READ = 1;
    public static final int CMD_WRITE = 2;
    public static final int CMD_EXIT = 3;
    public AtomicBoolean exitSignal;
    public AtomicInteger cmd;
    public AtomicInteger len;
    public AtomicLong readCounter;
    public AtomicLong writeCounter;
    
    public CommandProcessor() {
        this.exitSignal = new AtomicBoolean();
        this.cmd = new AtomicInteger(0);
        this.len = new AtomicInteger();
        this.readCounter = new AtomicLong();
        this.writeCounter = new AtomicLong();
        this.libKernel = new LibKernel();
    }
    
    public void handleCommands() {
        int pipeReadFd = -1;
        Pointer pipeScratchBuf = Pointer.NULL;
        int pipeWriteFd = -1;
        while (!this.exitSignal.get()) {
            final int cmd = this.cmd.get();
            if (cmd == 0) {
                Thread.yield();
            }
            else {
                final long len = this.len.get();
                if (Pointer.NULL.equals(pipeScratchBuf)) {
                    final KernelAccessorSlow ka = (KernelAccessorSlow)KernelReadWrite.getAccessor();
                    pipeReadFd = ka.pipeReadFd;
                    pipeWriteFd = ka.pipeWriteFd;
                    pipeScratchBuf = ka.pipeScratchBuf;
                }
                switch (cmd) {
                    case 1: {
                        if (DebugStatus.isDebugEnabled()) {
                            DebugStatus.debug("Command processor: blocking to write " + len + " bytes for READ command");
                        }
                        final long read = this.libKernel.write(pipeWriteFd, pipeScratchBuf, len);
                        this.readCounter.incrementAndGet();
                        if (DebugStatus.isDebugEnabled()) {
                            DebugStatus.debug("Command processor: written " + read + " bytes");
                            break;
                        }
                        break;
                    }
                    case 2: {
                        if (DebugStatus.isDebugEnabled()) {
                            DebugStatus.debug("Command processor: blocking to read " + len + " bytes for WRITE command");
                        }
                        final long write = this.libKernel.read(pipeReadFd, pipeScratchBuf, len);
                        this.writeCounter.incrementAndGet();
                        if (DebugStatus.isDebugEnabled()) {
                            DebugStatus.debug("Command processor: read " + write + " bytes");
                            break;
                        }
                        break;
                    }
                    case 3: {
                        DebugStatus.info("Command processor: exiting");
                        this.exitSignal.set(true);
                        break;
                    }
                    default: {
                        DebugStatus.error("Command processor: unknown command");
                        break;
                    }
                }
                this.cmd.set(0);
                DebugStatus.debug("Command processor: resetting");
            }
        }
        this.libKernel.closeLibrary();
        DebugStatus.info("Command processor: finished and cannot be reused");
    }
}
