package org.ps5jb.client.payloads.umtx.common;

import java.util.Iterator;
import org.ps5jb.sdk.core.Pointer;
import org.ps5jb.sdk.core.SdkException;
import org.ps5jb.sdk.include.sys.errno.NotFoundException;
import java.util.Collection;
import org.ps5jb.sdk.core.kernel.KernelPointer;
import org.ps5jb.sdk.lib.LibKernel;

public class KernelStabilizer
{
    private static final long OFFSET_SHMFD_SHM_REFS = 16L;
    private static final long OFFSET_FILE_F_DATA = 0L;
    private static final long OFFSET_FILE_F_TYPE = 32L;
    private static final long OFFSET_FILE_F_COUNT = 40L;
    private static final long OFFSET_THREAD_KSTACK_OBJ = 1128L;
    private static final long OFFSET_THREAD_KSTACK = 1136L;
    private static final long OFFSET_VMSPACE_VM_MAP = 0L;
    private static final long OFFSET_VM_MAP_ENTRY_START = 32L;
    private static final long OFFSET_VM_MAP_ENTRY_OBJECT = 80L;
    private static final long OFFSET_VM_MAP_ENTRY_NEXT = 8L;
    private static final long OFFSET_VM_OBJECT_REF_COUNT = 132L;
    private final LibKernel libKernel;
    
    public KernelStabilizer() {
        this.libKernel = new LibKernel();
    }
    
    public void free() {
        this.libKernel.closeLibrary();
    }
    
    public void fixupKernelStack(final KernelPointer threadAddress) {
        final KernelPointer kstack_obj_ptr = KernelPointer.valueOf(threadAddress.read8(1128L));
        threadAddress.write8(1136L, 0L);
        kstack_obj_ptr.write4(132L, 16);
    }
    
    public int fixupVmSpace(final KernelPointer processAddress, final Collection mappedKernelStackAddresses) {
        int numFixes = 0;
        if (mappedKernelStackAddresses != null) {
            final int stackUserAddressCount = mappedKernelStackAddresses.size();
            final KernelPointer vmSpaceAddress = KernelPointer.valueOf(processAddress.read8(512L));
            for (KernelPointer vmMapAddress = KernelPointer.valueOf(vmSpaceAddress.read8(0L)); !KernelPointer.NULL.equals(vmMapAddress) && numFixes < stackUserAddressCount; vmMapAddress = KernelPointer.valueOf(vmMapAddress.read8(8L))) {
                if (this.fixVmMapEntry(vmMapAddress, mappedKernelStackAddresses)) {
                    ++numFixes;
                }
            }
        }
        return numFixes;
    }
    
    public int fixupSharedMemory(final KernelPointer openFilesAddress, final int lookupDescriptor) throws SdkException {
        KernelPointer.validRange(openFilesAddress);
        if (lookupDescriptor == -1) {
            throw new NotFoundException("Lookup descriptor of primary shared memory object not found");
        }
        final KernelPointer fileDescEntryAddress = openFilesAddress.inc(lookupDescriptor * 48L);
        final KernelPointer fileAddress = KernelPointer.valueOf(fileDescEntryAddress.read8());
        final KernelPointer sharedMemoryFileDescAddress = KernelPointer.valueOf(fileAddress.read8(0L));
        if (!KernelPointer.NULL.equals(sharedMemoryFileDescAddress)) {
            final KernelPointer shmRefCountAddress = sharedMemoryFileDescAddress.inc(16L);
            shmRefCountAddress.write4(16);
        }
        final KernelPointer fCountAddress = fileAddress.inc(40L);
        fCountAddress.write4(16);
        return this.libKernel.close(lookupDescriptor);
    }
    
    private boolean fixVmMapEntry(final KernelPointer mapEntryKernelAddress, final Collection mappedKernelStackAddresses) {
        boolean matched = false;
        final long startUserAddress = mapEntryKernelAddress.read8(32L);
        for (final Pointer userAddress : mappedKernelStackAddresses) {
            if (userAddress.addr() == startUserAddress) {
                final KernelPointer objectAddress = KernelPointer.valueOf(mapEntryKernelAddress.read8(80L));
                if (!KernelPointer.NULL.equals(objectAddress)) {
                    final KernelPointer refCountAddress = objectAddress.inc(132L);
                    refCountAddress.write4(16);
                }
                matched = true;
                break;
            }
        }
        return matched;
    }
    
    public int fixUsedDescriptors(final KernelPointer openFilesAddress, final Collection usedDescriptors) {
        int numFixes = 0;
        for (final int descriptor : usedDescriptors) {
            final KernelPointer fileDescEntryAddress = openFilesAddress.inc(descriptor * 48L);
            KernelPointer fileAddress = KernelPointer.NULL;
            if (!KernelPointer.NULL.equals(fileDescEntryAddress)) {
                fileAddress = KernelPointer.valueOf(fileDescEntryAddress.read8());
            }
            if (!KernelPointer.NULL.equals(fileAddress)) {
                final short fileType = fileAddress.read2(32L);
                if (fileType != 8) {
                    continue;
                }
                ++numFixes;
            }
        }
        return numFixes;
    }
}
