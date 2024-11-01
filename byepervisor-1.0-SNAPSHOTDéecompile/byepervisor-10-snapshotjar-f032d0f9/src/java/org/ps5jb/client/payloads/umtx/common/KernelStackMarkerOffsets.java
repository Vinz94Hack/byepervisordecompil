package org.ps5jb.client.payloads.umtx.common;

import org.ps5jb.sdk.core.SdkSoftwareVersionUnsupportedException;

public class KernelStackMarkerOffsets
{
    public final long OFFSET_RET_FROM_MARKER;
    public final long OFFSET_KBASE_FROM_RET;
    
    public KernelStackMarkerOffsets(final int softwareVersion) {
        switch (softwareVersion) {
            case 258: {
                this.OFFSET_RET_FROM_MARKER = -196L;
                this.OFFSET_KBASE_FROM_RET = -5062920L;
                break;
            }
            case 592: {
                this.OFFSET_RET_FROM_MARKER = -212L;
                this.OFFSET_KBASE_FROM_RET = -4847710L;
                break;
            }
            case 1616: {
                this.OFFSET_RET_FROM_MARKER = -196L;
                this.OFFSET_KBASE_FROM_RET = -2933129L;
                break;
            }
            case 1824: {
                this.OFFSET_RET_FROM_MARKER = -196L;
                this.OFFSET_KBASE_FROM_RET = -2907221L;
                break;
            }
            default: {
                throw new SdkSoftwareVersionUnsupportedException("Firmware not supported: 0x" + Integer.toHexString(softwareVersion));
            }
        }
    }
}
