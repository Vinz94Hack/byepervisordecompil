package org.ps5jb.sdk.core.kernel;

import org.ps5jb.sdk.core.SdkSoftwareVersionUnsupportedException;
import java.text.MessageFormat;

public class KernelOffsets
{
    public final long OFFSET_KERNEL_DATA;
    public final long OFFSET_KERNEL_DATA_BASE_DYNAMIC;
    public final long OFFSET_KERNEL_DATA_BASE_TO_DYNAMIC;
    public final long OFFSET_KERNEL_DATA_BASE_ALLPROC;
    public final long OFFSET_KERNEL_DATA_BASE_SECURITY_FLAGS;
    public final long OFFSET_KERNEL_DATA_BASE_TARGET_ID;
    public final long OFFSET_KERNEL_DATA_BASE_QA_FLAGS;
    public final long OFFSET_KERNEL_DATA_BASE_UTOKEN_FLAGS;
    public final long OFFSET_KERNEL_DATA_BASE_ROOTVNODE;
    public final long OFFSET_KERNEL_DATA_BASE_KERNEL_PMAP_STORE;
    public final long OFFSET_KERNEL_DATA_BASE_DATA_CAVE;
    public final long SIZE_KERNEL_DATA;
    
    public KernelOffsets(final int softwareVersion) {
        switch (softwareVersion) {
            case 256:
            case 257:
            case 258: {
                this.OFFSET_KERNEL_DATA = 28573696L;
                this.SIZE_KERNEL_DATA = 140712240L;
                this.OFFSET_KERNEL_DATA_BASE_DYNAMIC = 0L;
                this.OFFSET_KERNEL_DATA_BASE_TO_DYNAMIC = 106478424L;
                this.OFFSET_KERNEL_DATA_BASE_ALLPROC = 40705016L;
                this.OFFSET_KERNEL_DATA_BASE_SECURITY_FLAGS = 103026804L;
                this.OFFSET_KERNEL_DATA_BASE_ROOTVNODE = 106321216L;
                this.OFFSET_KERNEL_DATA_BASE_KERNEL_PMAP_STORE = 49935032L;
                this.OFFSET_KERNEL_DATA_BASE_DATA_CAVE = 99745792L;
                break;
            }
            case 261:
            case 272:
            case 273:
            case 274:
            case 275:
            case 276: {
                this.OFFSET_KERNEL_DATA = 28573696L;
                this.SIZE_KERNEL_DATA = 140712240L;
                this.OFFSET_KERNEL_DATA_BASE_DYNAMIC = 0L;
                this.OFFSET_KERNEL_DATA_BASE_TO_DYNAMIC = 106478424L;
                this.OFFSET_KERNEL_DATA_BASE_ALLPROC = 40705048L;
                this.OFFSET_KERNEL_DATA_BASE_SECURITY_FLAGS = 103026804L;
                this.OFFSET_KERNEL_DATA_BASE_ROOTVNODE = 106321216L;
                this.OFFSET_KERNEL_DATA_BASE_KERNEL_PMAP_STORE = 49935144L;
                this.OFFSET_KERNEL_DATA_BASE_DATA_CAVE = 99745792L;
                break;
            }
            case 512:
            case 544:
            case 549:
            case 550:
            case 560:
            case 592:
            case 624: {
                this.OFFSET_KERNEL_DATA = 28835840L;
                this.SIZE_KERNEL_DATA = 142481712L;
                this.OFFSET_KERNEL_DATA_BASE_DYNAMIC = 0L;
                this.OFFSET_KERNEL_DATA_BASE_TO_DYNAMIC = 108239752L;
                this.OFFSET_KERNEL_DATA_BASE_ALLPROC = 40901672L;
                this.OFFSET_KERNEL_DATA_BASE_SECURITY_FLAGS = 104731252L;
                this.OFFSET_KERNEL_DATA_BASE_ROOTVNODE = 108082368L;
                this.OFFSET_KERNEL_DATA_BASE_KERNEL_PMAP_STORE = 51591368L;
                this.OFFSET_KERNEL_DATA_BASE_DATA_CAVE = 101449728L;
                break;
            }
            case 768:
            case 800:
            case 801: {
                this.OFFSET_KERNEL_DATA = 12386304L;
                this.SIZE_KERNEL_DATA = 143071536L;
                this.OFFSET_KERNEL_DATA_BASE_DYNAMIC = 65536L;
                this.OFFSET_KERNEL_DATA_BASE_TO_DYNAMIC = 108862352L;
                this.OFFSET_KERNEL_DATA_BASE_ALLPROC = 41344088L;
                this.OFFSET_KERNEL_DATA_BASE_SECURITY_FLAGS = 105276532L;
                this.OFFSET_KERNEL_DATA_BASE_ROOTVNODE = 108704960L;
                this.OFFSET_KERNEL_DATA_BASE_KERNEL_PMAP_STORE = 52159000L;
                this.OFFSET_KERNEL_DATA_BASE_DATA_CAVE = 101974016L;
                break;
            }
            case 1024:
            case 1026:
            case 1027:
            case 1104:
            case 1105: {
                this.OFFSET_KERNEL_DATA = 12582912L;
                this.SIZE_KERNEL_DATA = 142285104L;
                this.OFFSET_KERNEL_DATA_BASE_DYNAMIC = 65536L;
                this.OFFSET_KERNEL_DATA_BASE_TO_DYNAMIC = 108059536L;
                this.OFFSET_KERNEL_DATA_BASE_ALLPROC = 41868472L;
                this.OFFSET_KERNEL_DATA_BASE_SECURITY_FLAGS = 105931892L;
                this.OFFSET_KERNEL_DATA_BASE_ROOTVNODE = 107902144L;
                this.OFFSET_KERNEL_DATA_BASE_KERNEL_PMAP_STORE = 52787832L;
                this.OFFSET_KERNEL_DATA_BASE_DATA_CAVE = 113250304L;
                break;
            }
            case 1280:
            case 1282:
            case 1296:
            case 1360: {
                this.OFFSET_KERNEL_DATA = 12910592L;
                this.SIZE_KERNEL_DATA = 143726896L;
                this.OFFSET_KERNEL_DATA_BASE_DYNAMIC = 0L;
                this.OFFSET_KERNEL_DATA_BASE_TO_DYNAMIC = 109485056L;
                this.OFFSET_KERNEL_DATA_BASE_ALLPROC = 43048192L;
                this.OFFSET_KERNEL_DATA_BASE_SECURITY_FLAGS = 107177708L;
                this.OFFSET_KERNEL_DATA_BASE_ROOTVNODE = 109327632L;
                this.OFFSET_KERNEL_DATA_BASE_KERNEL_PMAP_STORE = 54020744L;
                this.OFFSET_KERNEL_DATA_BASE_DATA_CAVE = 103874560L;
                break;
            }
            case 1536:
            case 1538:
            case 1616: {
                this.OFFSET_KERNEL_DATA = 10747904L;
                this.SIZE_KERNEL_DATA = 142940464L;
                this.OFFSET_KERNEL_DATA_BASE_DYNAMIC = 0L;
                this.OFFSET_KERNEL_DATA_BASE_TO_DYNAMIC = 108747792L;
                this.OFFSET_KERNEL_DATA_BASE_ALLPROC = 42310944L;
                this.OFFSET_KERNEL_DATA_BASE_SECURITY_FLAGS = 106457324L;
                this.OFFSET_KERNEL_DATA_BASE_ROOTVNODE = 108590352L;
                this.OFFSET_KERNEL_DATA_BASE_KERNEL_PMAP_STORE = 53298008L;
                this.OFFSET_KERNEL_DATA_BASE_DATA_CAVE = 103153664L;
                break;
            }
            case 1792:
            case 1793:
            case 1824:
            case 1856:
            case 1888:
            case 1889: {
                this.OFFSET_KERNEL_DATA = 10682368L;
                this.SIZE_KERNEL_DATA = 85465392L;
                this.OFFSET_KERNEL_DATA_BASE_DYNAMIC = 0L;
                this.OFFSET_KERNEL_DATA_BASE_TO_DYNAMIC = 51240000L;
                this.OFFSET_KERNEL_DATA_BASE_ALLPROC = 42245456L;
                this.OFFSET_KERNEL_DATA_BASE_SECURITY_FLAGS = 11239524L;
                this.OFFSET_KERNEL_DATA_BASE_ROOTVNODE = 51082512L;
                this.OFFSET_KERNEL_DATA_BASE_KERNEL_PMAP_STORE = 48351304L;
                this.OFFSET_KERNEL_DATA_BASE_DATA_CAVE = 84480000L;
                break;
            }
            default: {
                final String strSwVersion = MessageFormat.format("{0,number,#0}.{1,number,00}", new Object[] { new Integer(softwareVersion >> 8 & 0xFF), new Integer(softwareVersion & 0xFF) });
                throw new SdkSoftwareVersionUnsupportedException(strSwVersion);
            }
        }
        this.OFFSET_KERNEL_DATA_BASE_TARGET_ID = this.OFFSET_KERNEL_DATA_BASE_SECURITY_FLAGS + 9L;
        this.OFFSET_KERNEL_DATA_BASE_QA_FLAGS = this.OFFSET_KERNEL_DATA_BASE_SECURITY_FLAGS + 36L;
        this.OFFSET_KERNEL_DATA_BASE_UTOKEN_FLAGS = this.OFFSET_KERNEL_DATA_BASE_SECURITY_FLAGS + 140L;
    }
}
