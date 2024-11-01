package org.ps5jb.client.payloads.umtx.common;

import java.util.Iterator;
import org.ps5jb.sdk.core.kernel.KernelPointer;
import org.ps5jb.sdk.core.Pointer;
import java.util.TreeMap;
import java.util.Map;

public class KernelAddressClassifier
{
    Map counts;
    
    public KernelAddressClassifier() {
        this.counts = (Map)new TreeMap();
    }
    
    public static KernelAddressClassifier fromBuffer(final Pointer buffer) {
        if (buffer.size() == null) {
            throw new IllegalArgumentException("Buffer must have a defined size for kernel address scanning");
        }
        final KernelAddressClassifier result = new KernelAddressClassifier();
        for (long i = 0L; i + 8L <= buffer.size(); i += 8L) {
            final KernelPointer kptr = new KernelPointer(buffer.read8(i));
            try {
                KernelPointer.validRange(kptr);
                final Long val = new Long(kptr.addr());
                Integer curCount = (Integer)result.counts.get((Object)val);
                if (curCount == null) {
                    curCount = new Integer(0);
                }
                else {
                    curCount = new Integer(curCount + 1);
                }
                result.counts.put((Object)val, (Object)curCount);
            }
            catch (final IllegalAccessError illegalAccessError) {}
        }
        return result;
    }
    
    public Long getMostOccuredHeapAddress(final int threshold) {
        Long result = null;
        final int maxCount = 0;
        for (final Map.Entry count : this.counts.entrySet()) {
            final int countVal = (int)count.getValue();
            if (countVal > maxCount && countVal >= threshold) {
                result = (Long)count.getKey();
            }
        }
        return result;
    }
}
