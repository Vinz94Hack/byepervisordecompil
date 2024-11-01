package org.ps5jb.sdk.include.sys.bitset;

import org.ps5jb.sdk.core.Pointer;

public class BitSetType
{
    private static final int _BITSET_BITS = 64;
    private final Pointer ptr;
    private final long[] __bits;
    private final int __bitset_words;
    
    public BitSetType(final Pointer pointer, final int size) {
        this.ptr = pointer;
        this.__bitset_words = (size + 63) / 64;
        this.__bits = new long[this.__bitset_words];
        this.refresh();
    }
    
    private long __bitset_mask(final int n) {
        return 1L << ((this.__bitset_words == 1) ? n : (n % 64));
    }
    
    private int __bitset_word(final int n) {
        return (this.__bitset_words == 1) ? 0 : (n / 64);
    }
    
    private long __bitcountl(long _x) {
        _x = (_x & 0x5555555555555555L) + ((_x & 0xAAAAAAAAAAAAAAAAL) >> 1);
        _x = (_x & 0x3333333333333333L) + ((_x & 0xCCCCCCCCCCCCCCCCL) >> 2);
        _x = (_x + (_x >> 4) & 0xF0F0F0F0F0F0F0FL);
        _x += _x >> 8;
        _x += _x >> 16;
        _x = (_x + (_x >> 32) & 0xFFL);
        return _x;
    }
    
    public long getSize() {
        return this.__bitset_words * 8L;
    }
    
    public boolean isSet(final int bitIndex) {
        final long word = this.__bits[this.__bitset_word(bitIndex)];
        return (word & this.__bitset_mask(bitIndex)) != 0x0L;
    }
    
    public void set(final int bitIndex) {
        final int wordIndex = this.__bitset_word(bitIndex);
        final long[] _bits = this.__bits;
        final int n = wordIndex;
        _bits[n] |= this.__bitset_mask(bitIndex);
        this.ptr.write8(8L * wordIndex, this.__bits[wordIndex]);
    }
    
    public void unset(final int bitIndex) {
        final int wordIndex = this.__bitset_word(bitIndex);
        final long[] _bits = this.__bits;
        final int n = wordIndex;
        _bits[n] &= ~this.__bitset_mask(bitIndex);
        this.ptr.write8(8L * wordIndex, this.__bits[wordIndex]);
    }
    
    public void zero() {
        for (int i = 0; i < this.__bitset_words; ++i) {
            this.__bits[i] = 0L;
            this.ptr.write8(8L * i, this.__bits[i]);
        }
    }
    
    public int getCount() {
        long count = 0L;
        for (int i = 0; i < this.__bitset_words; ++i) {
            count += this.__bitcountl(this.__bits[i]);
        }
        return (int)count;
    }
    
    public Pointer getPointer() {
        return this.ptr;
    }
    
    public void refresh() {
        for (int i = 0; i < this.__bitset_words; ++i) {
            this.__bits[i] = this.ptr.read8(i * 8L);
        }
    }
    
    @Override
    public String toString() {
        final StringBuffer sb = new StringBuffer();
        boolean hasNonZero = false;
        for (int i = this.__bitset_words - 1; i >= 0; --i) {
            if (this.__bits[i] != 0L) {
                hasNonZero = true;
            }
            if (this.__bits[i] != 0L || hasNonZero) {
                final String binString = Long.toBinaryString(this.__bits[i]);
                if (!hasNonZero) {
                    for (int j = binString.length(); j < 64; ++j) {
                        sb.append("0");
                    }
                }
                sb.append(binString);
            }
        }
        return sb.toString();
    }
}
