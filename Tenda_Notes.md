**Notes to Tenda**



6.0 Firmware

- Strings

```
Xdecompressing kernel:
done decompressing kernel.
start address: 0x%08x
0123456789abcdefghijklmnopqrstuvwxyz
0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ
<NULL>
 -- System halted
Uncompressing...
LZMA: Too big uncompressed stream
LZMA: Incorrect stream properties
Malloc error
Memory error
Out of memory
LZMA: Decoding error = %d
 done, booting the kernel.
```

https://www.tendacn.com/product/specification/N301.html

https://portswigger.net/daily-swig/unpatched-tenda-wifi-router-vulnerabilities-leave-home-networks-wide-open-to-abuse

```
$ binwalk N301.bin 

DECIMAL    HEXADECIMAL   DESCRIPTION

10292     0x2834     LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 3039160 bytes
```

