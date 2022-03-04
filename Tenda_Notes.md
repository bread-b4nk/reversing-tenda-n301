# Reversing Tenda N301

## OSINT

- The [Tenda N301 Spec](https://www.tendacn.com/product/specification/N301.html)
- The [download page for the firmware](https://www.tendacn.com/us/download/detail-3977.html)
- https://portswigger.net/daily-swig/unpatched-tenda-wifi-router-vulnerabilities-leave-home-networks-wide-open-to-abuse
- Network Processor Datasheet: RTL8196E-CG http://www.hytic.net/upload/files/2015/09/REALTEK-RTL8196E.pdf
- https://reverseengineering.stackexchange.com/questions/15088/lzma-file-format-not-recognized-details-enclosed
- https://github.com/w3slee/Tenda-Firmware-Reversing (decompressed Tenda firmware can be found @ decompressed/tenda.bin

## Hardware
- Network Processor: RTL8196E-CG
- WLan Chip:
- SD Ram: W9864G6KH-6
- ???: letters on chip: H25S80 BG 20k0 AP2N113

## Firmware

- looking at the latest version (6.0), downloaded from https://www.tendacn.com/us/download/detail-3977.html

### Static Analysis

- Calling `strings` gives

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

- Calling `binwalk -eMd3` gave us a file system, the output of that is in `binwalk.out`, and it produced `_2834.extracted`

```
$ binwalk -emd3 N301.bin > binwalk.out

DECIMAL    HEXADECIMAL   DESCRIPTION

10292     0x2834     LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 3039160 bytes

```

- Trying to find what architecture:

```bash
kris@bread-bank:~/Projects/reversing-tenda-n301$ cat binwalk.out | grep arch
0             0x0             eCos kernel exception handler, architecture: MIPS, exception vector table base address: 0x80000200
128           0x80            eCos kernel exception handler, architecture: MIPS, exception vector table base address: 0x80000200

kris@bread-bank:~/Projects/reversing-tenda-n301$ binwalk --disasm tenda/US_N301V6.0re_V12.02.01.61_multi_TDE01.bin 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
12            0xC             MIPS executable code, 32/64-bit, big endian, at least 1250 valid instructions
```



- Binwalk -- examining for encryption

```bash
$ binwalk -E N301.bin

DECIMAL       HEXADECIMAL     ENTROPY
--------------------------------------------------------------------------------
0             0x0             Falling entropy edge (0.613818)
10240         0x2800          Rising entropy edge (0.957594)
952320        0xE8800         Falling entropy edge (0.002793)
```

```bash
binwalk -eMd3 N301.bin 


```

Looking at `tenda.bin`
