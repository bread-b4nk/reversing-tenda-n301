# Final Project Writeup - CS69

## Team Members

Our group was composed of Lucas Wilbur, Kris (Chavin) Udomwongsa, and Tian Xia.

## Process

### Step 1: Physical Analysis

To begin our reverse engineering, we opened the Tenda n301 router and examined contents inside.  <Insert picture Kris made here labeling different parts>.  For each chip or other internal component, we closely inspected it to find any visible writing or information.  Then, we turned to research on the internet to gain a more complete picture of what the role of each chip was.

| Hardware Object Purpose |          Serial # / Other Writing           |
| :---------------------: | :-----------------------------------------: |
|    Network Processor    |                 RTL8196E-CG                 |
|         SD Ram          |                 W9864G6KH-6                 |
|        WLan Chip        | **<insert; we have this somewhere right?>** |
|        *unknown*        |           H25S80 BG 20k0 AP2N113            |

### Step 2: OSINT

The first step of intelligence gathering, as shown in the table above, was identifying the various chips and other hardware used to run the n301 and determining their purpose.

Once this had been completed, we continued to gather whatever information we could.  For general, basic information about the n301, we could refer to its [specs on the Tenda website](https://www.tendacn.com/product/specification/N301.html).  We found a public release of the router's [most recent firmware update](https://www.tendacn.com/us/download/detail-3977.html) on the website as well, which would come in handy for later static analysis.

Perhaps most importantly, we found the [official datasheet for the RTL8196E-CG network processor](http://www.hytic.net/upload/files/2015/09/REALTEK-RTL8196E.pdf) used by the router.  Included in that datasheet was such vital information as:

```
"The RTL8196E supports one flash memory chip ( SF_CS0#). The interface supports SPI flash memory. When Flash is used, the system will boot from KSEG1 at virtual address 0xBFC0_0000 (physical address: 0x1FC0_0000)."
```

It also listed the architecture of the chip as being MIPS, which was an important step for later static analysis.  However, with the many different varieties of MIPS in existance, further exploration was required.

### Step 3: Static Analysis

As a classic first step, we naturally called `strings` on the firmware update that we downloaded.  Among the large amount of useless output was the text:

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



