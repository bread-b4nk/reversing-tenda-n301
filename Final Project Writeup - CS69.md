# Final Project Writeup - CS69

## Team Members

Our group was composed of Lucas Wilbur, Kris (Chavin) Udomwongsa, and Tian Xia.

## Process

### Step 1: Physical Analysis

To begin our reverse engineering, we opened the Tenda n301 router and examined contents inside.  For each chip or other internal component, we closely inspected it to find any visible writing or information.  Then, we turned to research on the internet to gain a more complete picture of what the role of each chip was.

| Hardware Object Purpose | Serial # / Other Writing |
| :---------------------: | :----------------------: |
|    Network Processor    |       RTL8196E-CG        |
|         SD Ram          |       W9864G6KH-6        |
|        WLan Chip        |                          |
|        *unknown*        |  H25S80 BG 20k0 AP2N113  |

![router-inside](tenda-inside.jpg)

### Step 2: OSINT

The first step of intelligence gathering, as shown in the table above, was identifying the various chips and other hardware used to run the n301 and determining their purpose.

Once this had been completed, we continued to gather whatever information we could.  For general, basic information about the n301, we could refer to its [specs on the Tenda website](https://www.tendacn.com/product/specification/N301.html).  We found a public release of the router's [most recent firmware update](https://www.tendacn.com/us/download/detail-3977.html) on the website as well, which would come in handy for later static analysis.

Perhaps most importantly, we found the [official datasheet for the RTL8196E-CG network processor](http://www.hytic.net/upload/files/2015/09/REALTEK-RTL8196E.pdf) used by the router.  Included in that datasheet was such vital information as:

```
"The RTL8196E supports one flash memory chip ( SF_CS0#). The interface supports SPI flash memory. When Flash is used, the system will boot from KSEG1 at virtual address 0xBFC0_0000 (physical address: 0x1FC0_0000)."
```

It also listed the architecture of the chip as being MIPS, which was an important step for later static analysis.  However, with the many different varieties of MIPS in existance, further exploration was required.

### Step 3: Static Binwalk Firmware Analysis

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

Continuing our analysis, we turned to using `binwalk` on the firmware.

```
$ binwalk -emd3 N301.bin > binwalk.out

DECIMAL    HEXADECIMAL   DESCRIPTION

10292     0x2834     LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 3039160 bytes
```

Our first attempt yielded only compressed data, instead of a functional filesystem.  However, examining that data further continued to give results.

```
$ cat binwalk.out | grep arch
0             0x0             eCos kernel exception handler, architecture: MIPS, exception vector table base address: 0x80000200
128           0x80            eCos kernel exception handler, architecture: MIPS, exception vector table base address: 0x80000200

$ binwalk --disasm tenda/US_N301V6.0re_V12.02.01.61_multi_TDE01.bin 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
12            0xC             MIPS executable code, 32/64-bit, big endian, at least 1250 valid instructions
```

Thus, we determined the exact identity of the architecture used for this device: 32/64 bit big-endian MIPS.

To verify that this document is compressed, and not under some form of encyption, we performed entropy analysis on the firmware using `binwalk -E`

```
$ binwalk -E N301.bin

DECIMAL       HEXADECIMAL     ENTROPY
--------------------------------------------------------------------------------
0             0x0             Falling entropy edge (0.613818)
10240         0x2800          Rising entropy edge (0.957594)
952320        0xE8800         Falling entropy edge (0.002793)
```

![entropy-analysis-results](tenda-entropy.png)

This entropy graph is consistent with whole-file compression, thus all-but-confirming that it is indeed compressed, not encrypted.

We load the file with `dd` which gives us a compressed `lzma` file. 

```bash
dd if=US_N301V6.0re_V12.02.01.61_multi_TDE01.bin of=firmware.bin.lzma ibs=1 skip=10292 count=8388608
```

Interestingly `lzma -d firmware.bin.lzma` on various distributions of `Linux` and also `Solaris` all return a `corrupt` data error. After more trials and errors, we found out that if we decompressed the `firmware.bin.lzma` on Windows, a correct version of `firmware.bin` could be produced. Here are the results:

```
(base) txia23@pop-os:~/Desktop/dart21w/cs69/reversing-tenda-n301/compressed$ binwalk firmware.bin

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             eCos kernel exception handler, architecture: MIPS, exception vector table base address: 0x80000200
128           0x80            eCos kernel exception handler, architecture: MIPS, exception vector table base address: 0x80000200
141391        0x2284F         GPG key trust database version 93
209216        0x33140         SHA256 hash constants, big endian
1559900       0x17CD5C        eCos RTOS string reference: "eCos Release: %d.%d.%d"
1587628       0x1839AC        Unix path: /dev/net/dhcpc
1588564       0x183D54        Unix path: /dev/net/dhcpd
1590488       0x1844D8        Unix path: /dev/net/ipl
1602084       0x187224        eCos RTOS string reference: "ecos_name"
1602096       0x187230        eCos RTOS string reference: "ecos"
1617632       0x18AEE0        XML document, version: "1.0"
1618248       0x18B148        eCos RTOS string reference: "ECOS"
1620680       0x18BAC8        XML document, version: "1.0"
1621448       0x18BDC8        XML document, version: "1.0"
1627584       0x18D5C0        XML document, version: "1.0"
1629852       0x18DE9C        Unix path: /dev/net/ppp/ppp%d
1632844       0x18EA4C        Unix path: /dev/net/pppoe/%s
1640111       0x1906AF        HTML document footer
1640884       0x1909B4        HTML document footer
1640992       0x190A20        HTML document header
1641816       0x190D58        HTML document header
1641935       0x190DCF        HTML document footer
1641960       0x190DE8        eCos RTOS string reference: "ecos_pw=%s:language=%s; path=/"
1642060       0x190E4C        HTML document header
1642238       0x190EFE        HTML document footer
1644376       0x191758        eCos RTOS string reference: "ecos_cgi/cgi_devManage.c"
1647120       0x192210        eCos RTOS string reference: "ecos_pw="
1664912       0x196790        Base64 standard index table
1671240       0x198048        SHA256 hash constants, big endian
1682532       0x19AC64        Base64 standard index table
1683324       0x19AF7C        CRC32 polynomial table, big endian
1687512       0x19BFD8        Unix path: /home/work/workspace/ECOSV2.0_TRUNK/ecos-work/../ecos-3.0/packages/devs/eth/rltk/819x_1_5_3/switch/v3_0/src/swNic_poll.c
1687533       0x19BFED        eCos RTOS string reference: "ECOSV2.0_TRUNK/ecos-work/../ecos-3.0/packages/devs/eth/rltk/819x_1_5_3/switch/v3_0/src/swNic_poll.c"
1687548       0x19BFFC        eCos RTOS string reference: "ecos-work/../ecos-3.0/packages/devs/eth/rltk/819x_1_5_3/switch/v3_0/src/swNic_poll.c"
1687561       0x19C009        eCos RTOS string reference: "ecos-3.0/packages/devs/eth/rltk/819x_1_5_3/switch/v3_0/src/swNic_poll.c"
1689432       0x19C758        Unix path: /home/work/workspace/ECOSV2.0_TRUNK/ecos-work/../ecos-3.0/packages/devs/eth/rltk/819x_1_5_3/switch/v3_0/src/swTable.c
1689453       0x19C76D        eCos RTOS string reference: "ECOSV2.0_TRUNK/ecos-work/../ecos-3.0/packages/devs/eth/rltk/819x_1_5_3/switch/v3_0/src/swTable.c"
1689468       0x19C77C        eCos RTOS string reference: "ecos-work/../ecos-3.0/packages/devs/eth/rltk/819x_1_5_3/switch/v3_0/src/swTable.c"
1689481       0x19C789        eCos RTOS string reference: "ecos-3.0/packages/devs/eth/rltk/819x_1_5_3/switch/v3_0/src/swTable.c"
1690420       0x19CB34        Unix path: /home/work/workspace/ECOSV2.0_TRUNK/ecos-work/../ecos-3.0/packages/devs/eth/rltk/819x_1_5_3/switch/v3_0/src/vlanTable.c
1690441       0x19CB49        eCos RTOS string reference: "ECOSV2.0_TRUNK/ecos-work/../ecos-3.0/packages/devs/eth/rltk/819x_1_5_3/switch/v3_0/src/vlanTable.c"
1690456       0x19CB58        eCos RTOS string reference: "ecos-work/../ecos-3.0/packages/devs/eth/rltk/819x_1_5_3/switch/v3_0/src/vlanTable.c"
1690469       0x19CB65        eCos RTOS string reference: "ecos-3.0/packages/devs/eth/rltk/819x_1_5_3/switch/v3_0/src/vlanTable.c"
1690593       0x19CBE1        eCos RTOS string reference: "ECOSV2.0_TRUNK/ecos-work/../ecos-3.0/packages/devs/eth/rltk/819x_1_5_3/switch/v3_0/src/rtl865x_igmpsnooping_new.c"
1690608       0x19CBF0        eCos RTOS string reference: "ecos-work/../ecos-3.0/packages/devs/eth/rltk/819x_1_5_3/switch/v3_0/src/rtl865x_igmpsnooping_new.c"
1690621       0x19CBFD        eCos RTOS string reference: "ecos-3.0/packages/devs/eth/rltk/819x_1_5_3/switch/v3_0/src/rtl865x_igmpsnooping_new.c"
1695754       0x19E00A        Neighborly text, "neighbor channel_load: %2u, rssi %4u, busy %4u"
1751832       0x1ABB18        SHA256 hash constants, big endian
1765850       0x1AF1DA        XML document, version: "1.0"
1766028       0x1AF28C        HTML document header
1766093       0x1AF2CD        HTML document footer
1766264       0x1AF378        Base64 standard index table
1766542       0x1AF48E        HTML document header
1766667       0x1AF50B        HTML document footer
1766948       0x1AF624        HTML document header
1767088       0x1AF6B0        HTML document footer
1767100       0x1AF6BC        HTML document header
1767130       0x1AF6DA        HTML document footer
1767584       0x1AF8A0        XML document, version: "1.0"
1773864       0x1B1128        eCos RTOS string reference: "eCos_node"
1781828       0x1B3044        Unix path: /var/log/alias.log
1804568       0x1B8918        XML document, version: "1.0"
1815096       0x1BB238        XML document, version: "1.0"
1818136       0x1BBE18        XML document, version: "1.0"
1819108       0x1BC1E4        XML document, version: "1.0"
1825100       0x1BD94C        XML document, version: "1.0"
2034132       0x1F09D4        HTML document header
2034138       0x1F09DA        HTML document footer
2034766       0x1F0C4E        HTML document header
2034772       0x1F0C54        HTML document footer
2095182       0x1FF84E        Base64 standard index table
2105900       0x20222C        Copyright string: "Copyright 2014 ET.W"
2109313       0x202F81        Copyright string: "Copyright 2013 reasy Foundation and other contributors"
2112281       0x203B19        Copyright string: "Copyright 2013 reasy Foundation and other contributors"
2116233       0x204A89        Copyright string: "Copyright 2013 reasy Foundation and other contributors"
2122745       0x2063F9        Copyright string: "Copyright 2013 reasy Foundation and other contributors"
2123532       0x20670C        Copyright string: "Copyright 2013 reasy Foundation and other contributors"
2260398       0x227DAE        eCos RTOS string reference: "ECOS\\dist\\wifi\\advanced.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\advanced"
2261745       0x2282F1        eCos RTOS string reference: "ECOS\\dist\\wifi\\index.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\index.html "
2264305       0x228CF1        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\advanced.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\ad"
2266735       0x22966F        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\index.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\index"
2266836       0x2296D4        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\index.js  ----------------------*/","unknown":"ismeretlen","Unknown error":"Ismeretlen hiba","JSON is to"
2269303       0x22A077        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\ajaxupload.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi"
2269415       0x22A0E7        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\ajaxupload.js  ----------------------*/","/*----------------------  D:\\Project\\ECOS\\dist\\wifi"
2269527       0x22A157        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\common.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js"
2269635       0x22A1C3        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\common.js  ----------------------*/","Samsung":"Samsung","Apple":"Apple","Huawei":"Huawei","XiaoMi"
2273932       0x22B28C        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\j.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\lib"
2274035       0x22B2F3        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\j.js  ----------------------*/","REasy":"REasy","/*----------------------  D:\\Project\\ECOS\\dis"
2274154       0x22B36A        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\j_ajaxError.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wif"
2274267       0x22B3DB        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\j_ajaxError.js  ----------------------*/","/*----------------------  D:\\Project\\ECOS\\dist\\wif"
2274380       0x22B44C        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\reasy-ui-1.0.3.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\"
2276360       0x22BC08        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\net-control.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\"
2276467       0x22BC73        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\net-control.js  ----------------------*/","A maximum of %s devices can be added to the blacklist.":"Legf"
2277291       0x22BFAB        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\network.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\net"
2277394       0x22C012        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\network.js  ----------------------*/","When the AP mode is disabled, the router reboots. Do you want to "
2280337       0x22CB91        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\quickset.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\qu"
2280441       0x22CBF9        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\quickset.js  ----------------------*/","Synchronization success. The current page is refreshed when you "
2281484       0x22D00C        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\status.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\stat"
2281767       0x22D127        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\system.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\syst"
2283992       0x22D9D8        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\userManage.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\"
2284098       0x22DA42        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\userManage.js  ----------------------*/","/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\"
2284204       0x22DAAC        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\wireless.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\wi"
2284308       0x22DB14        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\wireless.js  ----------------------*/","The wireless connection will be released. Please connect again.""
2284842       0x22DD2A        eCos RTOS string reference: "ECOS\\dist\\wifi\\login.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\login.html "
2285795       0x22E0E3        eCos RTOS string reference: "ECOS\\dist\\wifi\\net-control.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\net-c"
2286322       0x22E2F2        eCos RTOS string reference: "ECOS\\dist\\wifi\\network.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\network.h"
2288734       0x22EC5E        eCos RTOS string reference: "ECOS\\dist\\wifi\\quickset.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\quickset"
2291892       0x22F8B4        eCos RTOS string reference: "ECOS\\dist\\wifi\\status.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\status.htm"
2292480       0x22FB00        eCos RTOS string reference: "ECOS\\dist\\wifi\\system.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\system.htm"
2299679       0x23171F        eCos RTOS string reference: "ECOS\\dist\\wifi\\userManage.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\userMa"
2299961       0x231839        eCos RTOS string reference: "ECOS\\dist\\wifi\\wechart.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\wechart.h"
2300062       0x23189E        eCos RTOS string reference: "ECOS\\dist\\wifi\\wechart.html  ----------------------*/","Tenda wechart":"Tenda wechart","/*----------------------  D:\\Proj"
2300195       0x231923        eCos RTOS string reference: "ECOS\\dist\\wifi\\wireless.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\wireless"
2304258       0x232902        eCos RTOS string reference: "ECOS\\dist\\wifi\\advanced.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\advanced"
2304360       0x232968        eCos RTOS string reference: "ECOS\\dist\\wifi\\advanced.html  ----------------------*/","MAC Address Filter":"MAC-Adressen-Filter","Filter Mode":"Filtermod"
2305543       0x232E07        eCos RTOS string reference: "ECOS\\dist\\wifi\\index.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\index.html "
2305642       0x232E6A        eCos RTOS string reference: "ECOS\\dist\\wifi\\index.html  ----------------------*/","Tenda Wireless Router":"Tenda Wireless Router","Tenda":"Tenda","Tenda"
2308023       0x2337B7        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\advanced.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\ad"
2308127       0x23381F        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\advanced.js  ----------------------*/","Blacklisted MAC Address":"MAC-Adressen auf der Blacklist","White"
2310440       0x234128        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\index.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\index"
2310541       0x23418D        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\index.js  ----------------------*/","unknown":"Unbekannt","Unknown error":"Unbekannter Fehler","JSON is "
2313174       0x234BD6        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\ajaxupload.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi"
2313286       0x234C46        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\ajaxupload.js  ----------------------*/","/*----------------------  D:\\Project\\ECOS\\dist\\wifi"
2313398       0x234CB6        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\common.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js"
2313506       0x234D22        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\common.js  ----------------------*/","Samsung":"Samsung","Apple":"Apple","Huawei":"Huawei","XiaoMi"
2317871       0x235E2F        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\j.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\lib"
2317974       0x235E96        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\j.js  ----------------------*/","REasy":"REasy","/*----------------------  D:\\Project\\ECOS\\dis"
2318093       0x235F0D        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\j_ajaxError.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wif"
2318206       0x235F7E        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\j_ajaxError.js  ----------------------*/","/*----------------------  D:\\Project\\ECOS\\dist\\wif"
2318319       0x235FEF        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\reasy-ui-1.0.3.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\"
2320311       0x2367B7        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\net-control.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\"
2320418       0x236822        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\net-control.js  ----------------------*/","A maximum of %s devices can be added to the blacklist.":"Es k"
2321242       0x236B5A        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\network.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\net"
2321345       0x236BC1        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\network.js  ----------------------*/","When the AP mode is disabled, the router reboots. Do you want to "
2324265       0x237729        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\quickset.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\qu"
2324369       0x237791        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\quickset.js  ----------------------*/","Synchronization success. The current page is refreshed when you "
2325340       0x237B5C        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\status.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\stat"
2325442       0x237BC2        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\status.js  ----------------------*/","Internet":"Internet","WiFi":"WLAN","Upstream Router":"Upstream-Rou"
2325616       0x237C70        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\system.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\syst"
2325718       0x237CD6        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\system.js  ----------------------*/","The login IP will be changed into %s.":"Die Login-IP wird in %s ge"
2327841       0x238521        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\userManage.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\"
2327947       0x23858B        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\userManage.js  ----------------------*/","/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\"
2328053       0x2385F5        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\wireless.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\wi"
2328157       0x23865D        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\wireless.js  ----------------------*/","The wireless connection will be released. Please connect again.""
2328692       0x238874        eCos RTOS string reference: "ECOS\\dist\\wifi\\login.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\login.html "
2328791       0x2388D7        eCos RTOS string reference: "ECOS\\dist\\wifi\\login.html  ----------------------*/","Tenda | LOGIN":"Tenda | LOGIN","Language":"Sprache","Password":"Passw"
2329657       0x238C39        eCos RTOS string reference: "ECOS\\dist\\wifi\\net-control.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\net-c"
2330163       0x238E33        eCos RTOS string reference: "ECOS\\dist\\wifi\\network.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\network.h"
2330264       0x238E98        eCos RTOS string reference: "ECOS\\dist\\wifi\\network.html  ----------------------*/","Operating Mode":"Betriebsmodus","Router":"Router","WISP":"WISP","Un"
2332420       0x239704        eCos RTOS string reference: "ECOS\\dist\\wifi\\quickset.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\quickset"
2332522       0x23976A        eCos RTOS string reference: "ECOS\\dist\\wifi\\quickset.html  ----------------------*/","Tenda Wizard":"Tenda-Assistent","You can access the internet after"
2335578       0x23A35A        eCos RTOS string reference: "ECOS\\dist\\wifi\\status.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\status.htm"
2335678       0x23A3BE        eCos RTOS string reference: "ECOS\\dist\\wifi\\status.html  ----------------------*/","Internet Connection Status":"Internetverbindungsstatus","My Router":"
2336146       0x23A592        eCos RTOS string reference: "ECOS\\dist\\wifi\\system.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\system.htm"
2336246       0x23A5F6        eCos RTOS string reference: "ECOS\\dist\\wifi\\system.html  ----------------------*/","Old Password":"Altes Passwort","New Password":"Neues Passwort","WAN "
2343059       0x23C093        eCos RTOS string reference: "ECOS\\dist\\wifi\\userManage.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\userMa"
2343163       0x23C0FB        eCos RTOS string reference: "ECOS\\dist\\wifi\\userManage.html  ----------------------*/","Connection":"Verbindung","Add to Blacklist":"Zur Schwarzliste hi"
2343343       0x23C1AF        eCos RTOS string reference: "ECOS\\dist\\wifi\\wechart.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\wechart.h"
2343444       0x23C214        eCos RTOS string reference: "ECOS\\dist\\wifi\\wechart.html  ----------------------*/","Tenda wechart":"Tenda Wechart","/*----------------------  D:\\Proj"
2343577       0x23C299        eCos RTOS string reference: "ECOS\\dist\\wifi\\wireless.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\wireless"
2343679       0x23C2FF        eCos RTOS string reference: "ECOS\\dist\\wifi\\wireless.html  ----------------------*/","WiFi On/Off":"WLAN An/Aus","WiFi Name and Password":"WLAN-Name und"
2347506       0x23D1F2        eCos RTOS string reference: "ECOS\\dist\\wifi\\advanced.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\advanced"
2347608       0x23D258        eCos RTOS string reference: "ECOS\\dist\\wifi\\advanced.html  ----------------------*/","MAC Address Filter":"Filtro de direcciones MAC","Filter Mode":"Mod"
2348863       0x23D73F        eCos RTOS string reference: "ECOS\\dist\\wifi\\index.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\index.html "
2351337       0x23E0E9        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\advanced.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\ad"
2351441       0x23E151        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\advanced.js  ----------------------*/","Blacklisted MAC Address":"Direcciones MAC bloqueadas","Whitelist"
2353753       0x23EA59        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\index.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\index"
2353854       0x23EABE        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\index.js  ----------------------*/","unknown":"desconocido","Unknown error":"Error desconocido","JSON is"
2356364       0x23F48C        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\ajaxupload.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi"
2356476       0x23F4FC        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\ajaxupload.js  ----------------------*/","/*----------------------  D:\\Project\\ECOS\\dist\\wifi"
2356588       0x23F56C        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\common.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js"
2356696       0x23F5D8        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\common.js  ----------------------*/","Samsung":"Samsung","Apple":"Apple","Huawei":"Huawei","XiaoMi"
2361115       0x24071B        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\j.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\lib"
2361218       0x240782        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\j.js  ----------------------*/","REasy":"REasy","/*----------------------  D:\\Project\\ECOS\\dis"
2361337       0x2407F9        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\j_ajaxError.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wif"
2361450       0x24086A        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\j_ajaxError.js  ----------------------*/","/*----------------------  D:\\Project\\ECOS\\dist\\wif"
2361563       0x2408DB        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\reasy-ui-1.0.3.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\"
2361679       0x24094F        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\reasy-ui-1.0.3.js  ----------------------*/","Capital characters are entered.":"Se han introducido"
2363530       0x24108A        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\net-control.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\"
2363637       0x2410F5        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\net-control.js  ----------------------*/","A maximum of %s devices can be added to the blacklist.":"Se p"
2364439       0x241417        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\network.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\net"
2364542       0x24147E        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\network.js  ----------------------*/","When the AP mode is disabled, the router reboots. Do you want to "
2367509       0x242015        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\quickset.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\qu"
2367613       0x24207D        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\quickset.js  ----------------------*/","Synchronization success. The current page is refreshed when you "
2368613       0x242465        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\status.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\stat"
2368715       0x2424CB        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\status.js  ----------------------*/","Internet":"Internet","WiFi":"WiFi","Upstream Router":"Enrutador de"
2368893       0x24257D        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\system.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\syst"
2371180       0x242E6C        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\userManage.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\"
2371286       0x242ED6        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\userManage.js  ----------------------*/","/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\"
2371392       0x242F40        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\wireless.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\wi"
2371496       0x242FA8        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\wireless.js  ----------------------*/","The wireless connection will be released. Please connect again.""
2372032       0x2431C0        eCos RTOS string reference: "ECOS\\dist\\wifi\\login.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\login.html "
2372131       0x243223        eCos RTOS string reference: "ECOS\\dist\\wifi\\login.html  ----------------------*/","Tenda | LOGIN":"Tenda | INGRESAR","Language":"Idioma","Password":"Con"
2373046       0x2435B6        eCos RTOS string reference: "ECOS\\dist\\wifi\\net-control.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\net-c"
2373572       0x2437C4        eCos RTOS string reference: "ECOS\\dist\\wifi\\network.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\network.h"
2373673       0x243829        eCos RTOS string reference: "ECOS\\dist\\wifi\\network.html  ----------------------*/","Operating Mode":"Modo de funcionamiento","Router":"Enrutador","WISP"
2375817       0x244089        eCos RTOS string reference: "ECOS\\dist\\wifi\\quickset.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\quickset"
2375919       0x2440EF        eCos RTOS string reference: "ECOS\\dist\\wifi\\quickset.html  ----------------------*/","Tenda Wizard":"Asistente de Tenda","You can access the internet af"
2378903       0x244C97        eCos RTOS string reference: "ECOS\\dist\\wifi\\status.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\status.htm"
2379528       0x244F08        eCos RTOS string reference: "ECOS\\dist\\wifi\\system.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\system.htm"
2386737       0x246B31        eCos RTOS string reference: "ECOS\\dist\\wifi\\userManage.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\userMa"
2386841       0x246B99        eCos RTOS string reference: "ECOS\\dist\\wifi\\userManage.html  ----------------------*/","Connection":"Conexiones","Add to Blacklist":"Agregar a la lista "
2387017       0x246C49        eCos RTOS string reference: "ECOS\\dist\\wifi\\wechart.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\wechart.h"
2387118       0x246CAE        eCos RTOS string reference: "ECOS\\dist\\wifi\\wechart.html  ----------------------*/","Tenda wechart":"Tenda wechart","/*----------------------  D:\\Proj"
2387251       0x246D33        eCos RTOS string reference: "ECOS\\dist\\wifi\\wireless.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\wireless"
2387353       0x246D99        eCos RTOS string reference: "ECOS\\dist\\wifi\\wireless.html  ----------------------*/","WiFi On/Off":"Activar/desactivar WiFi","WiFi Name and Password":"N"
2391266       0x247CE2        eCos RTOS string reference: "ECOS\\dist\\wifi\\advanced.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\advanced"
2392577       0x248201        eCos RTOS string reference: "ECOS\\dist\\wifi\\index.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\index.html "
2392676       0x248264        eCos RTOS string reference: "ECOS\\dist\\wifi\\index.html  ----------------------*/","Tenda Wireless Router":"Router Wireless Tenda","Tenda":"Tenda","Tenda"
2394939       0x248B3B        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\advanced.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\ad"
2395043       0x248BA3        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\advanced.js  ----------------------*/","Blacklisted MAC Address":"Indirizzi MAC sulla Blacklist","Whitel"
2397312       0x249480        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\index.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\index"
2397413       0x2494E5        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\index.js  ----------------------*/","unknown":"Sconosciuto","Unknown error":"Errore sconosciuto","JSON i"
2399865       0x249E79        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\ajaxupload.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi"
2399977       0x249EE9        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\ajaxupload.js  ----------------------*/","/*----------------------  D:\\Project\\ECOS\\dist\\wifi"
2400089       0x249F59        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\common.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js"
2400197       0x249FC5        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\common.js  ----------------------*/","Samsung":"Samsung","Apple":"Apple","Huawei":"Huawei","XiaoMi"
2404243       0x24AF93        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\j.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\lib"
2404346       0x24AFFA        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\j.js  ----------------------*/","REasy":"REasy","/*----------------------  D:\\Project\\ECOS\\dis"
2404465       0x24B071        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\j_ajaxError.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wif"
2404578       0x24B0E2        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\j_ajaxError.js  ----------------------*/","/*----------------------  D:\\Project\\ECOS\\dist\\wif"
2404691       0x24B153        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\reasy-ui-1.0.3.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\"
2404807       0x24B1C7        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\reasy-ui-1.0.3.js  ----------------------*/","Capital characters are entered.":"Sono inseriti cara"
2406583       0x24B8B7        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\net-control.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\"
2407479       0x24BC37        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\network.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\net"
2407582       0x24BC9E        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\network.js  ----------------------*/","When the AP mode is disabled, the router reboots. Do you want to "
2410447       0x24C7CF        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\quickset.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\qu"
2410551       0x24C837        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\quickset.js  ----------------------*/","Synchronization success. The current page is refreshed when you "
2411523       0x24CC03        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\status.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\stat"
2411625       0x24CC69        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\status.js  ----------------------*/","Internet":"Internet","WiFi":"WiFi","Upstream Router":"Router a mon"
2411798       0x24CD16        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\system.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\syst"
2414043       0x24D5DB        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\userManage.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\"
2414149       0x24D645        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\userManage.js  ----------------------*/","/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\"
2414255       0x24D6AF        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\wireless.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\wi"
2414359       0x24D717        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\wireless.js  ----------------------*/","The wireless connection will be released. Please connect again.""
2414890       0x24D92A        eCos RTOS string reference: "ECOS\\dist\\wifi\\login.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\login.html "
2414989       0x24D98D        eCos RTOS string reference: "ECOS\\dist\\wifi\\login.html  ----------------------*/","Tenda | LOGIN":"Tenda | LOGIN","Language":"Lingua","Password":"Passwo"
2415797       0x24DCB5        eCos RTOS string reference: "ECOS\\dist\\wifi\\net-control.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\net-c"
2415902       0x24DD1E        eCos RTOS string reference: "ECOS\\dist\\wifi\\net-control.html  ----------------------*/","Online Devices":"Dispositivi online","Device Name":"Nome del di"
2416326       0x24DEC6        eCos RTOS string reference: "ECOS\\dist\\wifi\\network.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\network.h"
2418548       0x24E774        eCos RTOS string reference: "ECOS\\dist\\wifi\\quickset.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\quickset"
2418650       0x24E7DA        eCos RTOS string reference: "ECOS\\dist\\wifi\\quickset.html  ----------------------*/","Tenda Wizard":"Tenda Wizard","You can access the internet after co"
2421509       0x24F305        eCos RTOS string reference: "ECOS\\dist\\wifi\\status.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\status.htm"
2421609       0x24F369        eCos RTOS string reference: "ECOS\\dist\\wifi\\status.html  ----------------------*/","Internet Connection Status":"Stato connessione internet","My Router""
2422109       0x24F55D        eCos RTOS string reference: "ECOS\\dist\\wifi\\system.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\system.htm"
2422209       0x24F5C1        eCos RTOS string reference: "ECOS\\dist\\wifi\\system.html  ----------------------*/","Old Password":"Vecchia password","New Password":"Nuova password","WA"
2429014       0x251056        eCos RTOS string reference: "ECOS\\dist\\wifi\\userManage.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\userMa"
2429118       0x2510BE        eCos RTOS string reference: "ECOS\\dist\\wifi\\userManage.html  ----------------------*/","Connection":"Connessione","Add to Blacklist":"Aggiungere alla li"
2429297       0x251171        eCos RTOS string reference: "ECOS\\dist\\wifi\\wechart.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\wechart.h"
2429398       0x2511D6        eCos RTOS string reference: "ECOS\\dist\\wifi\\wechart.html  ----------------------*/","Tenda wechart":"Tenda wechart","/*----------------------  D:\\Proj"
2429531       0x25125B        eCos RTOS string reference: "ECOS\\dist\\wifi\\wireless.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\wireless"
2429633       0x2512C1        eCos RTOS string reference: "ECOS\\dist\\wifi\\wireless.html  ----------------------*/","WiFi On/Off":"Wifi Acceso/Spento","WiFi Name and Password":"Nome e"
2444718       0x254DAE        eCos RTOS string reference: "ECOS\\dist\\wifi\\advanced.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\advanced"
2446078       0x2552FE        eCos RTOS string reference: "ECOS\\dist\\wifi\\index.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\index.html "
2446177       0x255361        eCos RTOS string reference: "ECOS\\dist\\wifi\\index.html  ----------------------*/","Tenda Wireless Router":"Tenda Routeur sans fil","Tenda":"Tenda","Tend"
2448523       0x255C8B        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\advanced.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\ad"
2451004       0x25663C        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\index.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\index"
2451105       0x2566A1        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\index.js  ----------------------*/","unknown":"Inconnu","Unknown error":"Erreur inconnue","JSON is too l"
2453627       0x25707B        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\ajaxupload.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi"
2453739       0x2570EB        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\ajaxupload.js  ----------------------*/","/*----------------------  D:\\Project\\ECOS\\dist\\wifi"
2453851       0x25715B        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\common.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js"
2453959       0x2571C7        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\common.js  ----------------------*/","Samsung":"Samsung","Apple":"Apple","Huawei":"Huawei","XiaoMi"
2458111       0x2581FF        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\j.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\lib"
2458214       0x258266        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\j.js  ----------------------*/","REasy":"REasy","/*----------------------  D:\\Project\\ECOS\\dis"
2458333       0x2582DD        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\j_ajaxError.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wif"
2458446       0x25834E        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\j_ajaxError.js  ----------------------*/","/*----------------------  D:\\Project\\ECOS\\dist\\wif"
2458559       0x2583BF        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\reasy-ui-1.0.3.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\"
2460560       0x258B90        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\net-control.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\"
2460667       0x258BFB        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\net-control.js  ----------------------*/","A maximum of %s devices can be added to the blacklist.":"Un m"
2461490       0x258F32        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\network.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\net"
2461593       0x258F99        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\network.js  ----------------------*/","When the AP mode is disabled, the router reboots. Do you want to "
2464542       0x259B1E        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\quickset.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\qu"
2464646       0x259B86        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\quickset.js  ----------------------*/","Synchronization success. The current page is refreshed when you "
2465667       0x259F83        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\status.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\stat"
2465769       0x259FE9        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\status.js  ----------------------*/","Internet":"Internet","WiFi":"WiFi","Upstream Router":"Routeur en a"
2465944       0x25A098        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\system.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\syst"
2466046       0x25A0FE        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\system.js  ----------------------*/","The login IP will be changed into %s.":"IP de connexion sera chang"
2468278       0x25A9B6        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\userManage.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\"
2468384       0x25AA20        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\userManage.js  ----------------------*/","/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\"
2468490       0x25AA8A        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\wireless.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\wi"
2468594       0x25AAF2        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\wireless.js  ----------------------*/","The wireless connection will be released. Please connect again.""
2469137       0x25AD11        eCos RTOS string reference: "ECOS\\dist\\wifi\\login.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\login.html "
2469236       0x25AD74        eCos RTOS string reference: "ECOS\\dist\\wifi\\login.html  ----------------------*/","Tenda | LOGIN":"Tenda | Connexion","Language":"Langue","Password":"Mo"
2470096       0x25B0D0        eCos RTOS string reference: "ECOS\\dist\\wifi\\net-control.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\net-c"
2470653       0x25B2FD        eCos RTOS string reference: "ECOS\\dist\\wifi\\network.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\network.h"
2472862       0x25BB9E        eCos RTOS string reference: "ECOS\\dist\\wifi\\quickset.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\quickset"
2472964       0x25BC04        eCos RTOS string reference: "ECOS\\dist\\wifi\\quickset.html  ----------------------*/","Tenda Wizard":"Tenda Wizard","You can access the internet after co"
2475967       0x25C7BF        eCos RTOS string reference: "ECOS\\dist\\wifi\\status.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\status.htm"
2476067       0x25C823        eCos RTOS string reference: "ECOS\\dist\\wifi\\status.html  ----------------------*/","Internet Connection Status":"Statut de la connexion internet","My Ro"
2476570       0x25CA1A        eCos RTOS string reference: "ECOS\\dist\\wifi\\system.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\system.htm"
2476670       0x25CA7E        eCos RTOS string reference: "ECOS\\dist\\wifi\\system.html  ----------------------*/","Old Password":"Ancien mot de passe","New Password":"Nouveau mot de p"
2483626       0x25E5AA        eCos RTOS string reference: "ECOS\\dist\\wifi\\userManage.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\userMa"
2483906       0x25E6C2        eCos RTOS string reference: "ECOS\\dist\\wifi\\wechart.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\wechart.h"
2484007       0x25E727        eCos RTOS string reference: "ECOS\\dist\\wifi\\wechart.html  ----------------------*/","Tenda wechart":"Tenda wechart","/*----------------------  D:\\Proj"
2484140       0x25E7AC        eCos RTOS string reference: "ECOS\\dist\\wifi\\wireless.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\wireless"
2488094       0x25F71E        eCos RTOS string reference: "ECOS\\dist\\wifi\\advanced.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\advanced"
2489464       0x25FC78        eCos RTOS string reference: "ECOS\\dist\\wifi\\index.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\index.html "
2489563       0x25FCDB        eCos RTOS string reference: "ECOS\\dist\\wifi\\index.html  ----------------------*/","Tenda Wireless Router":"Roteador Sem Fio da Tenda","Tenda":"Tenda","T"
2491816       0x2605A8        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\advanced.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\ad"
2494130       0x260EB2        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\index.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\index"
2494231       0x260F17        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\index.js  ----------------------*/","unknown":"desconhecido","Unknown error":"Erro desconhecido","JSON i"
2496666       0x26189A        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\ajaxupload.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi"
2496778       0x26190A        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\ajaxupload.js  ----------------------*/","/*----------------------  D:\\Project\\ECOS\\dist\\wifi"
2496890       0x26197A        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\common.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js"
2496998       0x2619E6        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\common.js  ----------------------*/","Samsung":"Samsung","Apple":"Apple","Huawei":"Huawei","XiaoMi"
2500979       0x262973        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\j.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\lib"
2501082       0x2629DA        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\j.js  ----------------------*/","REasy":"REasy","/*----------------------  D:\\Project\\ECOS\\dis"
2501201       0x262A51        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\j_ajaxError.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wif"
2501314       0x262AC2        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\j_ajaxError.js  ----------------------*/","/*----------------------  D:\\Project\\ECOS\\dist\\wif"
2501427       0x262B33        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\reasy-ui-1.0.3.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\"
2501543       0x262BA7        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\reasy-ui-1.0.3.js  ----------------------*/","Capital characters are entered.":"Os caracteres em m"
2503318       0x263296        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\net-control.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\"
2503425       0x263301        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\net-control.js  ----------------------*/","A maximum of %s devices can be added to the blacklist.":"Um m"
2504210       0x263612        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\network.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\net"
2504313       0x263679        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\network.js  ----------------------*/","When the AP mode is disabled, the router reboots. Do you want to "
2507086       0x26414E        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\quickset.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\qu"
2507190       0x2641B6        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\quickset.js  ----------------------*/","Synchronization success. The current page is refreshed when you "
2508158       0x26457E        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\status.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\stat"
2508260       0x2645E4        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\status.js  ----------------------*/","Internet":"Internet","WiFi":"WiFi","Upstream Router":"Roteador Asc"
2508438       0x264696        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\system.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\syst"
2510639       0x264F2F        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\userManage.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\"
2510745       0x264F99        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\userManage.js  ----------------------*/","/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\"
2510851       0x265003        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\wireless.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\wi"
2510955       0x26506B        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\wireless.js  ----------------------*/","The wireless connection will be released. Please connect again.""
2511477       0x265275        eCos RTOS string reference: "ECOS\\dist\\wifi\\login.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\login.html "
2511576       0x2652D8        eCos RTOS string reference: "ECOS\\dist\\wifi\\login.html  ----------------------*/","Tenda | LOGIN":"Tenda | LOGIN","Language":"Idioma","Password":"Palavr"
2512406       0x265616        eCos RTOS string reference: "ECOS\\dist\\wifi\\net-control.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\net-c"
2512511       0x26567F        eCos RTOS string reference: "ECOS\\dist\\wifi\\net-control.html  ----------------------*/","Online Devices":"Dispositivos on-line","Device Name":"Nome do D"
2512954       0x26583A        eCos RTOS string reference: "ECOS\\dist\\wifi\\network.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\network.h"
2513055       0x26589F        eCos RTOS string reference: "ECOS\\dist\\wifi\\network.html  ----------------------*/","Operating Mode":"Modo de Funcionamento","Router":"Roteador","WISP":"
2515135       0x2660BF        eCos RTOS string reference: "ECOS\\dist\\wifi\\quickset.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\quickset"
2515237       0x266125        eCos RTOS string reference: "ECOS\\dist\\wifi\\quickset.html  ----------------------*/","Tenda Wizard":"Assistente Tenda","You can access the internet afte"
2518093       0x266C4D        eCos RTOS string reference: "ECOS\\dist\\wifi\\status.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\status.htm"
2518701       0x266EAD        eCos RTOS string reference: "ECOS\\dist\\wifi\\system.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\system.htm"
2518801       0x266F11        eCos RTOS string reference: "ECOS\\dist\\wifi\\system.html  ----------------------*/","Old Password":"Senha Antiga","New Password":"Senha Nova","WAN Parame"
2525753       0x268A39        eCos RTOS string reference: "ECOS\\dist\\wifi\\userManage.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\userMa"
2526031       0x268B4F        eCos RTOS string reference: "ECOS\\dist\\wifi\\wechart.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\wechart.h"
2526132       0x268BB4        eCos RTOS string reference: "ECOS\\dist\\wifi\\wechart.html  ----------------------*/","Tenda wechart":"Wechart Tenda","/*----------------------  D:\\Proj"
2526265       0x268C39        eCos RTOS string reference: "ECOS\\dist\\wifi\\wireless.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\wireless"
2526367       0x268C9F        eCos RTOS string reference: "ECOS\\dist\\wifi\\wireless.html  ----------------------*/","WiFi On/Off":"Ligar/Desligar WiFi","WiFi Name and Password":"Nome "
2530066       0x269B12        eCos RTOS string reference: "ECOS\\dist\\wifi\\advanced.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\advanced"
2531397       0x26A045        eCos RTOS string reference: "ECOS\\dist\\wifi\\index.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\index.html "
2531496       0x26A0A8        eCos RTOS string reference: "ECOS\\dist\\wifi\\index.html  ----------------------*/","Tenda Wireless Router":"Router Wireless Tenda","Tenda":"Tenda","Tenda"
2533915       0x26AA1B        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\advanced.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\ad"
2536255       0x26B33F        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\index.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\index"
2538849       0x26BD61        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\ajaxupload.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi"
2538961       0x26BDD1        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\ajaxupload.js  ----------------------*/","/*----------------------  D:\\Project\\ECOS\\dist\\wifi"
2539073       0x26BE41        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\common.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js"
2539181       0x26BEAD        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\common.js  ----------------------*/","Samsung":"Samsung","Apple":"Apple","Huawei":"Huawei","XiaoMi"
2543282       0x26CEB2        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\j.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\lib"
2543385       0x26CF19        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\j.js  ----------------------*/","REasy":"REasy","/*----------------------  D:\\Project\\ECOS\\dis"
2543504       0x26CF90        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\j_ajaxError.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wif"
2543617       0x26D001        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\j_ajaxError.js  ----------------------*/","/*----------------------  D:\\Project\\ECOS\\dist\\wif"
2543730       0x26D072        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\reasy-ui-1.0.3.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\"
2543846       0x26D0E6        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\reasy-ui-1.0.3.js  ----------------------*/","Capital characters are entered.":"Au fost introduse "
2545645       0x26D7ED        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\net-control.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\"
2545752       0x26D858        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\net-control.js  ----------------------*/","A maximum of %s devices can be added to the blacklist.":"Se p"
2546532       0x26DB64        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\network.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\net"
2546635       0x26DBCB        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\network.js  ----------------------*/","When the AP mode is disabled, the router reboots. Do you want to "
2549490       0x26E6F2        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\quickset.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\qu"
2549594       0x26E75A        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\quickset.js  ----------------------*/","Synchronization success. The current page is refreshed when you "
2550580       0x26EB34        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\status.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\stat"
2550858       0x26EC4A        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\system.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\syst"
2550960       0x26ECB0        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\system.js  ----------------------*/","The login IP will be changed into %s.":"IP-ul pentru autentificare"
2553131       0x26F52B        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\userManage.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\"
2553237       0x26F595        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\userManage.js  ----------------------*/","/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\"
2553343       0x26F5FF        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\wireless.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\wi"
2553447       0x26F667        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\wireless.js  ----------------------*/","The wireless connection will be released. Please connect again.""
2553966       0x26F86E        eCos RTOS string reference: "ECOS\\dist\\wifi\\login.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\login.html "
2554895       0x26FC0F        eCos RTOS string reference: "ECOS\\dist\\wifi\\net-control.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\net-c"
2555000       0x26FC78        eCos RTOS string reference: "ECOS\\dist\\wifi\\net-control.html  ----------------------*/","Online Devices":"Dispozitive online","Device Name":"Nume dispoz"
2555430       0x26FE26        eCos RTOS string reference: "ECOS\\dist\\wifi\\network.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\network.h"
2555531       0x26FE8B        eCos RTOS string reference: "ECOS\\dist\\wifi\\network.html  ----------------------*/","Operating Mode":"Mod de operare","Router":"Router","WISP":"WISP","U"
2557692       0x2706FC        eCos RTOS string reference: "ECOS\\dist\\wifi\\quickset.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\quickset"
2557794       0x270762        eCos RTOS string reference: "ECOS\\dist\\wifi\\quickset.html  ----------------------*/","Tenda Wizard":"Wizard Tenda","You can access the internet after co"
2560687       0x2712AF        eCos RTOS string reference: "ECOS\\dist\\wifi\\status.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\status.htm"
2560787       0x271313        eCos RTOS string reference: "ECOS\\dist\\wifi\\status.html  ----------------------*/","Internet Connection Status":"Stare de conexiune la Internet","My Rou"
2561274       0x2714FA        eCos RTOS string reference: "ECOS\\dist\\wifi\\system.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\system.htm"
2568270       0x27304E        eCos RTOS string reference: "ECOS\\dist\\wifi\\userManage.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\userMa"
2568551       0x273167        eCos RTOS string reference: "ECOS\\dist\\wifi\\wechart.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\wechart.h"
2568652       0x2731CC        eCos RTOS string reference: "ECOS\\dist\\wifi\\wechart.html  ----------------------*/","Tenda wechart":"Tenda wechat","/*----------------------  D:\\Proje"
2568784       0x273250        eCos RTOS string reference: "ECOS\\dist\\wifi\\wireless.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\wireless"
2572630       0x274156        eCos RTOS string reference: "ECOS\\dist\\wifi\\advanced.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\advanced"
2572732       0x2741BC        eCos RTOS string reference: "ECOS\\dist\\wifi\\advanced.html  ----------------------*/","MAC Address Filter":"Filtr adresu MAC","Filter Mode":"Tryb filtru""
2573959       0x274687        eCos RTOS string reference: "ECOS\\dist\\wifi\\index.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\index.html "
2574058       0x2746EA        eCos RTOS string reference: "ECOS\\dist\\wifi\\index.html  ----------------------*/","Tenda Wireless Router":"Bezprzewodowy router firmy Tenda","Tenda":"Te"
2576455       0x275047        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\advanced.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\ad"
2578834       0x275992        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\index.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\index"
2581551       0x27642F        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\ajaxupload.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi"
2581663       0x27649F        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\ajaxupload.js  ----------------------*/","/*----------------------  D:\\Project\\ECOS\\dist\\wifi"
2581775       0x27650F        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\common.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js"
2581883       0x27657B        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\common.js  ----------------------*/","Samsung":"Samsung","Apple":"Apple","Huawei":"Huawei","XiaoMi"
2586183       0x277647        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\j.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\lib"
2586286       0x2776AE        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\j.js  ----------------------*/","REasy":"REasy","/*----------------------  D:\\Project\\ECOS\\dis"
2586405       0x277725        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\j_ajaxError.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wif"
2586518       0x277796        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\j_ajaxError.js  ----------------------*/","/*----------------------  D:\\Project\\ECOS\\dist\\wif"
2586631       0x277807        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\reasy-ui-1.0.3.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\"
2586747       0x27787B        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\reasy-ui-1.0.3.js  ----------------------*/","Capital characters are entered.":"Wprowadzono wielki"
2588523       0x277F6B        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\net-control.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\"
2588630       0x277FD6        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\net-control.js  ----------------------*/","A maximum of %s devices can be added to the blacklist.":"Licz"
2589430       0x2782F6        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\network.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\net"
2589533       0x27835D        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\network.js  ----------------------*/","When the AP mode is disabled, the router reboots. Do you want to "
2592546       0x278F22        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\quickset.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\qu"
2592650       0x278F8A        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\quickset.js  ----------------------*/","Synchronization success. The current page is refreshed when you "
2593633       0x279361        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\status.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\stat"
2593735       0x2793C7        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\status.js  ----------------------*/","Internet":"Internet","WiFi":"Wi-Fi","Upstream Router":"Router popr"
2593916       0x27947C        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\system.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\syst"
2594018       0x2794E2        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\system.js  ----------------------*/","The login IP will be changed into %s.":"Adres IP logowania zostani"
2596195       0x279D63        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\userManage.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\"
2596301       0x279DCD        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\userManage.js  ----------------------*/","/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\"
2596407       0x279E37        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\wireless.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\wi"
2596511       0x279E9F        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\wireless.js  ----------------------*/","The wireless connection will be released. Please connect again.""
2597057       0x27A0C1        eCos RTOS string reference: "ECOS\\dist\\wifi\\login.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\login.html "
2597973       0x27A455        eCos RTOS string reference: "ECOS\\dist\\wifi\\net-control.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\net-c"
2598507       0x27A66B        eCos RTOS string reference: "ECOS\\dist\\wifi\\network.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\network.h"
2598608       0x27A6D0        eCos RTOS string reference: "ECOS\\dist\\wifi\\network.html  ----------------------*/","Operating Mode":"Tryb pracy","Router":"Router","WISP":"WISP","Unive"
2600813       0x27AF6D        eCos RTOS string reference: "ECOS\\dist\\wifi\\quickset.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\quickset"
2600915       0x27AFD3        eCos RTOS string reference: "ECOS\\dist\\wifi\\quickset.html  ----------------------*/","Tenda Wizard":"Kreator Tenda","You can access the internet after c"
2603871       0x27BB5F        eCos RTOS string reference: "ECOS\\dist\\wifi\\status.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\status.htm"
2604499       0x27BDD3        eCos RTOS string reference: "ECOS\\dist\\wifi\\system.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\system.htm"
2611642       0x27D9BA        eCos RTOS string reference: "ECOS\\dist\\wifi\\userManage.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\userMa"
2611922       0x27DAD2        eCos RTOS string reference: "ECOS\\dist\\wifi\\wechart.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\wechart.h"
2612023       0x27DB37        eCos RTOS string reference: "ECOS\\dist\\wifi\\wechart.html  ----------------------*/","Tenda wechart":"Tenda wechart","/*----------------------  D:\\Proj"
2612156       0x27DBBC        eCos RTOS string reference: "ECOS\\dist\\wifi\\wireless.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\wireless"
2616146       0x27EB52        eCos RTOS string reference: "ECOS\\dist\\wifi\\advanced.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\advanced"
2616248       0x27EBB8        eCos RTOS string reference: "ECOS\\dist\\wifi\\advanced.html  ----------------------*/","MAC Address Filter":"MAC Adresi Filtresi","Filter Mode":"Filtre Mo"
2617509       0x27F0A5        eCos RTOS string reference: "ECOS\\dist\\wifi\\index.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\index.html "
2617608       0x27F108        eCos RTOS string reference: "ECOS\\dist\\wifi\\index.html  ----------------------*/","Tenda Wireless Router":"Tenda Kablosuz Router","Tenda":"Tenda","Tenda"
2619988       0x27FA54        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\advanced.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\ad"
2622265       0x280339        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\index.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\index"
2622366       0x28039E        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\index.js  ----------------------*/","unknown":"bilinmiyor","Unknown error":"Bilinmeyen hata","JSON is to"
2624772       0x280D04        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\ajaxupload.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi"
2624884       0x280D74        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\ajaxupload.js  ----------------------*/","/*----------------------  D:\\Project\\ECOS\\dist\\wifi"
2624996       0x280DE4        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\common.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js"
2625104       0x280E50        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\common.js  ----------------------*/","Samsung":"Samsung","Apple":"Apple","Huawei":"Huawei","XiaoMi"
2629336       0x281ED8        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\j.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\lib"
2629439       0x281F3F        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\j.js  ----------------------*/","REasy":"REasy","/*----------------------  D:\\Project\\ECOS\\dis"
2629558       0x281FB6        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\j_ajaxError.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wif"
2629671       0x282027        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\j_ajaxError.js  ----------------------*/","/*----------------------  D:\\Project\\ECOS\\dist\\wif"
2629784       0x282098        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\libs\\reasy-ui-1.0.3.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\"
2631647       0x2827DF        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\net-control.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\"
2631754       0x28284A        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\net-control.js  ----------------------*/","A maximum of %s devices can be added to the blacklist.":"En f"
2632507       0x282B3B        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\network.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\net"
2632610       0x282BA2        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\network.js  ----------------------*/","When the AP mode is disabled, the router reboots. Do you want to "
2635628       0x28376C        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\quickset.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\qu"
2635732       0x2837D4        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\quickset.js  ----------------------*/","Synchronization success. The current page is refreshed when you "
2636703       0x283B9F        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\status.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\stat"
2636991       0x283CBF        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\system.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\syst"
2639240       0x284588        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\userManage.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\"
2639346       0x2845F2        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\userManage.js  ----------------------*/","/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\"
2639452       0x28465C        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\wireless.js  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\js\\wi"
2639556       0x2846C4        eCos RTOS string reference: "ECOS\\dist\\wifi\\js\\wireless.js  ----------------------*/","The wireless connection will be released. Please connect again.""
2640079       0x2848CF        eCos RTOS string reference: "ECOS\\dist\\wifi\\login.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\login.html "
2640999       0x284C67        eCos RTOS string reference: "ECOS\\dist\\wifi\\net-control.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\net-c"
2641525       0x284E75        eCos RTOS string reference: "ECOS\\dist\\wifi\\network.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\network.h"
2643770       0x28573A        eCos RTOS string reference: "ECOS\\dist\\wifi\\quickset.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\quickset"
2646779       0x2862FB        eCos RTOS string reference: "ECOS\\dist\\wifi\\status.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\status.htm"
2647371       0x28654B        eCos RTOS string reference: "ECOS\\dist\\wifi\\system.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\system.htm"
2654412       0x2880CC        eCos RTOS string reference: "ECOS\\dist\\wifi\\userManage.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\userMa"
2654685       0x2881DD        eCos RTOS string reference: "ECOS\\dist\\wifi\\wechart.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\wechart.h"
2654786       0x288242        eCos RTOS string reference: "ECOS\\dist\\wifi\\wechart.html  ----------------------*/","Tenda wechart":"Tenda WeChat","/*----------------------  D:\\Proje"
2654918       0x2882C6        eCos RTOS string reference: "ECOS\\dist\\wifi\\wireless.html  ----------------------*/":"/*----------------------  D:\\Project\\ECOS\\dist\\wifi\\wireless"
2692511       0x29159F        HTML document header
2704602       0x2944DA        HTML document footer
2704612       0x2944E4        XML document, version: "1.0"
2821864       0x2B0EE8        GIF image data, version "89a", 18 x 18
2823052       0x2B138C        PNG image, 80 x 12, 8-bit colormap, non-interlaced
2823624       0x2B15C8        PNG image, 115 x 16, 8-bit colormap, non-interlaced
2823964       0x2B171C        PNG image, 133 x 30, 8-bit colormap, non-interlaced
2824964       0x2B1B04        PNG image, 43 x 31, 8-bit colormap, non-interlaced
2825576       0x2B1D68        PNG image, 172 x 436, 8-bit colormap, non-interlaced
2841964       0x2B5D6C        PNG image, 116 x 26, 8-bit colormap, non-interlaced
2842823       0x2B60C7        HTML document header
2846365       0x2B6E9D        HTML document footer
2855007       0x2B905F        HTML document header
2866177       0x2BBC01        HTML document footer
2877276       0x2BE75C        AES S-Box
```



### Step 4: Static Ghidra Firmware Analysis

After loading the decompressed firmware into Ghidra, we commenced static analysis.  Based on the references to files we found within various strings in the firmware, we have reason to believe that the firmware we found still contains files in it. 

Between `0x002b0ee8` and `0x002b5d6`, we see many pngs and a gif; these are most likely used in the user interface presented when you connect to the router to set it up.  Directly after these addresses is a section of HTML stored as a string.  This, too, seems like it's is used when setting up or configuring the router, as indicated by the inclusion of text like "Operating Mode" and "Blacklisted Devices".

Furthermore we found a very long section of JavaScript, stored as a string, from memory address `0x001ddae0` onwards.  However, based on our analysis, we did not discover any locations in the firmwhere that touched the JavaScript string, which would imply that this JavaScript is a file stored in the firmware.  Thus, this further supports our hypothesis that the firmware still contains multiple files.  To see an example of one of the segments of JavaScript, please see this snippet below (which we have manually added some newlines to for clarity about the various functions it performs):

```javascript
define((function(require,exports,module){
var pageModule=new PageLogic({getUrl:\"goform/getParentControl\",modules:\"parentCtrlList,parentAccessCtrl\",setUrl:\"goform/setParentControl\"});
pageModule.modules=[],module.exports=pageModule,pageModule.beforeSubmit=function(){var urlInputVal=$(\"#urlFilterAllow\").val(),msg=CheckUrlVolidate();return !msg||\"\"===urlInputVal||(top.mainLogic.showModuleMsg(msg),!1)};
var attachedModule=new AttachedModule;function AttachedModule(){var timeFlag;function getOnlineListData(){var str=\"\",i=0,listArry=$(\"#onlineList\").children(),len=listArry.length,hostname;
for(i=0;i<len;i++){
  str+=(hostname=$(listArry).eq(i).children().find(\"div\").eq(0).attr(\"data-hostName\"))+\"\\t\",hostname==$(listArry).eq(i).children().find(\"input\").val()?str+=\"\\t\":str+=$(listArry).eq(i).children().find(\"input\").val()+\"\\t\", str+=$(listArry).eq(i).children().find(\"div\").eq(0).attr(\"alt\")+\"\\t\",  str+=$(listArry).eq(i).children().eq(1).html()+\"\\t\", str+=$(listArry).eq(i).children().eq(3).find(\"div\").hasClass(\"icon-toggle-on\")+\"\\n\"}
return str=str.replace(/[\\n]$/,\"\")
}


function editDeviceName(){
        var deviceName=$(this).parent().prev(\"div\").text();$(this).parent().parent().find(\"div\").hide(), $(this).parent().parent().find(\"input\").show().addClass(\"edit-old\"), $(this).parent().parent().find(\"input\").val(deviceName), $(this).parent().parent().find(\"input\").focus()
}


function getEnablelist(){
var index=0,i=0,$listArry=$(\"#onlineList\").children(),length=$listArry.length;
for(i=0;i<length;i++){
$listArry.eq(i).children().eq(3).find(\"div\").hasClass(\"icon-toggle-on\")&&index++
}
return index
}


function changeDeviceManage(){
var className;
if(\"switch icon-toggle-on\"==(this.className||\"switch icon-toggle-on\")){
this.className=\"switch icon-toggle-off\"}else{if(getEnablelist()>=10){
return void top.mainLogic.showModuleMsg(_(\"A maximum of %s entries can be added.\"[10]))}
this.className=\"switch icon-toggle-on\"}}
    

function refreshTableList(
{$.get(\"goform/getParentControl\"+getRandom()+\"&modules=parentCtrlList\",updateTable), clearTimeout(timeFlag), timeFlag=setTimeout((function(){refreshTableList()}), 5000), pageModule.pageRunning||clearTimeout(timeFlag)
}
    

function updateTable(obj){
  checkIsTimeOut(obj) && top.location.reload(!0);
  try{obj=$.parseJSON(obj)}
  catch(e){obj={}}
  if(isEmptyObject(obj)){
    top.location.reload(!0)}
  else{
    if(pageModule.pageRunning){
      var getOnlineList=obj.parentCtrlList, $onlineTbodyList=$(\"#onlineList\").children(), onlineTbodyLen=$onlineTbodyList.length,getOnlineLen=getOnlineList.length,j=0,i=0,oldMac,newMac,rowData=new Array(onlineTbodyLen),refreshObj=new Array(getOnlineLen),newDataArray=[];
for(i=0;i<getOnlineLen;i++){
                                               for(newMac=getOnlineList[i].parentCtrlMAC.toUpperCase(),refreshObj[i]={},j=0;j<onlineTbodyLen;j++){
        var $nameDom=$onlineTbodyList.eq(j).children().eq(0).find(\".device-name-show\");(oldMac=$nameDom[0]?$nameDom.eq(0).attr(\"alt\").toUpperCase():\"\")==newMac&&(rowData[j]={},$onlineTbodyList.eq(j).children().eq(2).html(formatSeconds(getOnlineList[i].parentCtrlConnectTime)),rowData[j].refresh=!0,refreshObj[i].exist=!0),$onlineTbodyList.eq(j).children().eq(0).find(\"input\").eq(0).hasClass(\"edit-old\")&&(rowData[j]={},rowData[j].refresh=!0)}}
for(i=0;i<getOnlineLen;i++{
                                                                  refreshObj[i].exist||newDataArray.push(getOnlineList[i])}for(j=0;j<onlineTbodyLen;j++){rowData[j]&&rowData[j].refresh||$onlineTbodyList.eq(j).remove()}0!==newDataArray.length&&creatOnlineTable(newDataArray)}}}
function creatOnlineTable(obj){
  var len=obj.length, i=0, str=\"\",prop,hostname,divElem,divElem1,trElem,tdElem;for(i=0;i<len;i++){trElem=document.createElement(\"tr\");var tdStr=\"\";
  for(prop in obj[i]){hostname=\"\"!=obj[i].parentCtrlRemark?obj[i].parentCtrlRemark:obj[i].parentCtrlHostname,\"parentCtrlHostname\"==prop?(tdStr+='<td><input type=\"text\" class=\"form-control none device-name\" style=\"width:66%;\" value=\"\" maxLength=\"63\" />',tdStr+='<div class=\"col-xs-8 span-fixed device-name-show\"></div>',tdStr+='<div class=\"col-xs-2 editDiv\"><span class=\"ico-small icon-edit\" title=\"'+_(\"Edit\")+'\">&nbsp;</span></div></td>'):\"parentCtrlIP\"==prop?tdStr+='<td class=\"hidden-xs\">'+obj[i][prop]+\"</td>\":\"parentCtrlConnectTime\"==prop?tdStr+='<td class=\"hidden-xs\" data-onlinetime=\"'+obj[i][prop]+'\">'+formatSeconds(obj[i][prop])+\"</td>\":\"parentCtrlEn\"==prop&&(\"true\"==obj[i][prop]?tdStr+=\"<td class='internet-ctl' style=''><div class='switch icon-toggle-on'></div></td>\":tdStr+=\"<td class='internet-ctl' style=''><div class='switch icon-toggle-off'></div></td>\")}$(trElem).html(tdStr),$(trElem).find(\".device-name\")[0].value=hostname;var $deviceNameShow=$(trElem).find(\".device-name-show\");$deviceNameShow.attr(\"title\",hostname),$deviceNameShow.attr(\"alt\",obj[i].parentCtrlMAC),$deviceNameShow.attr(\"data-hostName\",obj[i].parentCtrlHostname),$deviceNameShow.attr(\"data-remark\",hostname),void 0!==$deviceNameShow.text()?$deviceNameShow[0].innerText=hostname:$deviceNameShow[0].textContent=hostname,$(\"#onlineList\").append($(trElem))}0==$(\"#onlineList\").children().length&&(str=\"<tr><td colspan='2' class='no-device'>\"+_(\"No device\")+\"</td></tr>\",$(\"#onlineList\").append(str)),top.mainLogic.initModuleHeight()}this.moduleName=\"parentCtrlList\",this.init=function(){this.initEvent()},this.initEvent=function(){$(\"#onlineList\").delegate(\".switch\",\"click\",changeDeviceManage),$(\"#onlineList\").delegate(\".icon-edit\",\"click\",editDeviceName),$(\"#onlineList\").delegate(\".form-control\",\"blur\",(function(){$(this).val()==$(this).next().attr(\"data-remark\")&&$(this).removeClass(\"edit-old\"),$(this).next().attr(\"title\",$(this).val()),$(this).next().text($(this).val()),$(this).next().show(),$(this).next().next().show(),$(this).hide()})),$(\"#urlFilterAllow\").on(\"keydown\",(function(e){var charCode;13==(e.keyCode||e.charCode)&&(window.event?window.event.returnValue=!1:e.preventDefault())}))},this.initValue=function(onlineArr){$(\"#onlineList\").html(\"\"),creatOnlineTable(onlineArr),timeFlag=setTimeout((function(){refreshTableList()}),5000),this.adjustWidth()},this.adjustWidth=function(){window.innerWidth<375&&$(\".span-fixed\").css(\"width\",\"90px\")},this.checkData=function(){var deviceName=\"\",$listTable=$(\"#onlineList\").children(),length=$listTable.length,$td,i=0;for(i=0;i<length;i++){if(\"\"==(deviceName=($td=$listTable.eq(i).children()).find(\"input\").eq(0).val()).replace(/[ ]/g,\"\")){return $td.find(\"input\").eq(0).focus(),_(\"No space is allowed in a device name.\")}}},this.getSubmitData=function(){var data={module1:this.moduleName,onlineList:getOnlineListData()};return objToString(data)}}


function CheckUrlVolidate(){
var url=$(\"#urlFilterAllow\").val(),len=$(\"#urlList\").children().length,i=0;if(\"\"==url){return $(\"#urlFilterAllow\").focus(),_(\"Please input a key word of domain name!\")}if(!/^[-_~\\#%&\\|\\\\\\/\\?=+!*\\.()0-9a-zA-Z\\u4e00-\\u9fa5]+$/gi.test(url)){return $(\"#urlFilterAllow\").focus(),_(\"Please input a key word of domain name!\")}if(/^(\\.)(.+)?$/gi.test(url)){return $(\"#urlFilterAllow\").focus(),_(\"Please input a key word of domain name!\")}if(-1!==url.indexOf(\"..\")){return $(\"#urlFilterAllow\").focus(),_(\"Please input a key word of domain name!\")}var ret=$.validate.valid.url(url);if(ret){return $(\"#urlFilterAllow\").focus(),ret}var trList=$(\"#urlList\").children();for(i=0;i<len;i++){if(url==trList.eq(i).children().eq(1).find(\"div\").text()){return $(\"#urlFilterAllow\").focus(),_(\"This website is used. Please try another.\")}}return len>=32?_(\"A maximum of %s entries can be added.\",[32]):void 0}pageModule.modules.push(attachedModule);var restrictionModule=new RestrictionModule;


function RestrictionModule(){
function getScheduleDate(){var i=0,len=8,str=\"\";for(i=0;i<8;i++){$(\"#day\"+i)[0].checked?str+=\"1\":str+=\"0\"}return str}var oldDate;
function clickTimeDay(){var dataStr=getScheduleDate();\"day0\"==this.id?this.checked?translateDate(\"11111111\"):translateDate(\"00000000\"):\"1111111\"==dataStr.slice(1)?translateDate(\"11111111\"):translateDate(\"0\"+dataStr.slice(1))}


function translateDate(str){var dayArry=str.split(\"\"),len=dayArry.length,i=0;for(i=0;i<len;i++){$(\"#day\"+i)[0].checked=1==dayArry[i]}}


function changeUrlMode(){var urlMode=$(\"#parentCtrlURLFilterMode\").val();\"disable\"!=urlMode?($(\"#urlFilterWrap\").show(),\"permit\"==urlMode?$(\"#websiteLabel\").html(_(\"Unblocked Websites\")):$(\"#websiteLabel\").html(_(\"Blocked Websites\"))):$(\"#urlFilterWrap\").hide(),mainLogic.initModuleHeight()}


function addUrlList(){var url=$(\"#urlFilterAllow\").val(),len=$(\"#urlList\").children().length,i=0,msg=CheckUrlVolidate();if(msg){top.mainLogic.showModuleMsg(msg)}else{var str=\"\";str+=\"<tr>\",str+=\"<td align='center'>\"+(len+1)+\"</td>\",str+=\"<td><div class='span-fixed' style='width:200px;' title='\"+url+\"'>\"+url+\"</div></td>\",str+='<td align=\"center\"><span class=\"operate icon-del deleteUrl\"></span></td>',$(\"#urlList\").append(str),$(\"#urlFilterAllow\").val(\"\"),top.mainLogic.initModuleHeight()}}


function deUrlList(){for(var nextTr=$(this).parent().parent().nextAll(),len=nextTr.length,i=0;i<len;i++){nextTr[i].children[0].innerHTML=parseInt(parseInt(nextTr[i].children[0].innerHTML))-1}$(this).parent().parent().remove(),top.mainLogic.initModuleHeight()}


function getUrlListData(){var str=\"\",i=0,listArry=$(\"#urlList\").children(),len=listArry.length,urlInputVal=$(\"#urlFilterAllow\").val();for(i=0;i<len;i++){str+=$(listArry).eq(i).children().eq(1).find(\"div\").text()+\"\\n\"}return str=str.replace(/[\\n]$/,\"\"),\"\"!==urlInputVal&&(str+=\"\"!=str?\"\\n\"+$(\"#urlFilterAllow\").val():$(\"#urlFilterAllow\").val()),str}


function createUrlList(arry){var i=0,len=arry.length,str=\"\";for(i=0;i<len;i++){str+=\"<tr>\",str+=\"<td align='center'>\"+(i+1)+\"</td>\",str+=\"<td><div class='span-fixed' style='width:200px;' title='\"+arry[i]+\"'>\"+arry[i]+\"</div></td>\",str+='<td align=\"center\"><span class=\"operate icon-del deleteUrl\"></span></td>'}$(\"#urlList\").html(str)}this.moduleName=\"parentAccessCtrl\",this.init=function(){this.initHtml(),this.initEvent()},this.initHtml=function(){var hourStr=\"\",minStr=\"\",i=0;for(i=0;i<24;i++){hourStr+=\"<option value='\"+(\"100\"+i).slice(-2)+\"'>\"+(\"100\"+i).slice(-2)+\"</option>\"}for($(\"#startHour, #endHour\").html(hourStr),i=0;i<60;i++){i%5==0&&(minStr+=\"<option value='\"+(\"100\"+i).slice(-2)+\"'>\"+(\"100\"+i).slice(-2)+\"</option>\")}$(\"#startMin, #endMin\").html(minStr)},this.initEvent=function(){$(\"[id^=day]\").on(\"click\",clickTimeDay),$(\"#addUrl\").on(\"click\",addUrlList),$(\"#urlList\").delegate(\".deleteUrl\",\"click\",deUrlList),$(\"#parentCtrlURLFilterMode\").on(\"change\",changeUrlMode),$(\"#onlineList\").delegate(\".device-name\",\"keyup\",(function(){var deviceVal=this.value.replace(\"\\t\",\"\").replace(\"\\n\",\"\"),len=deviceVal.length,totalByte=getStrByteNum(deviceVal);if(totalByte>63){for(var i=len-1;i>0;i--){if((totalByte-=getStrByteNum(deviceVal[i]))<=63){this.value=deviceVal.slice(0,i);break}}}this.value=deviceVal}))},this.initValue=function(obj){$(\"#urlFilterAllow\").val(\"\"),$(\"#urlFilterAllow\").addPlaceholder(_(\"Enter website\")),translateDate(obj.parentCtrlOnlineDate),oldDate=obj.parentCtrlOnlineDate;var time=obj.parentCtrlOnlineTime.split(\"-\");$(\"#startHour\").val(time[0].split(\":\")[0]),$(\"#startMin\").val(time[0].split(\":\")[1]),$(\"#endHour\").val(time[1].split(\":\")[0]),$(\"#endMin\").val(time[1].split(\":\")[1]),$(\"#parentCtrlURLFilterMode\").val(obj.parentCtrlURLFilterMode),createUrlList(obj.parentCtrlURL),changeUrlMode()},this.checkData=function(){var date;if(\"00000000\"==getScheduleDate()){return _(\"Select at least one day.\")}var urlList=getUrlListData(),url=$(\"#urlFilterAllow\").val(),urlFilterMode=$(\"#parentCtrlURLFilterMode\").val();return\"\"===urlList&&\"\"===url&&\"disable\"!==urlFilterMode?_(\"Please input a key word of domain name!\"):void 0},this.getSubmitData=function(){var time=time=$(\"#startHour\").val()+\":\"+$(\"#startMin\").val()+\"-\"+$(\"#endHour\").val()+\":\"+$(\"#endMin\").val(),data={module2:this.moduleName,parentCtrlOnlineTime:time,parentCtrlOnlineDate:getScheduleDate(),parentCtrlURLFilterMode:$(\"#parentCtrlURLFilterMode\").val(),urlList:getUrlListData()};return objToString(data)}}pageModule.modules.push(restrictionModule)}));"
```

Based on our cursory analysis of this JavaScript, this seems like generic code tasked with managing interactions between different devices and different URLs.  This, of course, is a very standard and expected action for a router to be taking.  Due to our group having limited knowledge about networking, our understanding of the code was ultimately limited.

Apart from various strings we found in the firmware update, there are also many memory touches that we examined that went beyond the addresses of the firmware.  These touches, for example, frequently accessed addresses from `0xfffffff8000000` onwards.  These addresses might be data or functions, but we think it most likely that this is data being stored either in ROM/RAM, or on another chip in the device.  In that case, the address just shows us that it's accessing another component of the circuit.

## Conclusions

From this project, we've come to a variety of conclusions.  First and foremost, we've gained much insight into the processes of embedded device analysis, especially in how to effectively research information about the physical specs of devices, and how to use tools like `binwalk` to examine firmwmare images.

As was expected, we were not able to complete our analysis of the Tenda n301 router.  However, we've had quite some success in building the foundations for further investigation and analysis.  We hope to build on this ourselves, but also are glad to make it available to the greater RE community on GitHub, such that others looking into the Tenda n301 can benefit from our findings.  We believe that there is absolutely a path—with further work and expertise—to exploiting and gaining complete control of a Tenda n301 router.

