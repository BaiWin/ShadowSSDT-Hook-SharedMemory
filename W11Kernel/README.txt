---------------------debug print-----------------------------
ed nt!KdDebuggerEnabled 1
dd nt!KdDebuggerEnabled L1

---------------------ntoskrnl section--------------------------

lm m ntoskrnl

kd> lm m ntoskrnl
Browse full module list                                                                    
start             end                 module name
kd> lmD
start             end                 module name
fffff80769280000 fffff807692d4000   KslD       (pdb symbols)          c:\symbols\KSLD.pdb\06B4876789602B014ABEAFF5FCBB14121\KSLD.pdb
fffff807692e0000 fffff807692fa000   WdNisDrv   (deferred)             
fffff806d2200000 fffff806d3650000   nt         (pdb symbols)          c:\symbols\ntkrnlmp.pdb\37037C16F29E2343ED6D79A5C68F87221\ntkrnlmp.pdb

Unloaded modules:
fffff80769020000 fffff80769040000   NetworkPrivacyPolicy.sys
fffff80766f20000 fffff80766f3a000   dump_storport.sys
fffff80766f90000 fffff80766fe0000   dump_stornvme.sys
fffff80766a30000 fffff80766a57000   dump_dumpfve.sys
fffff80767140000 fffff80767162000   dam.sys 
fffff80767170000 fffff80767184000   KMPDC.sys
fffff80766b50000 fffff80766b65000   uiomap.sys
fffff80764d00000 fffff80764d0c000   WdBoot.sys
fffff80766730000 fffff80766744000   hwpolicy.sys

ntoskrnl.exe 的地址范围是 fffff806`d2200000 fffff806`d3650000 

!dh fffff806`d2200000

SECTION HEADER #1A
   .data name
  1C35B0 virtual size
  E00000 virtual address
    F000 size of raw data
  BEE000 file pointer to raw data
       0 file pointer to relocation table
       0 file pointer to line numbers
       0 number of relocations
       0 number of line numbers
C8000040 flags
         Initialized Data
         Not Paged
         (no align specified)
         Read Write

fffff806`d2200000 + 0xE00000 ~ fffff806`d2200000 + 0xE00000 + 0x1C35B0

fffff806`d3000000 ~ xxxxxxx

db fffff806`d3000000 L100

find nop

LEARNING URL：https://m0uk4.gitbook.io/notebooks/mouka/windowsinternal/ssdt-hook

目标	SSDT Hooking	Shadow SSDT Hooking
目标模块	ntoskrnl.exe	win32k.sys
函数类型	内核系统调用	GUI系统调用
Shellcode位置	ntoskrnl模块内	win32k模块内
示例函数	NtQuerySystemInformation	NtUserCreateWindowEx


0:082> u win32u!NtUserGetListBoxInfo
win32u!NtUserGetListBoxInfo:
00007fff`8c7c9c30 4c8bd1          mov     r10,rcx
00007fff`8c7c9c33 b84d140000      mov     eax,144Dh
00007fff`8c7c9c38 f604250803fe7f01 test    byte ptr [SharedUserData+0x308 (00000000`7ffe0308)],1
00007fff`8c7c9c40 7503            jne     win32u!NtUserGetListBoxInfo+0x15 (00007fff`8c7c9c45)
00007fff`8c7c9c42 0f05            syscall
00007fff`8c7c9c44 c3              ret
00007fff`8c7c9c45 cd2e            int     2Eh
00007fff`8c7c9c47 c3              ret

-----------------------------
windbg设置调试显示输出： 
ed nt!Kd_Default_Mask 0xFFFFFFFF