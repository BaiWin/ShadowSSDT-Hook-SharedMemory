#include "KernelIncludes.h"

static const ULONG64 PageSize = 0x1000;
static const ULONG64 PageMask = 0xFFF;
static const ULONG64 PhysMask = 0x0000FFFFFFFFF000;
static const ULONG64 BitV = 0x1; // Valid?
static const ULONG64 BitW = 0x2; // Writable?
static const ULONG64 BitL = 0x80; // Large?


__forceinline ULONG64 Min(ULONG64 A, ULONG64 B)
{
    return (A < B) ? A : B;
}

NTSTATUS ReadPhysical(PEPROCESS Process, ULONG64 Address, PVOID Buffer, SIZE_T Length, ULONG64 BaseVA)
{
    if (!Process || !Length || !BaseVA) return STATUS_INVALID_PARAMETER;
    SIZE_T Left = Length;
    SIZE_T Off = 0;
    PUCHAR Dest = (PUCHAR)Buffer;

    DebugMessage("[Debug] ReadPhysical: BaseVA = 0x%llX, TargetVA = 0x%llX, Length = %zu\n",
        BaseVA, Address, Length);

    ULONG64 cr3 = GetCachedCr3(Process, BaseVA);
    if(!cr3) DebugMessage("[!] CR3 Invalid: %llX\n", cr3);

    while (Left > 0)
    {
        ULONG64 PA = TranslateToPhysical(Address + Off, cr3);
        if (!PA) return STATUS_UNSUCCESSFUL;

        DebugMessage("[Debug] VA 0x%llX -> PA 0x%llX (Offset: +0x%zX)\n",
            Address + Off, PA, Off);

        WriteFormattedLog("Virtual Adress: 0x%llx", Address);
        WriteFormattedLog("Transfered Physical: 0x%llx", PA);

        ULONG64 PO = PA & PageMask;
        SIZE_T Bytes = Min(PageSize - PO, Left);

        MM_COPY_ADDRESS Src;
        Src.PhysicalAddress.QuadPart = PA;
        SIZE_T TX;

        DebugMessage("[Debug] PageOffset=0x%llX, PageSize=0x%zX, Left=0x%zX, Bytes=0x%zX\n",
            PO, PageSize, Left, Bytes);

        if (!NT_SUCCESS(MmCopyMemory(Dest + Off, Src, Bytes,
            MM_COPY_MEMORY_PHYSICAL, &TX)))
        {
            DebugMessage("[!] MmCopyMemory Read Failed: %llX\n", PA);
            return STATUS_ACCESS_DENIED;
        }
        else
        {
            for (SIZE_T i = 0; i < 8; i++)  // 最多打印前8字节
            {
                DebugMessage(" %02X", Dest[Off + i]);
                WriteFormattedLog("[read][%zu]: %02X", i, Dest[Off + i]);
            }
            DebugMessage("\n");
        }

        Left -= Bytes;
        Off += Bytes;
    }
    return STATUS_SUCCESS;
}

ULONG64 GetCachedCr3(PEPROCESS Process, ULONG64 BaseVA)
{
    static ULONG64 cachedCR3 = 0;
    static ULONG cachedPid = 0;

    PSHARED_MEMORY_DATA pSharedData = GetSharedDataOnce();
    ULONG TargetPid = pSharedData->TargetPid;
    EncryptField(&TargetPid);

    if (cachedPid == TargetPid && cachedCR3 != 0)
    {
        return cachedCR3;
    }

    ULONG64 searchedCR3 = SearchRealCr3(BaseVA);
    if (searchedCR3)
    {
        cachedCR3 = searchedCR3;
        cachedPid = TargetPid;

        //ULONG64 RawCr3 = *(ULONG64*)((PUCHAR)Process + 0x28);

        /*DebugMessage("[*] SearchedCR3: 0x%llx, Raw CR3 (EPROCESS+0x28): 0x%llx\n",
            searchedCR3, RawCr3);*/
    }

    return cachedCR3;
}

ULONG64 SearchRealCr3(ULONG64 GameBaseVirtualAddress)
{
    for (ULONG64 i = 0; i < 0x800000; i++)           // 最多扫 32GB 物理内存
    {
        ULONG64 CandidateCR3 = i << 12;                 // 候选 PML4 物理页地址（4KB 对齐）

        ULONG64 TranslatedPA = TranslateToPhysical(GameBaseVirtualAddress, CandidateCR3);
        if (!TranslatedPA)
            continue;

        USHORT Signature = 0;
        SIZE_T Bytes = 0;
        MM_COPY_ADDRESS Src = { 0 };
        Src.PhysicalAddress.QuadPart = TranslatedPA;

        if (NT_SUCCESS(MmCopyMemory(&Signature, Src, sizeof(Signature),
            MM_COPY_MEMORY_PHYSICAL, &Bytes)))
        {
            if (Signature == 0x5A4D)                // 'MZ'
            {
                DebugMessage("[+] Found real CR3: 0x%llx (page %lld)\n", CandidateCR3, i);
                return CandidateCR3;                   // ← 正确返回
            }
        }
    }
    return 0;
}

ULONG64 TranslateToPhysical(ULONG64 VA, ULONG64 Base)
{
    ULONG64 Directory = Base & PhysMask;
    if (!Directory) return 0;

    // 强制砍成 48 位规范地址，防止符号位扩展
    VA &= 0x0000FFFFFFFFFFFFULL;

    ULONG64 PML4 = (VA >> 39) & 0x1FF;
    ULONG64 PDPT = (VA >> 30) & 0x1FF;
    ULONG64 PD = (VA >> 21) & 0x1FF;
    ULONG64 PT = (VA >> 12) & 0x1FF;

    ULONG64 PML4E = TableEntry(Directory + (PML4 * 8));
    if (!(PML4E & BitV)) return 0; 

    ULONG64 PDPTE = TableEntry((PML4E & PhysMask) + (PDPT * 8));
    if (!(PDPTE & BitV)) return 0;
    if (PDPTE & BitL) return (PDPTE & 0x000FFFFFC0000000) + (VA & 0x3FFFFFFF);

    ULONG64 PDE = TableEntry((PDPTE & PhysMask) + (PD * 8));
    if (!(PDE & BitV)) return 0;
    if (PDE & BitL) return (PDE & 0x000FFFFFFFE00000) + (VA & 0x1FFFFF);

    ULONG64 PTE = TableEntry((PDE & PhysMask) + (PT * 8));
    if (!(PTE & BitV)) return 0;

    //WriteFormattedLog("PML4E: 0x%llx", PML4E);
    //WriteFormattedLog("PDPTE: 0x%llx", PDPTE);
    //WriteFormattedLog("PDE: 0x%llx", PDE);
    //WriteFormattedLog("PTE: 0x%llx", PTE);

    return (PTE & PhysMask) + (VA & PageMask);
}

ULONG64 TableEntry(ULONG64 PA)
{
    if (!MmCopyMemory) return 0;
    MM_COPY_ADDRESS Source;
    Source.PhysicalAddress.QuadPart = PA;
    ULONG64 Buffer = 0;
    SIZE_T Bytes = 0;
    NTSTATUS Status = MmCopyMemory(
        &Buffer,
        Source,
        sizeof(ULONG64),
        MM_COPY_MEMORY_PHYSICAL,
        &Bytes);
    if (!NT_SUCCESS(Status))
    {
        return 0;
    }
    return Buffer;
}