#include "KernelIncludes.h"

KSPIN_LOCK g_ssdtLock;

NTSTATUS MmSafeCopyMemoryForNonPaged(
    IN PVOID Destination,
    IN CONST PVOID Source,
    IN SIZE_T Length
)
{
    PMDL mdl = NULL;
    PVOID mapped = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    KIRQL oldIrql = PASSIVE_LEVEL;

    if (!Destination || !Source || Length == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    __try
    {
        // 1) 分配 MDL 描述目标地址（注意：Destination 为内核 nonpaged 地址）
        mdl = IoAllocateMdl(Destination, (ULONG)Length, FALSE, FALSE, NULL);
        if (!mdl)
        {
            DebugMessage("MmSafeCopyMemoryForNonPaged: IoAllocateMdl failed\n");
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }

        // 2) 针对非分页池直接 build MDL（不要 MmProbeAndLockPages）
        MmBuildMdlForNonPagedPool(mdl);

        // 3) 在低 IRQL 映射此 MDL（必须在 <= APC_LEVEL）
        mapped = MmMapLockedPagesSpecifyCache(
            mdl,
            KernelMode,
            MmNonCached,
            NULL,
            FALSE,
            NormalPagePriority
        );
        if (!mapped)
        {
            DebugMessage("MmSafeCopyMemoryForNonPaged: MmMapLockedPagesSpecifyCache failed\n");
            status = STATUS_UNSUCCESSFUL;
            __leave;
        }

        // 4) 如果你担心并发读取表项（推荐），提升到 DPC 级别做短小写入
        oldIrql = KeRaiseIrqlToDpcLevel();

        // 5) 实际写入（短小、原子）
        RtlCopyMemory(mapped, Source, Length);

        // 6) 恢复 IRQL
        KeLowerIrql(oldIrql);

        status = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = GetExceptionCode();
        DebugMessage("MmSafeCopyMemoryForNonPaged: exception 0x%X\n", status);
    }

    // 7) 清理（注意：在低 IRQL 下解除映射和释放 MDL）
    if (mapped)
    {
        // MmUnmapLockedPages 要在 <= APC_LEVEL
        MmUnmapLockedPages(mapped, mdl);
        mapped = NULL;
    }

    if (mdl)
    {
        IoFreeMdl(mdl);
        mdl = NULL;
    }

    return status;
}

NTSTATUS MmSafeCopyMemoryEx(
    IN PVOID Destination,
    IN CONST PVOID Source,
    IN SIZE_T Length)
{
    KIRQL oldIrql;
    NTSTATUS status;

    if (!Destination || !Source || Length == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    // 双重保护：spinlock + MmSafeCopyMemory内部的DPC提升
    KeAcquireSpinLock(&g_ssdtLock, &oldIrql);
    status = MmSafeCopyMemoryForNonPaged(Destination, Source, Length);
    KeReleaseSpinLock(&g_ssdtLock, oldIrql);

    return status;
}


KIRQL DisableWP()
{
    KIRQL irql = KeRaiseIrqlToDpcLevel();
    ULONG_PTR cr0 = __readcr0();
#ifdef _AMD64_        
    cr0 &= 0xfffffffffffeffff;
#else
    cr0 &= 0xfffeffff;
#endif
    __writecr0(cr0);
    _disable();    // Disable interrupts
    return irql;
}

void EnableWP(KIRQL irql)
{
    ULONG_PTR cr0 = __readcr0();
    cr0 |= 0x10000;
    _enable();		// Enable interrupts
    __writecr0(cr0);
    KeLowerIrql(irql);
}

NTSTATUS PsLookupProcessByNameA(_In_ const char* targetName, _Out_ PEPROCESS* outProcess)
{
    if (!targetName || !outProcess)
        return STATUS_INVALID_PARAMETER;

    NTSTATUS status;
    ULONG bufferSize = 0x10000;
    PVOID buffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'prcL');

    if (!buffer)
        return STATUS_INSUFFICIENT_RESOURCES;

    status = ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, NULL);
    if (!NT_SUCCESS(status))
    {
        ExFreePool(buffer);
        return status;
    }

    PSYSTEM_PROCESS_INFORMATION spi = (PSYSTEM_PROCESS_INFORMATION)buffer;
    while (TRUE)
    {
        if (spi->ImageName.Buffer)
        {
            CHAR imageNameA[260] = { 0 };
            size_t len = spi->ImageName.Length / sizeof(WCHAR);
            for (size_t i = 0; i < len && i < sizeof(imageNameA) - 1; ++i)
                imageNameA[i] = (CHAR)spi->ImageName.Buffer[i];

            if (_stricmp(imageNameA, targetName) == 0)
            {
                // 找到目标进程，使用 PID 获取 EPROCESS
                status = PsLookupProcessByProcessId(spi->UniqueProcessId, outProcess);
                ExFreePool(buffer);
                return status;
            }
        }

        if (spi->NextEntryOffset == 0)
            break;

        spi = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)spi + spi->NextEntryOffset);
    }

    ExFreePool(buffer);
    return STATUS_NOT_FOUND;
}

NTSTATUS GetProcessIdByName(OUT PHANDLE pPid, PCWSTR targetProcessName)
{
    if (!pPid || !targetProcessName) return STATUS_INVALID_PARAMETER;

    NTSTATUS status;
    ULONG bufferSize = 0x10000;
    PVOID buffer = NULL;

    do
    {
        buffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'pidf');
        if (!buffer) return STATUS_INSUFFICIENT_RESOURCES;

        status = ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, NULL);
        if (status == STATUS_INFO_LENGTH_MISMATCH)
        {
            ExFreePool(buffer);
            bufferSize *= 2;
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status))
    {
        if (buffer) ExFreePool(buffer);
        return status;
    }

    PSYSTEM_PROCESS_INFORMATION pInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;

    while (TRUE)
    {
        if (pInfo->ImageName.Buffer)
        {
            if (wcsstr(pInfo->ImageName.Buffer, targetProcessName))
            {
                *pPid = pInfo->UniqueProcessId;
                ExFreePool(buffer);
                return STATUS_SUCCESS;
            }
        }

        if (pInfo->NextEntryOffset == 0) break;
        pInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pInfo + pInfo->NextEntryOffset);
    }

    ExFreePool(buffer);
    return STATUS_NOT_FOUND;
}

// Helper: RVA转文件偏移
ULONG RvaToOffset(PIMAGE_NT_HEADERS NtHeaders, ULONG Rva, ULONG FileSize)
{
    PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeaders);
    USHORT i;

    for (i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++)
    {
        ULONG SectionVA = Section[i].VirtualAddress;
        ULONG SectionSize = Section[i].SizeOfRawData;

        if (Rva >= SectionVA && Rva < SectionVA + SectionSize)
        {
            ULONG delta = Rva - SectionVA;
            if (delta > Section[i].SizeOfRawData)
            {
                DebugMessage("RvaToOffset: delta > SizeOfRawData\n");
                return ERROR_VALUE;
            }
            if (Section[i].PointerToRawData + delta > FileSize)
            {
                DebugMessage("RvaToOffset: Offset out of file size\n");
                return ERROR_VALUE;
            }

            return Section[i].PointerToRawData + delta;
        }
    }
    DebugMessage("RvaToOffset: No matching section found\n");
    return ERROR_VALUE;
}


NTSTATUS MyProtectVirtualMemory(
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect)
{
    UNICODE_STRING funcName;
    PFN_MmProtectVirtualMemory pfnMmProtectVirtualMemory;

    RtlInitUnicodeString(&funcName, L"MmProtectVirtualMemory");
    pfnMmProtectVirtualMemory = (PFN_MmProtectVirtualMemory)MmGetSystemRoutineAddress(&funcName);

    if (pfnMmProtectVirtualMemory == NULL)
    {
        return STATUS_NOT_IMPLEMENTED;
    }

    return pfnMmProtectVirtualMemory(BaseAddress, RegionSize, NewProtect, OldProtect);
}