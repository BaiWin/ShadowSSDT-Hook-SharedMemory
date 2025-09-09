#include "KernelIncludes.h"

// ----------------- 声明全局变量 -----------------
PSERVICE_DESCRIPTOR_TABLE_SHADOW g_KeServiceDescriptorTableShadow = NULL;

extern NTSTATUS MyNtUserGetListBoxInfo();

ULONG index = 0xFFFFFFFF; // 无效索引标记

PUCHAR ntBase = NULL;

BOOLEAN hook_sucess = FALSE;

NTSTATUS InitShadowSSDT()
{
    if (g_KeServiceDescriptorTableShadow == NULL)
    {
        g_KeServiceDescriptorTableShadow = (PSERVICE_DESCRIPTOR_TABLE_SHADOW)FindKeServiceDescriptorTableShadow();  // win32k.sys
        if (g_KeServiceDescriptorTableShadow == NULL)
        {
            DbgPrint("[W11Kernel] Failed to find KeServiceDescriptorTableShadow\n");
            return STATUS_UNSUCCESSFUL;
        }
        DbgPrint("[W11Kernel] KeServiceDescriptorTableShadow found at %p\n", g_KeServiceDescriptorTableShadow);
    }

    if (index == ERROR_VALUE)
    {
        index = GetSyscallIndex("NtUserGetListBoxInfo"); // find in ntdll   //
        if (index == (ULONG)-1)
        {
            DbgPrint("[W11Kernel] Failed to get syscall index.\n");
            return STATUS_UNSUCCESSFUL;
        }
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[+] Syscall Index: 0x%X\n", index);
    }

    // Shadow SSDT 基址
    PVOID W32pServiceTable = g_KeServiceDescriptorTableShadow->Table[1].ServiceTableBase;
    if (W32pServiceTable == NULL)
    {
        DbgPrint("W32pServiceTable is NULL\n");
        return STATUS_INVALID_PARAMETER;
    }

    UNICODE_STRING win32kName = RTL_CONSTANT_STRING(L"win32k.sys");
    UNICODE_STRING ntoskrnlName = RTL_CONSTANT_STRING(L"ntoskrnl.exe");
    /*IMAGE_SECTION_HEADER* dataSectionHeader = GetModuleSectionHeader(&ntoskrnlName,".data");
    if (dataSectionHeader)
    {
        DbgPrint("Section .text of win32k.sys found at offset: 0x%X\n", dataSectionHeader->VirtualAddress);
    }

    PVOID dataSectionVA = (PUCHAR)ntBase + dataSectionHeader->VirtualAddress;
    SIZE_T dataSectionSize = max(dataSectionHeader->Misc.VirtualSize, dataSectionHeader->SizeOfRawData);

    PVOID nopAddress = FindNopBytes(dataSectionVA, dataSectionSize, sizeof(HOOKOPCODES));

    if (nopAddress == NULL)
    {
        DbgPrint("[+] ntBase: 0x%p\n", ntBase);
        DbgPrint("[+] VirtualAddress: 0x%p\n", dataSectionHeader->VirtualAddress);
        DbgPrint("[+] dataSectionVA: 0x%p\n", dataSectionVA);
        DbgPrint("[+] dataSectionSize: 0x%llx (%llu)\n", dataSectionSize, dataSectionSize);
        DbgPrint("[+] HOOKOPCODESSize: 0x%llx (%llu)\n", sizeof(HOOKOPCODES), sizeof(HOOKOPCODES));
        DbgPrint("[+] dataNopAddress: 0x%p\n", nopAddress);
        return STATUS_UNSUCCESSFUL;
    }*/

    PVOID sectionGap = GetModuleSectionGap(&win32kName);
    if (sectionGap == NULL)
    {
        DbgPrint("Failed to fetch section gap information.\n");
        return STATUS_UNSUCCESSFUL;
    }

    if (MmIsAddressValid(sectionGap) == FALSE)
    {
        DbgPrint("Destination is not valid!\n");
        return STATUS_ACCESS_VIOLATION;
    }

    AllocateHookStruct((ULONG_PTR)sectionGap);
    if(hook == NULL)
        return STATUS_UNSUCCESSFUL;

    //set original data
    //RtlCopyMemory(&hook->orig, (const void*)nopAddress, sizeof(HOOKOPCODES));
    RtlCopyMemory(&hook->orig, (const PVOID)sectionGap, sizeof(HOOKOPCODES));

    //MmSafeCopyMemory((void*)nopAddress, &hook->hook, sizeof(HOOKOPCODES));  // set shellcode
    MmSafeCopyMemoryEx(sectionGap, &hook->hook, sizeof(HOOKOPCODES));

    LONG oldOffset = ((PLONG)W32pServiceTable)[index];
    //LONG newOffset = (LONG)((ULONG_PTR)nopAddress - (ULONG_PTR)W32pServiceEntries);
    LONG newOffset = (LONG)((ULONG_PTR)sectionGap - (ULONG_PTR)W32pServiceTable);
    newOffset = ((newOffset << 4) | (oldOffset & 0xF));

    ULONG_PTR realNtFunction = (oldOffset >> 4) + (ULONG_PTR)W32pServiceTable;

    hook->SSDTold = oldOffset;
    hook->SSDTnew = newOffset;
    hook->SSDTindex = index;
    hook->SSDTOffsetPointer = &((PLONG)W32pServiceTable)[index];
    hook->SSDTFunctionAddress = realNtFunction;

    MmSafeCopyMemoryEx(hook->SSDTOffsetPointer, &newOffset, sizeof(newOffset)); // hook offset -> shellcode offset

    LONG afterOffset = ((PLONG)W32pServiceTable)[index];
    DbgPrint("[+] W32pServiceTable[%u] after write = 0x%X\n", index, afterOffset);
    DbgPrint("[+] Expected newOffset = 0x%X, oldOffset = 0x%X\n", newOffset, oldOffset);

    hook_sucess = TRUE;

    return STATUS_SUCCESS;
}

VOID RestoreShadowSSDT()
{
    if (!hook_sucess) return;

    if (!hook || !MmIsAddressValid(hook)) return;

    MmSafeCopyMemoryEx(hook->SSDTOffsetPointer, &hook->SSDTold, sizeof(hook->SSDTold));

    MmSafeCopyMemoryEx((PVOID)(hook->addr), &hook->orig, sizeof(HOOKOPCODES));

    ExFreePoolWithTag(hook, 'kooH');
    hook = NULL;  // 重要：将指针置NULL

    DbgPrint("[W11Kernel] Shadow SSDT unhooked.\n");
}

NTSTATUS UnhookShadowSSDT()
{
    PEPROCESS winlogonProcess = NULL;
    HANDLE pid = NULL;
    if (!NT_SUCCESS(GetProcessIdByName(&pid, L"winlogon.exe")))
        return STATUS_UNSUCCESSFUL;

    NTSTATUS status = PsLookupProcessByProcessId(pid, &winlogonProcess);
    if (!NT_SUCCESS(status) || !winlogonProcess)
        return STATUS_UNSUCCESSFUL;

    KAPC_STATE apcState;
    KeStackAttachProcess(winlogonProcess, &apcState);

    RestoreShadowSSDT();

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(winlogonProcess);

    return STATUS_SUCCESS;
}

NTSTATUS HookShadowSSDT()
{
    PEPROCESS winlogonProcess = NULL;
    HANDLE pid = NULL;
    if (!NT_SUCCESS(GetProcessIdByName(&pid, L"winlogon.exe")))
    {
        DbgPrint("[W11Kernel] Failed to find pid\n");
        return STATUS_UNSUCCESSFUL;
    }
    NTSTATUS status = PsLookupProcessByProcessId(pid, &winlogonProcess);
    if (!NT_SUCCESS(status) || !winlogonProcess)
    {
        DbgPrint("[W11Kernel] Failed to find winlogon.exe\n");
        return STATUS_UNSUCCESSFUL;
    }

    KAPC_STATE apcState;
    KeStackAttachProcess(winlogonProcess, &apcState);

    InitShadowSSDT();

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(winlogonProcess);

    return STATUS_SUCCESS;
}