#pragma once
#include "KernelIncludes.h"

NTSTATUS MmSafeCopyMemoryForNonPaged(
    IN PVOID Destination,
    IN CONST PVOID Source,
    IN SIZE_T Length);

NTSTATUS MmSafeCopyMemoryEx(
    IN PVOID Destination,
    IN CONST PVOID Source,
    IN SIZE_T Length);

KIRQL DisableWP();

void EnableWP(KIRQL irql);

typedef struct _SYSTEM_PROCESS_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER Reserved[3];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    // ... 省略其余字段
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;



NTSTATUS PsLookupProcessByNameA(_In_ const char* targetName, _Out_ PEPROCESS* outProcess);

NTSTATUS GetProcessIdByName(OUT PHANDLE pPid, PCWSTR targetProcessName);

ULONG RvaToOffset(PIMAGE_NT_HEADERS NtHeaders, ULONG Rva, ULONG FileSize);

typedef NTSTATUS(*PFN_MmProtectVirtualMemory)(
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect
    );

NTSTATUS MyProtectVirtualMemory(
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect);


#ifdef __cplusplus
extern "C" {
#endif

    NTSYSAPI
        NTSTATUS
        NTAPI
        ZwQuerySystemInformation(
            ULONG SystemInformationClass,
            PVOID SystemInformation,
            ULONG SystemInformationLength,
            PULONG ReturnLength
        );                    //必须声明，虽然导出，但编译器需要签名。// 声明是为了告诉链接器“这个符号在运行时存在”

    /*NTSYSAPI
        NTSTATUS
        NTAPI
        MmProtectVirtualMemory(
            IN PVOID* BaseAddress,
            IN OUT PSIZE_T NumberOfBytes,
            IN ULONG NewProtect,
            OUT PULONG OldProtect
        );*/              //声明也没用，根本没导出，链接器找不到符号

#ifdef __cplusplus
}
#endif

#define SystemProcessInformation 5
