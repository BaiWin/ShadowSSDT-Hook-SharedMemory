#pragma once
#include "KernelIncludes.h"

// 函数声明
NTSTATUS TryConnectSharedMemory();
NTSTATUS CheckAndProcessCommand();
ULONG ProcessReceivedCommand(
	PEPROCESS clientProcess,
	PEPROCESS targetProcess,
	PCOMMAND_PACKET cmd,
	PSHARED_MEMORY_DATA pSharedData,
	ULONG writeOffset,
	ULONG index
);

VOID ReleaseSharedData(void);
PSHARED_MEMORY_DATA GetSharedDataOnce(void);

// 全局变量声明
extern HANDLE g_hSection;
extern PVOID g_pMappedAddress;


NTSTATUS NTAPI MmCopyVirtualMemory
(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);

// PEB structure definition for kernel mode (simplified)
typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	ULONG Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA;

typedef struct _PEB
{
	UCHAR Reserved1[2];
	UCHAR BeingDebugged;
	UCHAR Reserved2[1];
	PVOID Reserved3;
	PEB_LDR_DATA* Ldr;
	// other members can be added here as needed
	ULONG SizeOfImage;  // module size
} PEB;

PVOID PsGetProcessSectionBaseAddress(IN PEPROCESS Process);

ULONG GetOffsetOfResult(PSHARED_MEMORY_DATA pSharedData, ULONG currentIndex, ULONG packOffset, ULONG writeOffset);