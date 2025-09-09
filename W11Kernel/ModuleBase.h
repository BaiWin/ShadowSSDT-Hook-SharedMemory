#pragma once
#include "KernelIncludes.h"

#define SystemModuleInformation 11

typedef struct _SYSTEM_MODULE_ENTRY
{
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
    ULONG ModulesCount;
    SYSTEM_MODULE_ENTRY Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef struct _SERVICE_DESCRIPTOR_TABLE
{
    PULONG_PTR ServiceTableBase;
    PULONG_PTR ServiceCounterTableBase; // optional
    ULONG_PTR NumberOfServices;
    PUCHAR ParamTableBase;
} SERVICE_DESCRIPTOR_TABLE, * PSERVICE_DESCRIPTOR_TABLE;

typedef struct _SERVICE_DESCRIPTOR_TABLE_SHADOW
{
    SERVICE_DESCRIPTOR_TABLE Table[2]; // Table[1] = win32k!W32pServiceTable   //g_KeServiceDescriptorTableShadow->Table[1].ServiceTableBase;
} SERVICE_DESCRIPTOR_TABLE_SHADOW, * PSERVICE_DESCRIPTOR_TABLE_SHADOW;

PVOID GetModuleBaseByName(PCUNICODE_STRING moduleName, SIZE_T* pSize);
IMAGE_SECTION_HEADER* GetModuleSectionHeader(PCUNICODE_STRING moduleName, const char* sectionName);
PVOID GetModuleSectionGap(PCUNICODE_STRING moduleName);
BOOLEAN CheckMemoryProtection(PVOID addr, SIZE_T size);
IMAGE_SECTION_HEADER* RvaToSection(PVOID base, ULONG rva);
PVOID FindNopBytes(PVOID start, SIZE_T size, SIZE_T nopSize);
PVOID FindKeServiceDescriptorTableShadow();
ULONG GetSyscallIndex(_In_ PCSTR ExportName);

extern PUCHAR ntBase;