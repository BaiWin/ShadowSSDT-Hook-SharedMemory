#pragma once
#include "KernelIncludes.h"

NTSTATUS ReadPhysical(PEPROCESS Process, ULONG64 Address, PVOID Buffer, SIZE_T Length, ULONG64 BaseVA);

ULONG64 GetCachedCr3(PEPROCESS Process, ULONG64 BaseVA);

ULONG64 SearchRealCr3(ULONG64 GameBaseVirtualAddress);

ULONG64 TranslateToPhysical(ULONG64 VA, ULONG64 Base);

ULONG64 TableEntry(ULONG64 PA);