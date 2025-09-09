#pragma once
#include "KernelIncludes.h"

#pragma pack(push,1)        // This is important! ShellCode必须取消结构对齐

typedef struct HOOKOPCODES
{
#ifdef _WIN64
    unsigned short int mov;
#else
    unsigned char mov;
#endif
    ULONG_PTR addr;
    unsigned char push;
    unsigned char ret;
}HOOKOPCODES;
#pragma pack(pop)

typedef struct HOOKSTRUCT
{
    ULONG_PTR addr;
    HOOKOPCODES hook;
    unsigned char orig[sizeof(HOOKOPCODES)];
    //SSDT extension
    int SSDTindex;
    LONG SSDTold;
    LONG SSDTnew;
    PLONG SSDTOffsetPointer;
    ULONG_PTR SSDTFunctionAddress;
}HOOK, * PHOOK;

extern PHOOK hook;

void AllocateHookStruct(ULONG_PTR addr);