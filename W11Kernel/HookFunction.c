#include "KernelIncludes.h"

PHOOK hook = NULL;

NTSTATUS MyNtUserGetListBoxInfo()
{
    DbgPrint("[W11Kernel] NtQueryCompositionSurfaceStatistics was called!\n");

    // 你可以在这里执行一些逻辑，比如触发通信、读取内存、检测等等

    // 调用原始函数
    

    return STATUS_SUCCESS;
}

void AllocateHookStruct(ULONG_PTR addr)
{
    //allocate structure
    hook = (PHOOK)ExAllocatePoolWithTag(NonPagedPool, sizeof(HOOK), 'kooH');
    //set hooking address
    //hook->addr = nopAddress;        // Store the cave address
    hook->addr = addr;
    //set hooking opcode
#ifdef _WIN64
    hook->hook.mov = 0xB848;
#else
    hook->hook.mov = 0xB8;
#endif
    hook->hook.addr = (ULONG_PTR)MyNtUserGetListBoxInfo;    // Insert our own function
    hook->hook.push = 0x50;
    hook->hook.ret = 0xc3;
}