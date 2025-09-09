#include "KernelIncludes.h"

UNICODE_STRING g_DriverName;
UNICODE_STRING g_DriverPath;

NTSTATUS CopyShadowSSDTToStructure(PSHARED_MEMORY_DATA data)
{
    static PSHARED_MEMORY_TABLE_SHADOW g_KeServiceDescriptorTableShadow = { NULL };

    if (data == NULL)
    {
        DbgPrint("[W11Kernel] Invalid parameter: data is NULL\n");
        return STATUS_INVALID_PARAMETER;
    }

    if (g_KeServiceDescriptorTableShadow == NULL)
    {
        g_KeServiceDescriptorTableShadow = (PSHARED_MEMORY_TABLE_SHADOW)FindKeServiceDescriptorTableShadow();  // win32k.sys
        if (g_KeServiceDescriptorTableShadow == NULL)
        {
            DbgPrint("[W11Kernel] Failed to find KeServiceDescriptorTableShadow\n");
            return STATUS_UNSUCCESSFUL;
        }
        DbgPrint("[W11Kernel] KeServiceDescriptorTableShadow found at %p\n", g_KeServiceDescriptorTableShadow);
    }

    PSHARED_MEMORY_TABLE mainTable = &g_KeServiceDescriptorTableShadow->Table[0]; // SSDT
    PSHARED_MEMORY_TABLE shadowTable = &g_KeServiceDescriptorTableShadow->Table[1];
    if (mainTable == NULL || mainTable->ServiceTableBase == NULL ||
        shadowTable == NULL || shadowTable->ServiceTableBase == NULL)
    {
        DbgPrint("[W11Kernel] MainTable or ShadowTable is invalid\n");
        return STATUS_INVALID_PARAMETER;
    }

    SIZE_T mainTableSize = mainTable->NumberOfServices * sizeof(PULONG_PTR);
    SIZE_T shadowTableSize = shadowTable->NumberOfServices * sizeof(PULONG_PTR);
    SIZE_T mainParamSize = mainTable->NumberOfServices * sizeof(UCHAR);
    SIZE_T shadowParamSize = shadowTable->NumberOfServices * sizeof(UCHAR);
    SIZE_T totalTableSize = mainTableSize + shadowTableSize;
    SIZE_T totalParamSize = mainParamSize + shadowParamSize;

    // 拷贝 SSDT (Table[0])
    data->SystemTable.Table[0].NumberOfServices = mainTable->NumberOfServices;
    data->SystemTable.Table[0].ServiceCounterTableBase = mainTable->ServiceCounterTableBase;
    data->SystemTable.Table[0].ServiceTableBase = (PULONG_PTR)mainTable->ServiceTableBase;
    data->SystemTable.Table[0].ParamTableBase = mainTable->ParamTableBase;

    // 拷贝 Shadow SSDT (Table[1])
    data->SystemTable.Table[1].NumberOfServices = shadowTable->NumberOfServices;
    data->SystemTable.Table[1].ServiceCounterTableBase = shadowTable->ServiceCounterTableBase;
    data->SystemTable.Table[1].ServiceTableBase = (PULONG_PTR)(shadowTable->ServiceTableBase);
    data->SystemTable.Table[1].ParamTableBase = shadowTable->ParamTableBase;

    // 初始化虚假链表
    RtlZeroMemory(&data->FakeListEntry, sizeof(LIST_ENTRY));

    // 随机填充 Reserved1 和 Reserved2
    LARGE_INTEGER currentTime;
    KeQuerySystemTime(&currentTime);
    ULONG seed = currentTime.LowPart; // 使用时间低 32 位作为种子
    for (ULONG i = 0; i < sizeof(data->Reserved1); i++)
        data->Reserved1[i] = (UCHAR)RtlRandom(&seed);
    for (ULONG i = 0; i < sizeof(data->Reserved2); i++)
        data->Reserved2[i] = (UCHAR)RtlRandom(&seed);

    // 初始化自定义字段（无加密）
    /*data->Signature = SHARED_MEMORY_SIGNATURE;
    InterlockedExchange(&data->Lock, 0);
    data->ClientPid = (ULONG)PsGetCurrentProcessId();
    data->TargetPid = 0;
    InterlockedExchange(&data->CommandPackSize, 0);
    data->currentBufferIndex = 0;
    data->DataSize = 0;*/

    // 清空 commandPacks 和 Buffer
    RtlZeroMemory(data->commandPacks, sizeof(data->commandPacks));
    RtlZeroMemory(data->Buffer, sizeof(data->Buffer));

    // 防检测：模拟系统行为
    volatile ULONG dummy = data->SystemTable.Table[0].NumberOfServices +
        data->SystemTable.Table[1].NumberOfServices;
    UNREFERENCED_PARAMETER(dummy);

    DbgPrint("[W11Kernel] SSDT copied: %lu services, Shadow SSDT copied: %lu services\n",
        data->SystemTable.Table[0].NumberOfServices,
        data->SystemTable.Table[1].NumberOfServices);
    return STATUS_SUCCESS;
}

//NTSTATUS DriverInfoDisguise(PDRIVER_OBJECT DriverObject)
//{
//    static UNICODE_STRING g_DriverName;
//    static UNICODE_STRING g_DriverPath;
//
//    // 保存原始驱动名称和路径
//    RtlInitUnicodeString(&g_DriverName, L"W11Kernel.sys"); // 你的驱动名
//    RtlInitUnicodeString(&g_DriverPath, L"\\SystemRoot\\System32\\drivers\\W11Kernel.sys");
//
//    // 获取 LDR_DATA_TABLE_ENTRY
//    PLDR_DATA_TABLE_ENTRY ldrEntry = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
//    if (ldrEntry == NULL)
//    {
//        DbgPrint("[W11Kernel] Failed to get LDR_DATA_TABLE_ENTRY\n");
//        return STATUS_UNSUCCESSFUL;
//    }
//
//    // 保存原始名称（用于卸载或调试）
//    UNICODE_STRING originalBaseName;
//    UNICODE_STRING originalFullName;
//    RtlInitUnicodeString(&originalBaseName, ldrEntry->BaseDllName.Buffer);
//    RtlInitUnicodeString(&originalFullName, ldrEntry->FullDllName.Buffer);
//
//    // 修改为 ntoskrnl.exe
//    RtlInitUnicodeString(&ldrEntry->BaseDllName, L"ntoskrnl.exe");
//    RtlInitUnicodeString(&ldrEntry->FullDllName, L"\\SystemRoot\\System32\\ntoskrnl.exe");
//}
//
//NTSTATUS DriverInfoUndisguise(PDRIVER_OBJECT DriverObject)
//{
//    // 恢复 LDR_DATA_TABLE_ENTRY（防止异常）
//    PLDR_DATA_TABLE_ENTRY ldrEntry = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
//    if (ldrEntry != NULL)
//    {
//        RtlInitUnicodeString(&ldrEntry->BaseDllName, g_DriverName.Buffer);
//        RtlInitUnicodeString(&ldrEntry->FullDllName, g_DriverPath.Buffer);
//    }
//}