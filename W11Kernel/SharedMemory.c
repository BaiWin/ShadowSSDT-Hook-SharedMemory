#include "KernelIncludes.h"

int currentWriteBufferIndex = 1;

static PSHARED_MEMORY_DATA* GetSharedMemory()
{
    static PSHARED_MEMORY_DATA data = NULL;
    return &data;
}

static HANDLE* GetSectionHandle()
{
    static HANDLE hSection = NULL;
    return &hSection;
}

// 尝试连接共享内存（非阻塞，可重复调用）
NTSTATUS TryConnectSharedMemory()
{
    InsertJunkCodeRND();
    PSHARED_MEMORY_DATA pSharedData = GetSharedDataOnce(); // 使用新的方法
    if (pSharedData == NULL)
    {
        DbgPrint("Failed to get shared memory address\n");
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    // 验证共享内存结构
    if (pSharedData->Signature != EncryptedSignature(SHARED_MEMORY_SIGNATURE))
    {
        DbgPrint("Invalid shared memory signature!\n");
        return STATUS_INVALID_SIGNATURE;
    }

    DbgPrint("Shared memory successfully connected at: 0x%p\n", pSharedData);

    return STATUS_SUCCESS;
}

// 检查并处理数据
NTSTATUS CheckAndProcessCommand()
{
    InsertJunkCodeRND();
    PSHARED_MEMORY_DATA pSharedData = GetSharedDataOnce();
    if (pSharedData == NULL)
    {
        InsertJunkCode(1);
        return STATUS_INVALID_ADDRESS;
    }
        
    InsertJunkCode(2);
    if (InterlockedCompareExchange(&pSharedData->Lock, 1, 0) == 1)
    {
        DbgPrint("Return by lock!\n");
        return STATUS_SUCCESS;
    }

    InsertJunkCode(3);
    // 验证签名
    if (pSharedData->Signature != EncryptedSignature(SHARED_MEMORY_SIGNATURE))
    {
        InsertJunkCode(4);
        DbgPrint("Invalid signature!\n");
        InterlockedExchange(&pSharedData->Lock, 0);
        return STATUS_INVALID_PARAMETER;
    }

    PEPROCESS clientProcess = NULL;
    PEPROCESS targetProcess = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG ClientPid = pSharedData->ClientPid;
    ULONG TargetPid = pSharedData->TargetPid;
    EncryptField(&ClientPid);
    EncryptField(&TargetPid);
    status = PsLookupProcessByProcessId((HANDLE)ClientPid, &clientProcess);
    if (!NT_SUCCESS(status) || clientProcess == NULL)
    {
        DbgPrint("Failed to find client process: %lu (0x%X)\n", ClientPid, status);
        status = STATUS_SUCCESS; 
        goto Cleanup;
    }

    status = PsLookupProcessByProcessId((HANDLE)TargetPid, &targetProcess);
    if (!NT_SUCCESS(status) || targetProcess == NULL)
    {
        DbgPrint("Failed to find target process: %lu (0x%X)\n", TargetPid, status);
        // 已成功获取 clientProcess，需要释放
        status = STATUS_SUCCESS;
        goto Cleanup; //客户端还没关闭，只是没传目标进程pid，依然返回成功
    }

    // 写之前确保缓冲区正确
    currentWriteBufferIndex = (pSharedData->currentBufferIndex == 0) ? 1 : 0;

    DecryptField((ULONG*) & pSharedData->CommandPackSize);
    if (pSharedData->CommandPackSize > MAX_COMMAND_COUNT)
    {
        DbgPrint("[W11Kernel] Invalid CommandPackSize: %lu\n", pSharedData->CommandPackSize);
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }
    // 检测是否有数据
    if (pSharedData->CommandPackSize > 0)
    {
        // 写入位置，从 0 开始
        ULONG writeOffset = 0;
        RtlZeroMemory(                                                             // 写之前先清空
            pSharedData->Buffer[currentWriteBufferIndex],
            BUFFER_SIZE
        );

        for (ULONG i = 0; i < pSharedData->CommandPackSize; i++)
        {
            COMMAND_PACKET cmd = pSharedData->commandPacks[i];

            DecryptCommandPack(&cmd);

            // 处理单个命令
            writeOffset = ProcessReceivedCommand(clientProcess, targetProcess, &cmd, pSharedData, writeOffset, i);
        }

        InsertJunkCodeRND();
        EncryptBuffer(pSharedData->Buffer[currentWriteBufferIndex], writeOffset);

        // 写完以后更新 DataSize
        pSharedData->DataSize = writeOffset;
        EncryptField((ULONG*)&pSharedData->DataSize);

        // 告诉客户端使用另一个缓冲区
        pSharedData->currentBufferIndex = (pSharedData->currentBufferIndex == 0) ? 1 : 0; 

        // 告诉客户端已经执行过了
        pSharedData->CommandPackSize = 0;
        EncryptField((ULONG*)&pSharedData->CommandPackSize);

        currentWriteBufferIndex = (pSharedData->currentBufferIndex == 0) ? 1 : 0;  // 当前写的缓冲切换
    }

Cleanup:
    InsertJunkCodeRND();
    if (clientProcess) ObDereferenceObject(clientProcess);
    if (targetProcess) ObDereferenceObject(targetProcess);
    InterlockedExchange(&pSharedData->Lock, 0);
    return status;
}

// 处理接收到的命令
ULONG ProcessReceivedCommand(
    PEPROCESS clientProcess,
    PEPROCESS targetProcess,
    PCOMMAND_PACKET cmd,
    PSHARED_MEMORY_DATA pSharedData,
    ULONG writeOffset,
    ULONG index
)
{
    NTSTATUS status;
    SIZE_T bytes = 0;

    UCHAR* buffer = pSharedData->Buffer[currentWriteBufferIndex];

    if (writeOffset > BUFFER_SIZE)
    {
        DbgPrint("ProcessReceivedCommand: writeOffset (%lu) exceeds BUFFER_SIZE (%lu), skipping command index %lu\n",
            writeOffset, BUFFER_SIZE, index);
        return writeOffset;
    }

    switch (cmd->Type)
    {
    case CMD_MODULE_BASE:
    {
        PVOID baseAddress = PsGetProcessSectionBaseAddress(targetProcess);

        PVOID destAddr = buffer + writeOffset;

        //DbgPrint("CMD_MODULE_BASE: baseAddress = 0x%p\n", baseAddress);
        //DbgPrint("CMD_MODULE_BASE: destAddr = 0x%p, writeOffset = %lu\n", destAddr, writeOffset);

        RtlCopyMemory(destAddr, &baseAddress, sizeof(baseAddress));

        writeOffset += cmd->Size;
        break;
    }

    case CMD_READ_MEMORY:
    {
        if (cmd->Size == 0)
        {
            DbgPrint("Invalid size in CMD_READ_MEMORY\n");
            break;
        }

        if (cmd->Address >= 0x7FFFFFFFFFFF || cmd->Address == 0)   // Address 0 check
        {
            DbgPrint("Invalid address detected: 0x%p\n", (PVOID)cmd->Address);
            return STATUS_INVALID_ADDRESS;
        }

        PVOID sourceAddr = NULL;
        PVOID destAddr = buffer + writeOffset;
        //DbgPrint("writeOffset : 0x%X\n", writeOffset);
        //DbgPrint("address : 0x%p\n", (PVOID)cmd->Address);

        if (cmd->Address > 0x100)  // 最多256个包
        {
            sourceAddr = (PVOID)(cmd->Address + cmd->Offset);
        }
        else
        {
            // Address 是 PackOffset，计算真实地址
            ULONG packOffset = (ULONG)cmd->Address;
            if (packOffset > 0)
            {
                // 从前一个结果里取地址值
                PVOID baseAddr = NULL;
                RtlCopyMemory(
                    &baseAddr,
                    buffer + GetOffsetOfResult(pSharedData, index, packOffset, writeOffset),
                    sizeof(PVOID));

                if (baseAddr >= 0x7FFFFFFFFFFF || baseAddr == 0)
                {
                    DbgPrint("Invalid Pack Offset address detected: 0x%p\n", baseAddr);
                    return STATUS_INVALID_ADDRESS;
                }

                sourceAddr = (PVOID)((ULONG_PTR)baseAddr + cmd->Offset);

                /*DbgPrint("CMD_READ_MEMORY: baseAddr = 0x%p, offset = 0x%X, sourceAddr = 0x%p\n",
                    baseAddr,
                    cmd->Offset,
                    sourceAddr);*/
            }
        }

        UCHAR tempBuffer[8] = { 0 };

        // 共享内存是在内核空间，但不属于进程页表里的有效用户或内核页
        status = MmCopyVirtualMemory(
            targetProcess,
            sourceAddr,
            PsGetCurrentProcess(),
            tempBuffer,
            cmd->Size,
            KernelMode,
            &bytes
        );

        if (NT_SUCCESS(status) && bytes == cmd->Size)
        {
            // 安全写回共享内存（用户可映射）
            RtlCopyMemory(buffer + writeOffset, tempBuffer, cmd->Size);
            writeOffset += cmd->Size;
        }
        else
        {
            DbgPrint("MmCopyVirtualMemory failed: 0x%X, requested=%lu\n",
                status, cmd->Size);
        }
        break;
    }

    case CMD_WRITE_MEMORY:
    {
        if (cmd->Size == 0 || cmd->Size > sizeof(cmd->Value))
        {
            DbgPrint("Invalid size in CMD_WRITE_MEMORY\n");
            break;
        }

        if (cmd->Address >= 0x7FFFFFFFFFFF || cmd->Address == 0)  // Address 0 check
        {
            DbgPrint("Invalid address detected: 0x%p\n", (PVOID)cmd->Address);
            return STATUS_INVALID_ADDRESS;
        }

        PVOID sourceAddr = NULL;
        PVOID destAddr = buffer + writeOffset;
        if (cmd->Address > 0x100)  // 最多256个包
        {
            sourceAddr = (PVOID)(cmd->Address + cmd->Offset);
        }
        else
        {
            // Address 是 PackOffset，计算真实地址
            ULONG packOffset = (ULONG)cmd->Address;
            if (packOffset > 0)
            {
                // 从前一个结果里取地址值
                PVOID baseAddr = NULL;
                RtlCopyMemory(
                    &baseAddr,
                    buffer + GetOffsetOfResult(pSharedData, index, packOffset, writeOffset),
                    sizeof(PVOID));

                /*DbgPrint("CMD_WRITE_MEMORY: baseAddr = 0x%p, offset = 0x%X, sourceAddr = 0x%p\n",
                    baseAddr,
                    cmd->Offset,
                    sourceAddr);*/

                sourceAddr = (PVOID)((ULONG_PTR)baseAddr + cmd->Offset);
            }
        }

        UCHAR tempBuffer[8] = { 0 };
        RtlCopyMemory(tempBuffer, &cmd->Value, cmd->Size);

        status = MmCopyVirtualMemory(
            PsGetCurrentProcess(),
            tempBuffer,          // 写入值直接来自命令结构
            targetProcess,
            sourceAddr,
            cmd->Size,
            KernelMode,
            &bytes
        );

        if (!NT_SUCCESS(status) || bytes != cmd->Size)
        {
            DbgPrint("Write memory failed: 0x%X\n", status);
        }
        break;
    }

    case CMD_EX_BUFFER:
    {
        currentWriteBufferIndex = 1;
        break;
    }

    default:
        DbgPrint("Unknown command type: %u\n", cmd->Type);
        break;
    }

    return writeOffset;
}

ULONG GetOffsetOfResult(PSHARED_MEMORY_DATA pSharedData, ULONG currentIndex, ULONG packOffset, ULONG writeOffset)
{
    ULONG previousWriteOffset = writeOffset;
    DbgPrint("GetOffsetOfResult called: currentIndex=%lu, packOffset=%lu, writeOffset=%lu\n",
        currentIndex, packOffset, writeOffset);

    if (currentIndex >= packOffset && packOffset != 0)
    {
        for (ULONG i = currentIndex - packOffset; i < currentIndex; i++)
        {
            LONG size = pSharedData->commandPacks[i].Size;
            DecryptField(&size);
            previousWriteOffset -= size;
            DbgPrint("  i=%lu, commandSize=%lu, previousWriteOffset=%lu\n",
                i, size, previousWriteOffset);
        }
    }
    DbgPrint("GetOffsetOfResult returning previousWriteOffset=%lu\n", previousWriteOffset);

    return previousWriteOffset;
}

// 不用 交给客户端清理
// DriverUnload 或停止服务时调用：
// 注意：在调用 ReleaseSharedData 之前，应确保没有 worker thread 在使用共享数据
VOID ReleaseSharedData(void)
{
    PSHARED_MEMORY_DATA* pSharedData = GetSharedMemory();
    HANDLE* hSection = GetSectionHandle();
    static volatile LONG initialized = 0;

    PVOID oldData = InterlockedExchangePointer((PVOID*)&(*pSharedData), NULL);
    HANDLE oldSection = InterlockedExchangePointer((PVOID*)&(*hSection), NULL);
    InterlockedExchange(&initialized, 0);

    if (oldData)
    {
        ZwUnmapViewOfSection(NtCurrentProcess(), oldData);
        DbgPrint("[ReleaseSharedData] Shared memory unmapped in kernel\n");
    }
    if (oldSection)
    {
        ZwClose(oldSection);
        DbgPrint("[ReleaseSharedData] Section handle closed\n");
    }
}

PSHARED_MEMORY_DATA GetSharedDataOnce(void)
{
    static volatile LONG initialized = 0;
    PSHARED_MEMORY_DATA* pSharedData = GetSharedMemory();
    HANDLE* hSection = GetSectionHandle();

    // 快速路径：如果已初始化，直接返回
    if (InterlockedCompareExchange(&initialized, 1, 0) == 1)
    {
        if (*pSharedData && (*pSharedData)->Signature == EncryptedSignature(SHARED_MEMORY_SIGNATURE))
        {
            return *pSharedData;
        }
        DbgPrint("[GetSharedDataOnce] Invalid signature, releasing\n");
        ReleaseSharedData();
    }

    UNICODE_STRING sectionName;
    WCHAR sharedName[128] = { 0 };
    GenerateSharedMemoryName(sharedName, 128);
    DbgPrint("[GetSharedDataOnce] Kernel sharedName: %ws\n", sharedName);
    RtlInitUnicodeString(&sectionName, sharedName);
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &sectionName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE localhSection = NULL;
    NTSTATUS status = ZwOpenSection(&localhSection, SECTION_MAP_READ | SECTION_MAP_WRITE, &objAttr);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[GetSharedDataOnce] ERROR: Failed to open section with status 0x%08X\n", status);
        return NULL;
    }

    PVOID localMap = NULL;
    SIZE_T viewSize = SHARED_MEMORY_SIZE;
    status = ZwMapViewOfSection(localhSection, NtCurrentProcess(), &localMap, 0, SHARED_MEMORY_SIZE, NULL, &viewSize, ViewShare, 0, PAGE_READWRITE);
    //ZwClose(localhSection);  // 这里要注释， 不然会被名称会被标记为临时，导致客户端连接不上
    if (!NT_SUCCESS(status) || localMap == NULL)
    {
        DbgPrint("[GetSharedDataOnce] ERROR: ZwMapViewOfSection failed with status 0x%08X\n", status);
        ZwClose(localhSection);
        localhSection = NULL;
        InterlockedExchange(&initialized, 0);
        return NULL;
    }

    PSHARED_MEMORY_DATA tempData = (PSHARED_MEMORY_DATA)localMap;
    if (tempData->Signature != EncryptedSignature(SHARED_MEMORY_SIGNATURE))
    {
        DbgPrint("[GetSharedDataOnce] Invalid shared memory signature, unmapping\n");
        ZwUnmapViewOfSection(NtCurrentProcess(), localMap);
        ZwClose(localhSection);
        localhSection = NULL;
        InterlockedExchange(&initialized, 0);
        return NULL;
    }

    status = CopyShadowSSDTToStructure(tempData);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[GetSharedDataOnce] ERROR: CopyShadowSSDTToStructure failed with status 0x%08X\n", status);
        ZwUnmapViewOfSection(NtCurrentProcess(), localMap);
        ZwClose(localhSection);
        InterlockedExchange(&initialized, 0);
        return NULL;
    }

    // 原子设置 pSharedData 和 initialized
    PSHARED_MEMORY_DATA prevData = (PSHARED_MEMORY_DATA)InterlockedCompareExchangePointer((PVOID*)&(*pSharedData), localMap, NULL);
    HANDLE prevSection = (HANDLE)InterlockedCompareExchangePointer((PVOID*)&(*hSection), localhSection, NULL);
    if (prevData != NULL)
    {
        ZwUnmapViewOfSection(NtCurrentProcess(), localMap);
        ZwClose(localhSection);
        return prevData;
    }

    InterlockedExchange(&initialized, 1);
    DbgPrint("[GetSharedDataOnce] Shared memory successfully connected at: 0x%p\n", localMap);
    return *pSharedData;
}