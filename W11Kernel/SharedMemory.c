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
        DebugMessage("Failed to get shared memory address\n");
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    // 验证共享内存结构
    if (pSharedData->Signature != EncryptedSignature(SHARED_MEMORY_SIGNATURE))
    {
        DebugMessage("Invalid shared memory signature!\n");
        return STATUS_INVALID_SIGNATURE;
    }

    DebugMessage("Shared memory successfully connected at: 0x%p\n", pSharedData);

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
        DebugMessage("Return by ShareData null!\n");
        return STATUS_INVALID_ADDRESS;
    }
        
    InsertJunkCode(2);
    if (InterlockedCompareExchange(&pSharedData->Lock, 1, 0) == 1)
    {
        DebugMessage("Return by lock!\n");
        return STATUS_SUCCESS;
    }

    InsertJunkCode(3);
    // 验证签名
    if (pSharedData->Signature != EncryptedSignature(SHARED_MEMORY_SIGNATURE))
    {
        InsertJunkCode(4);
        DebugMessage("Invalid signature!\n");
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
        DebugMessage("Failed to find client process: %lu (0x%X)\n", ClientPid, status);
        status = STATUS_SUCCESS; 
        goto Cleanup;
    }

    status = PsLookupProcessByProcessId((HANDLE)TargetPid, &targetProcess);
    if (!NT_SUCCESS(status) || targetProcess == NULL)
    {
        DebugMessage("Failed to find target process: %lu (0x%X)\n", TargetPid, status);
        // 已成功获取 clientProcess，需要释放
        status = STATUS_SUCCESS;
        goto Cleanup; //客户端还没关闭，只是没传目标进程pid，依然返回成功
    }

    // 写之前确保缓冲区正确
    currentWriteBufferIndex = (pSharedData->currentBufferIndex == 0) ? 1 : 0;

    DecryptField((ULONG*)&pSharedData->CommandPackSize);
    if (pSharedData->CommandPackSize > MAX_COMMAND_COUNT)
    {
        DebugMessage("[W11Kernel] Invalid CommandPackSize: %lu\n", pSharedData->CommandPackSize);
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

        DebugMessage("[W11Kernel] CommandPackSize: %lu\n", pSharedData->CommandPackSize);
        for (ULONG i = 0; i < pSharedData->CommandPackSize; i++)
        {
            COMMAND_PACKET cmd = pSharedData->commandPacks[i];

            DecryptCommandPack(&cmd);

            DebugMessage("[W11Kernel] CMD Type: %lu\n", cmd.Type);
            DebugMessage("[W11Kernel] CMD Address: 0x%p\n", (PVOID)cmd.Address);
            DebugMessage("[W11Kernel] CMD Size: %lu\n", cmd.Size);

            // 处理单个命令
            writeOffset = ProcessReceivedCommand(clientProcess, targetProcess, &cmd, pSharedData, writeOffset, i);
            DebugMessage("[W11Kernel] CurrentWriteOffset: %lu\n", writeOffset);
        }

        if (writeOffset > BUFFER_SIZE)
        {
            DebugMessage("[W11Kernel] WriteOffset Excced Max Size: %lu\n", writeOffset);
            writeOffset = BUFFER_SIZE;
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

        currentWriteBufferIndex = (pSharedData->currentBufferIndex == 0) ? 1 : 0;  // 当前写的缓冲切换
    }
    EncryptField((ULONG*)&pSharedData->CommandPackSize); // 上面DecryptField((ULONG*)&pSharedData->CommandPackSize);对应

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

    static PVOID targetProcessAddress = 0;

    if (writeOffset > BUFFER_SIZE)
    {
        DebugMessage("ProcessReceivedCommand: writeOffset (%lu) exceeds BUFFER_SIZE (%lu), skipping command index %lu\n",
            writeOffset, BUFFER_SIZE, index);
        return writeOffset;
    }

    //static ULONG_PTR processStart = { 0 };
    //static ULONG_PTR processEnd = { 0 };

    switch (cmd->Type)
    {
    case CMD_MODULE_BASE:
    {
        //PPEB peb = NULL;
        //ULONG moduleSize = 0;
        //peb = PsGetProcessPeb(targetProcess); // targetProcess 是 PEPROCESS
        //KAPC_STATE apcState;
        //KeStackAttachProcess(targetProcess, &apcState);
        //if (peb != NULL)
        //{
        //    __try
        //    {
        //        ProbeForRead(peb, sizeof(PEB), sizeof(ULONG));
        //        moduleSize = peb->SizeOfImage; // 主模块大小
        //    }
        //    __except (EXCEPTION_EXECUTE_HANDLER)
        //    {
        //        DebugMessage("[W11Kernel] CMD_MODULE_BASE: Exception accessing PEB\n");
        //        moduleSize = 0;
        //    }
        //}
        //else
        //{
        //    DebugMessage("[W11Kernel] CMD_MODULE_BASE: PEB is NULL\n");
        //}
        //KeUnstackDetachProcess(&apcState);

        PVOID baseAddress = PsGetProcessSectionBaseAddress(targetProcess);

        PVOID destAddr = buffer + writeOffset;

        //processStart = (ULONG_PTR)baseAddress;
        //processEnd = (ULONG_PTR)((ULONG_PTR)baseAddress + moduleSize);
        DebugMessage("CMD_MODULE_BASE_START: baseAddress = 0x%p\n", baseAddress);
        //DebugMessage("CMD_MODULE_BASE_START: baseAddress = 0x%p\n", (PVOID)processStart);
        //DebugMessage("CMD_MODULE_BASE_END: baseAddress = 0x%p\n", (PVOID)processEnd);
        //DebugMessage("CMD_MODULE_BASE: destAddr = 0x%p, writeOffset = %lu\n", destAddr, writeOffset);
        targetProcessAddress = baseAddress;

        RtlCopyMemory(destAddr, &baseAddress, sizeof(baseAddress));

        writeOffset += cmd->Size;
        break;
    }

    case CMD_READ_MEMORY:
    {
        if (cmd->Size == 0)
        {
            DebugMessage("Invalid size in CMD_READ_MEMORY\n");
            break;
        }

        ULONG rawWriteOffset = writeOffset;
        writeOffset += cmd->Size;

        PVOID sourceAddr = NULL;
        PVOID destAddr = buffer + rawWriteOffset;
        //DebugMessage("writeOffset : 0x%X\n", rawWriteOffset);
        //DebugMessage("address : 0x%p\n", (PVOID)cmd->Address);

        if (cmd->Address > MAX_COMMAND_COUNT)  // 最多512个包
        {
            if (cmd->Address > MM_USER_PROBE_ADDRESS)
            {
                DebugMessage("Invalid address detected from CMD_READ Absolute: 0x%p, i = %lu\n", (PVOID)cmd->Address, index);
                break;
            }

            sourceAddr = (PVOID)(cmd->Address + cmd->Offset);
        }
        else
        {
            // Address 是 PackOffset，计算真实地址
            ULONG packOffset = cmd->Address;
            if (packOffset > 0 && packOffset <= pSharedData->CommandPackSize)
            {
                // 从前一个结果里取地址值
                PVOID baseAddr = NULL;
                RtlCopyMemory(
                    &baseAddr,
                    buffer + GetOffsetOfResult(pSharedData, index, packOffset, rawWriteOffset),
                    sizeof(PVOID));

                if (baseAddr == NULL || (ULONG_PTR)baseAddr > MM_USER_PROBE_ADDRESS)
                {
                    DebugMessage("Invalid address detected from CMD_READ Pack Offset: 0x%p, i = %lu\n", baseAddr, index);
                    break;
                }

                sourceAddr = (PVOID)((ULONG_PTR)baseAddr + cmd->Offset);

                /*DebugMessage("CMD_READ_MEMORY: baseAddr = 0x%p, offset = 0x%X, sourceAddr = 0x%p\n",
                    baseAddr,
                    cmd->Offset,
                    sourceAddr);*/
            }
        }

        static UCHAR tempBuffer[0x400] = { 0 };
        RtlZeroMemory(tempBuffer, sizeof(tempBuffer));

        status = ReadPhysical(targetProcess, (ULONG64)sourceAddr, tempBuffer, cmd->Size, (ULONG64)targetProcessAddress);

        // 共享内存是在内核空间，但不属于进程页表里的有效用户或内核页
        /*status = MmCopyVirtualMemory(
            targetProcess,
            sourceAddr,
            PsGetCurrentProcess(),
            tempBuffer,
            cmd->Size,
            KernelMode,
            &bytes
        );*/

        //ULONG64 user_cr3 = *(ULONG64*)((PUCHAR)targetProcess + 0x158);
        //ULONG64 directory_cr3 = *(ULONG64*)((PUCHAR)targetProcess + 0x28);

        //if (user_cr3 != directory_cr3) status = STATUS_TOO_MANY_SECRETS;

        //RtlCopyMemory(buffer + rawWriteOffset, &directory_cr3, cmd->Size);

        //if (NT_SUCCESS(status) && bytes == cmd->Size)
        if (NT_SUCCESS(status))
        {
            // 安全写回共享内存（用户可映射）
            RtlCopyMemory(buffer + rawWriteOffset, tempBuffer, cmd->Size);
            //rawWriteOffset += cmd->Size;
        }
        else
        {
            DebugMessage("MmCopyVirtualMemory failed: 0x%X, requested=%lu\n",
                status, cmd->Size);

            RtlCopyMemory(buffer + rawWriteOffset, &status, sizeof(status));
        }

        break;
    }

    case CMD_WRITE_MEMORY:
    {
        if (cmd->Size == 0 || cmd->Size > sizeof(cmd->Value))
        {
            DebugMessage("Invalid size in CMD_WRITE_MEMORY\n");
            break;
        }

        PVOID sourceAddr = NULL;
        PVOID destAddr = buffer + writeOffset;
        if (cmd->Address > MAX_COMMAND_COUNT)  // 最多512个包
        {
            if (cmd->Address > MM_USER_PROBE_ADDRESS)
            {
                DebugMessage("Invalid address detected from CMD_WRITE: 0x%p\n", (PVOID)cmd->Address);
                break;
            }
            sourceAddr = (PVOID)(cmd->Address + cmd->Offset);
        }
        else
        {
            // Address 是 PackOffset，计算真实地址
            ULONG packOffset = (ULONG)cmd->Address;
            if (packOffset > 0 && packOffset <= pSharedData->CommandPackSize)
            {
                // 从前一个结果里取地址值
                PVOID baseAddr = NULL;
                RtlCopyMemory(
                    &baseAddr,
                    buffer + GetOffsetOfResult(pSharedData, index, packOffset, writeOffset),
                    sizeof(PVOID));

                if (baseAddr == NULL || (ULONG_PTR)baseAddr > MM_USER_PROBE_ADDRESS)
                {
                    DebugMessage("Invalid address detected from CMD_READ Pack Offset: 0x%p, i = %lu\n", baseAddr, index);
                    break;
                }

                /*DebugMessage("CMD_WRITE_MEMORY: baseAddr = 0x%p, offset = 0x%X, sourceAddr = 0x%p\n",
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
            DebugMessage("Write memory failed: 0x%X\n", status);
        }
        break;
    }

    case CMD_FILL_EMPTY:
    {
        ULONG seed = (ULONG)__rdtsc();
        for (SIZE_T i = writeOffset; i < cmd->Size; i++)
        {
            buffer[i] = (UCHAR)(RtlRandomEx(&seed) & 0xFF);
        }
        writeOffset += cmd->Size;
        break;
    }

    default:
        DebugMessage("Unknown command type: %u\n", cmd->Type);
        break;
    }

    return writeOffset;
}

ULONG GetOffsetOfResult(PSHARED_MEMORY_DATA pSharedData, ULONG currentIndex, ULONG packOffset, ULONG writeOffset)
{
    ULONG previousWriteOffset = writeOffset;
    DebugMessage("GetOffsetOfResult called: currentIndex=%lu, packOffset=%lu, writeOffset=%lu\n",
        currentIndex, packOffset, writeOffset);

    if (currentIndex >= packOffset && packOffset != 0)
    {
        for (ULONG i = currentIndex - packOffset; i < currentIndex; i++)
        {
            COMMAND_TYPE cmdType = pSharedData->commandPacks[i].Type;
            DecryptField((ULONG*)&cmdType);

            if (!(cmdType == CMD_MODULE_BASE || cmdType == CMD_READ_MEMORY)) continue;

            LONG size = pSharedData->commandPacks[i].Size;
            DecryptField(&size);

            previousWriteOffset -= size;
            DebugMessage("GetOffsetOfResult:  i=%lu, commandSize=%lu, previousWriteOffset=%lu\n",
                i, size, previousWriteOffset);
        }
    }
    DebugMessage("GetOffsetOfResult returning previousWriteOffset=%lu\n", previousWriteOffset);

    if (previousWriteOffset > writeOffset)
    {
        previousWriteOffset = writeOffset;
    }

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
        DebugMessage("[ReleaseSharedData] Shared memory unmapped in kernel\n");
    }
    if (oldSection)
    {
        ZwClose(oldSection);
        DebugMessage("[ReleaseSharedData] Section handle closed\n");
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
        DebugMessage("[GetSharedDataOnce] Invalid signature, releasing\n");
        ReleaseSharedData();
    }

    UNICODE_STRING sectionName;
    WCHAR sharedName[128] = { 0 };
    GenerateSharedMemoryName(sharedName, 128);
    DebugMessage("[GetSharedDataOnce] Kernel sharedName: %ws\n", sharedName);
    RtlInitUnicodeString(&sectionName, sharedName);
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &sectionName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE localhSection = NULL;
    NTSTATUS status = ZwOpenSection(&localhSection, SECTION_MAP_READ | SECTION_MAP_WRITE, &objAttr);
    if (!NT_SUCCESS(status))
    {
        DebugMessage("[GetSharedDataOnce] ERROR: Failed to open section with status 0x%08X\n", status);
        return NULL;
    }

    PVOID localMap = NULL;
    SIZE_T viewSize = SHARED_MEMORY_SIZE;
    status = ZwMapViewOfSection(localhSection, NtCurrentProcess(), &localMap, 0, SHARED_MEMORY_SIZE, NULL, &viewSize, ViewShare, 0, PAGE_READWRITE);
    //ZwClose(localhSection);  // 这里要注释， 不然会被名称会被标记为临时，导致客户端连接不上
    if (!NT_SUCCESS(status) || localMap == NULL)
    {
        DebugMessage("[GetSharedDataOnce] ERROR: ZwMapViewOfSection failed with status 0x%08X\n", status);
        ZwClose(localhSection);
        localhSection = NULL;
        InterlockedExchange(&initialized, 0);
        return NULL;
    }

    PSHARED_MEMORY_DATA tempData = (PSHARED_MEMORY_DATA)localMap;
    if (tempData->Signature != EncryptedSignature(SHARED_MEMORY_SIGNATURE))
    {
        DebugMessage("[GetSharedDataOnce] Invalid shared memory signature, unmapping\n");
        ZwUnmapViewOfSection(NtCurrentProcess(), localMap);
        ZwClose(localhSection);
        localhSection = NULL;
        InterlockedExchange(&initialized, 0);
        return NULL;
    }

    status = CopyShadowSSDTToStructure(tempData);
    if (!NT_SUCCESS(status))
    {
        DebugMessage("[GetSharedDataOnce] ERROR: CopyShadowSSDTToStructure failed with status 0x%08X\n", status);
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
    DebugMessage("[GetSharedDataOnce] Shared memory successfully connected at: 0x%p\n", localMap);
    return *pSharedData;
}