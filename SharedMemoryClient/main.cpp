#include <iostream>
#include "ClientIncludes.h"

bool OnFrameStart()
{
    InsertJunkCodeRND();
    ResetSequence();
    ResetBufferReadStart();
    MemoryBarrier();
    PSHARED_MEMORY_DATA pSharedData = GetSharedDataOnce();
    InsertJunkCode(1);
    if (InterlockedCompareExchange(&pSharedData->Lock, 1, 0) == 1)
    {
        InsertJunkCode(2);
        return false;
    }
    // 初始化，待赋值
    pSharedData->ClientPid = 0;
    pSharedData->TargetPid = 0;
    pSharedData->CommandPackSize = 0;
    RtlZeroMemory(&pSharedData->commandPacks, sizeof(COMMAND_PACKET) * MAX_COMMAND_COUNT); // 单包加密

    InsertJunkCodeRND();

    // Buffer统一解密
    DecryptField((ULONG*)&pSharedData->DataSize);
    DecryptBuffer(pSharedData->Buffer[pSharedData->currentBufferIndex], pSharedData->DataSize); // 直接作用
    InsertJunkCode(3);
    return true;
}

void OnFrameEnd()
{
    InsertJunkCodeRND();
    PSHARED_MEMORY_DATA pSharedData = GetSharedDataOnce();
    pSharedData->CommandPackSize = GetSequence();
    if (pSharedData->CommandPackSize >= MAX_COMMAND_COUNT)
    {
        std::cout << "Exceed max command size: " << std::dec << pSharedData->CommandPackSize << std::endl;
    }
    //std::cout << "TotalCommand Sent: " << std::dec << pSharedData->CommandPackSize << std::endl;
    InsertJunkCodeRND();
    EncryptField(&pSharedData->ClientPid);
    EncryptField(&pSharedData->TargetPid);
    EncryptField((ULONG*)&pSharedData->CommandPackSize);
    //Buffer恢复
    EncryptBuffer(pSharedData->Buffer[pSharedData->currentBufferIndex], pSharedData->DataSize);  // 恢复
    EncryptField((ULONG*)&pSharedData->DataSize);
    InsertJunkCode(1);

    MemoryBarrier();
    InsertJunkCode(2);
    InterlockedExchange(&pSharedData->Lock, 0);
}

int main()
{
    InsertJunkCodeRND();
    printf("User Mode Client Starting...\n");

    if (!InitializeSharedMemory())
    {
        InsertJunkCode(1);
        getchar();
        return 1;
    }

    while(true)
    {
        InsertJunkCodeRND();
        if (!OnFrameStart()) break;

        // 设置pid,设置 ex buffer
        DWORD clientPid = GetCurrentProcessId();
        DWORD targetPid = GetProcessID(L"League of Legends.exe");

        //std::cout << (ULONG)clientPid << "  " << (ULONG)targetPid << std::endl;
        PSHARED_MEMORY_DATA pSharedData = GetSharedDataOnce();
        ULONG DataSize = pSharedData->DataSize;
        DecryptField((ULONG*)&DataSize);
        std::cout << "CurrenBufferIndex: " << pSharedData->currentBufferIndex << std::endl;
        std::cout << "DataSize: " << DataSize << std::endl;
        
        pSharedData->ClientPid = (ULONG)clientPid;
        pSharedData->TargetPid = (ULONG)targetPid;

        MemoryResult<uintptr_t> baseAddress = GetModuleBase(targetPid);
        MemoryResult<int> v1 = Read<int>(baseAddress, 0x5034);
        Write<int>(baseAddress, 0x5034, 100);

        ULONG data_size = 64;

        std::vector<uint8_t> buffer = ReadBuffer(baseAddress, 0x5050, data_size).Value;

        float viewMatrix4x4[16] = { 0 };

        for (int i = 0; i < 16; ++i)
        {
            std::memcpy(&viewMatrix4x4[i], &buffer[i * 4], sizeof(float));
            std::cout << "," << viewMatrix4x4[i];
        }
        std::cout << "" << std::endl;

        std::cout << "Base Address: " << std::hex << baseAddress.Value << std::endl;
        std::cout << "v1 : " << std::dec << v1.Value << std::endl;

        OnFrameEnd();

        int sleepTime = 2000;
        Sleep(sleepTime + rand() % sleepTime - sleepTime / 2);
    }

    // 等待用户输入，保持程序运行
    printf("Press Enter to exit...\n");
    getchar();

    CleanupSharedMemory();
    return 0;
}

