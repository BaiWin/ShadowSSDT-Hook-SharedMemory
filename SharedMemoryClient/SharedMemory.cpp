#include "ClientIncludes.h"

static volatile LONG initialized = 0;

static PSHARED_MEMORY_DATA* GetSharedMemory()
{
    static PSHARED_MEMORY_DATA data = NULL;
    return &data;
}

static HANDLE* GetFileMappingHandle()
{
    static HANDLE hMapFile = NULL;
    return &hMapFile;
}

// 初始化共享内存
PSHARED_MEMORY_DATA InitializeSharedMemory()
{
    if (InterlockedCompareExchange(&initialized, 1, 0) == 0)
    {
        PSHARED_MEMORY_DATA* pSharedData = GetSharedMemory();
        HANDLE* hMapFile = GetFileMappingHandle();
        if (*pSharedData != NULL || *hMapFile != NULL)
        {
            printf("[InitializeSharedMemory] Reusing existing mapping: %p\n", *pSharedData);
            InterlockedExchange(&initialized, 1);
            return *pSharedData;
        }

        WCHAR sharedName[128] = { 0 };
        GenerateSharedMemoryName(sharedName, 128);
        printf("[InitializeSharedMemory] Client sharedName: %ws\n", sharedName);

        *hMapFile = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, SHARED_MEMORY_SIZE, sharedName);
        DWORD err = GetLastError();
        if (*hMapFile == NULL)
        {
            printf("[InitializeSharedMemory] [(5)Run as administrator] CreateFileMapping failed (%lu)\n", err);
            InterlockedExchange(&initialized, 0);
            return NULL;
        }
        printf("[InitializeSharedMemory] CreateFileMapping: %s (error=%lu)\n",
            err == ERROR_ALREADY_EXISTS ? "Opened existing" : "Created new", err);

        *pSharedData = (PSHARED_MEMORY_DATA)MapViewOfFile(*hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, SHARED_MEMORY_SIZE);
        if (*pSharedData == NULL)
        {
            printf("[InitializeSharedMemory] MapViewOfFile failed (%lu)\n", GetLastError());
            CloseHandle(*hMapFile);
            *hMapFile = NULL;
            InterlockedExchange(&initialized, 0);
            return NULL;
        }

        // 初始化（强制重置）
        (*pSharedData)->Signature = SHARED_MEMORY_SIGNATURE;
        EncryptField(&(*pSharedData)->Signature);
        InterlockedExchange(&(*pSharedData)->Lock, 0);
        RtlZeroMemory(&(*pSharedData)->commandPacks, sizeof(COMMAND_PACKET) * MAX_COMMAND_COUNT);
        (*pSharedData)->ClientPid = GetCurrentProcessId();
        (*pSharedData)->TargetPid = 0;
        (*pSharedData)->currentBufferIndex = 0;
        (*pSharedData)->CommandPackSize = 0;
        EncryptField((ULONG*)&(*pSharedData)->CommandPackSize);
        (*pSharedData)->DataSize = 0;
        EncryptField((ULONG*) & (*pSharedData)->DataSize);
        RtlZeroMemory((*pSharedData)->Buffer[0], BUFFER_SIZE);
        RtlZeroMemory((*pSharedData)->Buffer[1], BUFFER_SIZE);
        printf("[InitializeSharedMemory] Shared memory initialized successfully! ClientPid=%lu\n", (*pSharedData)->ClientPid);
    }
    else
    {
        while (InterlockedCompareExchange(&initialized, 0, 0) != 1)
        {
            Sleep(1);
        }
    }
    return *GetSharedMemory();
}

PSHARED_MEMORY_DATA GetSharedDataOnce()
{
    PSHARED_MEMORY_DATA* pSharedData = GetSharedMemory();
    if (*pSharedData == NULL)
    {
        *pSharedData = InitializeSharedMemory();
    }
    PSHARED_MEMORY_DATA result = *pSharedData;
    return result;
}

// 发送数据到内核
BOOL SendCommandToKernel(COMMAND_PACKET commandPack, int sequence)
{
    if (sequence < 0 || sequence > MAX_COMMAND_COUNT)  // 越界保护
        return FALSE;

    EncryptCommandPack(&commandPack);

    PSHARED_MEMORY_DATA pSharedData = GetSharedDataOnce();

    // 原子写入，可以用 memcpy_s 确保安全
    memcpy_s(&pSharedData->commandPacks[sequence],
        sizeof(COMMAND_PACKET),
        &commandPack,
        sizeof(COMMAND_PACKET));

    // 内存屏障
    MemoryBarrier();

    printf("Data sent to kernel, sequence = %d\n", sequence);
    printf("Data sent to kernel, type = %d\n", commandPack.Type);

    return TRUE;
}

// 清理资源
VOID CleanupSharedMemory(void)
{
    PSHARED_MEMORY_DATA* pSharedData = GetSharedMemory();
    HANDLE* hMapFile = GetFileMappingHandle();
    if (*pSharedData)
    {
        UnmapViewOfFile(*pSharedData);
        *pSharedData = NULL;
    }
    if (*hMapFile)
    {
        CloseHandle(*hMapFile);
        *hMapFile = NULL;
    }
    InterlockedExchange(&initialized, 0);
}
