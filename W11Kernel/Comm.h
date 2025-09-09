#pragma once

// 内核和用户态都能使用的定义

#ifdef __cplusplus
extern "C" {
#endif

    // 根据编译环境选择不同的基本类型定义
#ifdef _KERNEL_MODE
    // 内核模式包含
#include <ntddk.h>
#include <wdm.h>

// 定义用户态也需要的类型（如果内核已经定义了就不需要重复）
    typedef ULONG_PTR SIZE_T;

#else
    // 用户模式包含
#include <windows.h>
#include <winnt.h>

// 确保有必要的类型定义
    typedef unsigned long ULONG;
    typedef unsigned char UCHAR;
    typedef unsigned long long ULONG_PTR;
    typedef void* PVOID;
    typedef long LONG;

#endif

#ifdef _KERNEL_MODE
#define SHARED_MEMORY_NAME L"\\BaseNamedObjects\\Global\\SysUpdateObj_"
#include <ntstrsafe.h>

    __forceinline void GenerateSharedMemoryName(WCHAR* buffer, size_t bufferSize)
    {
        const WCHAR* localSuffix = L"A0C39D1B-6B9E-4a63-9E33-2F16F4E4345F";

        RtlStringCchPrintfW(buffer, bufferSize, L"%ws%ws", SHARED_MEMORY_NAME, localSuffix);
        DbgPrint("Kernel sharedName: %ws\n", buffer);
    }

#else
#define SHARED_MEMORY_NAME L"Global\\SysUpdateObj_"

    __forceinline void GenerateSharedMemoryName(WCHAR* buffer, size_t bufferSize)
    {
        const WCHAR* localSuffix = L"A0C39D1B-6B9E-4a63-9E33-2F16F4E4345F";

        swprintf_s(buffer, bufferSize, L"%ws%ws", SHARED_MEMORY_NAME, localSuffix);
        printf("Client sharedName: %ws\n", buffer);
    }
#endif

// 共享内存大小
#define SHARED_MEMORY_SIZE (32 * 1024)  // 16KB，适合大量数据
#define MAX_COMMAND_COUNT 512           // 支持最多256个命令
#define BUFFER_SIZE (4 * 1024)          // 每个缓冲区大小
#define REMAIN_SIZE SHARED_MEMORY_SIZE - ((BUFFER_SIZE * 2) + (28 * MAX_COMMAND_COUNT) + 8 + 20 + 200)

// 魔数签名
#define SHARED_MEMORY_SIGNATURE 0x4D454D53 // 'SMEM'

// 确保结构体打包一致
#pragma pack(push, 1)

    // 命令类型定义
    typedef enum _COMMAND_TYPE
    {
        CMD_MODULE_BASE = 1,      // 读取基址
        CMD_READ_MEMORY,   // 读取内存
        CMD_WRITE_MEMORY,  // 写入内存
        CMD_EX_BUFFER        // 双缓冲切换
    } COMMAND_TYPE;

    // 通用命令结构
    typedef struct _COMMAND_PACKET
    {
        COMMAND_TYPE Type;  // 4 bytes
        ULONG_PTR Address;  // Typically 8 bytes on 64-bit, 4 bytes on 32-bit
        ULONG Offset;       // 4 bytes
        ULONG Size;         // 4 bytes
        ULONG64 Value;      // 8 bytes     存储getbase指令的targetpid / read和write的value
    } COMMAND_PACKET, * PCOMMAND_PACKET;

    typedef struct _SHARED_MEMORY_TABLE
    {
        ULONG_PTR ServiceTableBase;      // 8 bytes
        ULONG_PTR ServiceCounterTableBase; // 8 bytes
        ULONG NumberOfServices;         // 4 bytes (匹配 56 字节假设)
        ULONG_PTR ParamTableBase;       // 8 bytes
    } SHARED_MEMORY_TABLE, * PSHARED_MEMORY_TABLE; // 28 bytes

    typedef struct _SHARED_MEMORY_TABLE_SHADOW
    {
        SHARED_MEMORY_TABLE Table[2]; // 28 * 2 = 56 bytes
    } SHARED_MEMORY_TABLE_SHADOW, * PSHARED_MEMORY_TABLE_SHADOW;

    typedef struct _SHARED_MEMORY_DATA
    {
        LIST_ENTRY FakeListEntry; // 虚假链表，模仿系统对象 16 bytes
        SHARED_MEMORY_TABLE_SHADOW SystemTable; // 拷贝 Shadow SSDT  56bytes
        UCHAR Reserved1[128];     // 填充随机数据，混淆分析
        // 200 bytes
        ULONG Signature;           // 魔数校验 4 bytes
        volatile LONG Lock;        // 自旋锁或原子锁 4 bytes
        // 客户端控制
        ULONG ClientPid;           // 原子操作 4 bytes
        ULONG TargetPid;           // 原子操作 4 bytes
        volatile ULONG CommandPackSize;          // 原子操作+内存屏障 4 bytes （complete mark）
        COMMAND_PACKET commandPacks[MAX_COMMAND_COUNT]; // 命令数组  28 * 256 bytes  内存屏障
        // 内核控制
        volatile ULONG currentBufferIndex;       // 4 bytes
        volatile ULONG DataSize;                 // 4 bytes
        UCHAR Buffer[2][BUFFER_SIZE];            // 双缓冲
        UCHAR Reserved2[REMAIN_SIZE];            // 剩余填充
    } SHARED_MEMORY_DATA, * PSHARED_MEMORY_DATA;

#pragma pack(pop)

#ifdef __cplusplus
}
#endif
