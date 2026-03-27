#pragma once
#include "ClientIncludes.h"
#include <type_traits>
#include <vector>
#include <cstdint>

PSHARED_MEMORY_DATA InitializeSharedMemory();
PSHARED_MEMORY_DATA GetSharedDataOnce();

BOOL SendCommandToKernel(COMMAND_PACKET commandPack, int sequence);

template<typename T>
T ProcessSingleResult(int* start, int size = sizeof(T))
{
    PSHARED_MEMORY_DATA pSharedData = GetSharedDataOnce();
    // 指向共享内存里的数据缓冲
    UCHAR* buffer = pSharedData->Buffer[pSharedData->currentBufferIndex];

    /*printf("Buffer first 8 bytes: ");
    for (int i = 0; i < 8; i++)
    {
        printf("%02X ", buffer[i]);
    }
    printf("\n");*/

    // 数据指针 = buffer + 偏移
    T value{};

    if (size > 0)
    {
        if constexpr (std::is_same_v<T, std::vector<uint8_t>>)
        {
            // 对于 std::vector<uint8_t>，使用 data() 获取内存指针
            value.resize(size);  // 确保 vector 足够大
            memcpy(value.data(), buffer + *start, size);
        }
        else
        {
            // 对于其他基本类型，直接 memcpy
            memcpy(&value, buffer + *start, size);
        }
        *start += size;  // 更新 start
    }

    //printf("Reading from buffer + %d\n", *start);

    return value;
}

void IncrementStartBySize(int* start, int size);

int FillSizeOfChunk(int size);

void CleanupSharedMemory();