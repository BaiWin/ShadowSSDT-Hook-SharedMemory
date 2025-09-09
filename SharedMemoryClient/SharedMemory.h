#pragma once
#include "ClientIncludes.h"

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
    memcpy(&value, buffer + *start, size);

    //printf("Reading from buffer + %d\n", *start);

    // 消费掉的数据，移动 start 指针
    *start += size;

    return value;
}


void CleanupSharedMemory();