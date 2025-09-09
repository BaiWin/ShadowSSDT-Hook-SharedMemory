#pragma once
#include "comm.h"

static const ULONG XOR_KEY = 0xDEADBEEF;

__forceinline void EncryptField(ULONG* field)
{
    *field ^= XOR_KEY;
}

__forceinline void DecryptField(ULONG* field)
{
    *field ^= XOR_KEY; // XOR 是对称的
}

__forceinline ULONG EncryptedSignature(ULONG field)
{
    field ^= XOR_KEY; // XOR 是对称的
    return field;
}

__forceinline void EncryptField64(PVOID* field)
{
    *(ULONG64*)field ^= (ULONG64)XOR_KEY;
}

__forceinline void DecryptField64(PVOID* field)
{
    *(ULONG64*)field ^= (ULONG64)XOR_KEY; // XOR 是对称的
}

__forceinline void EncryptBuffer(UCHAR* buffer, ULONG size)
{
    const UCHAR* keyBytes = (const UCHAR*)&XOR_KEY; // 密钥字节数组 [0xEF, 0xBE, 0xAD, 0xDE] (小端字节序)
    for (ULONG i = 0; i < size; i++)
    {
        buffer[i] ^= keyBytes[i % sizeof(XOR_KEY)];
    }
}

__forceinline void DecryptBuffer(UCHAR* buffer, ULONG size)
{
    const UCHAR* keyBytes = (const UCHAR*)&XOR_KEY;
    for (ULONG i = 0; i < size; i++)
    {
        buffer[i] ^= keyBytes[i % sizeof(XOR_KEY)];
    }
}

__forceinline void EncryptCommandPack(PCOMMAND_PACKET cmd)
{
    EncryptField((ULONG*)&cmd->Type); // 4 bytes
    EncryptField64((PVOID*)&cmd->Address);  // 8 bytes
    EncryptField(&cmd->Offset); // 4 bytes
    EncryptField(&cmd->Size); // 4 bytes
    EncryptField64((PVOID*)&cmd->Value); // 8 bytes
}

__forceinline void DecryptCommandPack(PCOMMAND_PACKET cmd)
{
    DecryptField((ULONG*)&cmd->Type); // 4 bytes
    DecryptField64((PVOID*)&cmd->Address); // 8 bytes
    DecryptField(&cmd->Offset); // 4 bytes
    DecryptField(&cmd->Size); // 4 bytes
    DecryptField64((PVOID*)&cmd->Value); // 8 bytes
}


