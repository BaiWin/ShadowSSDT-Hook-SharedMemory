#include "KernelIncludes.h"

void WriteFormattedLog(const CHAR* Format, ...)
{
    return;

    va_list args;
    CHAR formattedBuffer[512];  // 确保足够大

    va_start(args, Format);
    vsprintf(formattedBuffer, Format, args);
    va_end(args);

    // 调用您现有的单参数函数
    WriteLogToFile(formattedBuffer);
}

NTSTATUS WriteLogToFile(const CHAR* Message)
{
    UNICODE_STRING fileName;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;
    HANDLE fileHandle;
    NTSTATUS status;

    // 指定文件路径 - 使用 \??\ 前缀
    RtlInitUnicodeString(&fileName, L"\\??\\C:\\W11KenrelLog.txt");

    InitializeObjectAttributes(&objectAttributes,
        &fileName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    // 创建或打开文件
    status = ZwCreateFile(&fileHandle,
        FILE_APPEND_DATA | SYNCHRONIZE,
        &objectAttributes,
        &ioStatusBlock,
        NULL,                    // 初始大小 = 0，文件不存在时创建
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,  // 允许其他进程访问
        FILE_OPEN_IF,            // 关键：文件不存在就创建，存在就打开
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL,
        0);

    if (NT_SUCCESS(status))
    {
        // 写入消息
        ZwWriteFile(fileHandle,
            NULL,
            NULL,
            NULL,
            &ioStatusBlock,
            (PVOID)Message,
            (ULONG)strlen(Message),
            NULL,
            NULL);

        // 添加换行
        ZwWriteFile(fileHandle,
            NULL,
            NULL,
            NULL,
            &ioStatusBlock,
            "\r\n",
            2,
            NULL,
            NULL);

        // 立即关闭文件，释放占用
        ZwClose(fileHandle);

        DbgPrint("Successfully wrote to file: %s\n", Message);
    }
    else
    {
        DbgPrint("Failed to open file: 0x%X\n", status);
    }

    return status;
}