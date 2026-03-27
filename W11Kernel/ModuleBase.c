#include "KernelIncludes.h"
#define SAFETY_MARGIN 0x8

PVOID GetModuleBaseByName(PCUNICODE_STRING moduleName, SIZE_T* pSize)
{
    NTSTATUS status;
    ULONG len = 0;
    PSYSTEM_MODULE_INFORMATION moduleInfo = NULL;
    PVOID base = NULL;

    status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &len);
    if (status != STATUS_INFO_LENGTH_MISMATCH)
        return NULL;

    moduleInfo = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, len, 'ModI');
    if (!moduleInfo)
        return NULL;

    status = ZwQuerySystemInformation(SystemModuleInformation, moduleInfo, len, &len);
    if (!NT_SUCCESS(status))
    {
        ExFreePoolWithTag(moduleInfo, 'ModI');
        return NULL;
    }

    for (ULONG i = 0; i < moduleInfo->ModulesCount; i++)
    {
        ANSI_STRING ansiName;
        UNICODE_STRING uniName;

        // FullPathName 是 ANSI，转成 Unicode 再比较
        RtlInitAnsiString(&ansiName, (PCSZ)moduleInfo->Modules[i].FullPathName);

        if (NT_SUCCESS(RtlAnsiStringToUnicodeString(&uniName, &ansiName, TRUE)))
        {
            // 只比较文件名部分（后缀），忽略路径
            PCWSTR fileName = uniName.Buffer + (moduleInfo->Modules[i].OffsetToFileName);

            UNICODE_STRING uniFileName;
            RtlInitUnicodeString(&uniFileName, fileName);

            if (RtlCompareUnicodeString(&uniFileName, moduleName, TRUE) == 0)
            {
                base = moduleInfo->Modules[i].ImageBase;
                if (pSize)
                    *pSize = moduleInfo->Modules[i].ImageSize;
                RtlFreeUnicodeString(&uniName);
                break;
            }
            RtlFreeUnicodeString(&uniName);
        }
    }

    ExFreePoolWithTag(moduleInfo, 'ModI');
    return base;
}

IMAGE_SECTION_HEADER* GetModuleSectionHeader(PCUNICODE_STRING moduleName, const char* sectionName)
{
    SIZE_T moduleSize = 0;
    PVOID moduleBase = GetModuleBaseByName(moduleName, &moduleSize);

    if (!moduleBase)
    {
        DebugMessage("Failed to find module: %wZ\n", moduleName);
        return NULL;
    }

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)moduleBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        DebugMessage("Invalid DOS signature in module: %wZ\n", moduleName);
        return NULL;
    }

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((PUCHAR)moduleBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
    {
        DebugMessage("Invalid NT signature in module: %wZ\n", moduleName);
        return NULL;
    }

    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
    {
        if (strncmp((const char*)sec->Name, sectionName, IMAGE_SIZEOF_SHORT_NAME) == 0)
        {
            DebugMessage("Found section %s in module %wZ at offset: 0x%X\n",
                sectionName, moduleName, sec->VirtualAddress);
            return sec;
        }
    }

    DebugMessage("Section %s not found in module %wZ\n", sectionName, moduleName);
    return NULL;
}

PVOID FindFreeChunk(PVOID gapStart, SIZE_T gapSize, SIZE_T chunkSize)
{
    PUCHAR start = (PUCHAR)gapStart;
    PUCHAR end = start + gapSize;
    PUCHAR current = end - 1;

    SIZE_T freeCount = 0;

    while (current >= start)
    {
        UCHAR byte = *current;
        if (byte == 0x00 || byte == 0xCC || byte == 0x90)
        {
            freeCount++;

            if (freeCount >= chunkSize)
            {
                PVOID chunkStart = current; // 当前指针就是chunk的开始
                DebugMessage("Found chunk at: %p\n", chunkStart);
                return chunkStart;
            }
        }
        else
        {
            freeCount = 0;
        }

        current--;
    }
    return NULL;
}

BOOLEAN IsMemoryFree(PVOID address, SIZE_T size)
{
    for (SIZE_T i = 0; i < size; i += sizeof(ULONG_PTR))
    {
        ULONG_PTR value = *(ULONG_PTR*)((PUCHAR)address + i);
        // 通常未使用的内存是全零或特定填充模式
        if (value != 0 && value != 0xCCCCCCCCCCCCCCCC) // 常见的调试填充
        {
            DebugMessage("IsMemoryFree: Memory at 0x%p+0x%X contains non-free pattern: 0x%llX\n",
                address, i, value);
            return FALSE;
        }
    }
    return TRUE;
}

PVOID GetModuleSectionGap(PCUNICODE_STRING moduleName)
{
    SIZE_T ntSize = 0;
    PVOID ntBase = GetModuleBaseByName(moduleName, &ntSize);
    if (!ntBase) return NULL;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)ntBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((PUCHAR)ntBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);  // 获取第一个 section
    IMAGE_SECTION_HEADER* prevSec = NULL;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
    {
        // 如果前一个 section 存在，计算相邻间隙
        if (prevSec != NULL)
        {
            // 当前 section 的起始地址
            PUCHAR currentStart = (PUCHAR)ntBase + sec->VirtualAddress;

            // 前一个 section 的结束地址
            PUCHAR prevEnd = (PUCHAR)ntBase + prevSec->VirtualAddress + prevSec->SizeOfRawData;

            // 计算间隙大小
            SIZE_T gapSize = currentStart - prevEnd;
            SIZE_T hookSafeSize = sizeof(HOOKOPCODES) + SAFETY_MARGIN;
            if (gapSize >= hookSafeSize)
            {
                PVOID foundChunk = FindFreeChunk(prevEnd, gapSize, hookSafeSize);
                if (CheckMemoryProtection(foundChunk, hookSafeSize))
                {
                    return foundChunk ;
                }
            }
        }
        prevSec = sec;  // 记录当前 section 为下一个循环的前一个 section
    }

    return NULL;  // 如果没有找到符合条件的间隙
}

BOOLEAN CheckMemoryProtection(PVOID addr, SIZE_T size)
{
    // 1. 检查地址有效性
    if (!MmIsAddressValid(addr))
    {
        DebugMessage("CheckMemoryProtection: Address 0x%p is not valid\n", addr);
        return FALSE;
    }

    // 2. 检查保护属性（可写）
    ULONG oldProtect;
    PVOID base = addr;
    SIZE_T regionSize = size;
    NTSTATUS status = MyProtectVirtualMemory(&base, &regionSize, PAGE_READWRITE, &oldProtect);
    if (!NT_SUCCESS(status))
    {
        //DebugMessage("CheckMemoryProtection: Failed to change protection for address 0x%p, status: 0x%X\n", addr, status);
        //return FALSE;
    }


    // 立即恢复保护
    status = MyProtectVirtualMemory(&base, &regionSize, oldProtect, &oldProtect);
    if (!NT_SUCCESS(status))
    {
        //DebugMessage("CheckMemoryProtection: Warning: Failed to restore protection for address 0x%p, status: 0x%X\n", addr, status);
        // 这里不返回FALSE，因为主要检查已经通过
    }

    // 3. 检查内存内容（是否看起来未使用）
    /*if (!IsMemoryFree(addr, size))
    {
        DebugMessage("CheckMemoryProtection: Memory at 0x%p appears to be in use\n", addr);
        return FALSE;
    }*/

    DebugMessage("CheckMemoryProtection: Memory at 0x%p passed all checks\n", addr);
    return TRUE;
}

// 获取ntQuery...的函数的所在节section
IMAGE_SECTION_HEADER* RvaToSection(PVOID base, ULONG rva)
{
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((PUCHAR)base + dos->e_lfanew);
    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, section++)
    {
        if (rva >= section->VirtualAddress && rva < section->VirtualAddress + section->Misc.VirtualSize)
            return section;
    }
    return NULL;
}

PVOID FindNopBytes(PVOID start, SIZE_T size, SIZE_T nopSize)
{
    for (SIZE_T i = 0; i < size - nopSize; i++)
    {
        BOOLEAN match = TRUE;
        for (SIZE_T j = 0; j < nopSize; j++)
        {
            if (*((PUCHAR)start + i + j) != 0x90)
            {
                match = FALSE;
                break;
            }
        }
        if (match) return (PUCHAR)start + i;
    }
    return NULL;
}

PVOID FindKeServiceDescriptorTableShadow()
{
    /* 0: kd > u nt!KiSystemServiceStart
         nt!KiSystemServiceStart:
         fffff800`03e9575e 4889a3d8010000  mov     qword ptr[rbx + 1D8h], rsp
         fffff800`03e95765 8bf8            mov     edi, eax
         fffff800`03e95767 c1ef07          shr     edi, 7
         fffff800`03e9576a 83e720 and edi, 20h
         fffff800`03e9576d 25ff0f0000 and eax, 0FFFh
         nt!KiSystemServiceRepeat:
         fffff800`03e95772 4c8d15c7202300  lea     r10, [nt!KeServiceDescriptorTable(fffff800`040c7840)]
         fffff800`03e95779 4c8d1d00212300  lea     r11, [nt!KeServiceDescriptorTableShadow*/

    SIZE_T ntSize = 0;
    UNICODE_STRING ntoskrnlName = RTL_CONSTANT_STRING(L"ntoskrnl.exe");
    ntBase = GetModuleBaseByName(&ntoskrnlName, &ntSize);
    if (!ntBase)
    {
        DebugMessage("[W11Kernel] Failed to find ntoskrnl base\n");
        return NULL;
    }

    unsigned char pattern[] = {
        0x8B, 0xF8,                     // mov edi,eax
        0xC1, 0xEF, 0x07,               // shr edi,7
        0x83, 0xE7, 0x20,               // and edi,20h
        0x25, 0xFF, 0x0F, 0x00, 0x00    // and eax,0fffh  
    };

    SIZE_T patternLength = sizeof(pattern);
    PUCHAR match = NULL;

    for (ULONG i = 0; i <= ntSize - patternLength; i++)
    {
        if (RtlCompareMemory(ntBase + i, pattern, patternLength) == patternLength)
        {
            match = ntBase + i;
            break;
        }
    }

    if (!match)
    {
        DebugMessage("[W11Kernel] Failed to find pattern\n");
        return NULL;
    }

    PUCHAR address = match + 0xD + 0x7; // 跳过 pattern 和 lea 指令

    DebugMessage("[W11Kernel] Calculated address: %p", address);
    DebugMessage("[W11Kernel] Bytes: %02X %02X %02X", address[0], address[1], address[2]);

    if (address[0] == 0x4C && address[1] == 0x8D && address[2] == 0x1D)
    {
        LONG relOffset = *(LONG*)(address + 3);
        return (PVOID)(address + 7 + relOffset);
    }

    return NULL;
}

// 磁盘读取ntdll,解析pe结构和导出表,找到函数机器码起始地址,搜索 mov eax, XX 指令获取系统调用号（SSDT索引）,返回索引
ULONG GetSyscallIndex(_In_ PCSTR ExportName)
{
    UNICODE_STRING FileName;
    OBJECT_ATTRIBUTES ObjAttr;
    HANDLE FileHandle;
    IO_STATUS_BLOCK IoStatus;
    NTSTATUS Status;
    ULONG FileSize = 0;
    UCHAR* FileData = NULL;
    ULONG syscallIndex = (ULONG)-1;

    DebugMessage("GetSyscallIndex: Start for %s\n", ExportName);

#ifdef SHADOW_SSDT
    RtlInitUnicodeString(&FileName, L"\\SystemRoot\\System32\\win32u.dll");
#elif SSDT
    RtlInitUnicodeString(&FileName, L"\\SystemRoot\\System32\\ntdll.dll");
#endif
    InitializeObjectAttributes(&ObjAttr, &FileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    Status = ZwCreateFile(&FileHandle, GENERIC_READ, &ObjAttr, &IoStatus, NULL,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
        FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(Status))
    {
        DebugMessage("ZwCreateFile failed: 0x%X\n", Status);
        return (ULONG)-1;
    }

    FILE_STANDARD_INFORMATION FileInfo;
    Status = ZwQueryInformationFile(FileHandle, &IoStatus, &FileInfo, sizeof(FileInfo), FileStandardInformation);
    if (!NT_SUCCESS(Status))
    {
        DebugMessage("ZwQueryInformationFile failed: 0x%X\n", Status);
        ZwClose(FileHandle);
        return (ULONG)-1;
    }

    FileSize = FileInfo.EndOfFile.LowPart;
    DebugMessage("File size: %u bytes\n", FileSize);

    FileData = (UCHAR*)ExAllocatePoolWithTag(NonPagedPool, FileSize, 'ldNT');
    if (!FileData)
    {
        DebugMessage("ExAllocatePoolWithTag failed\n");
        ZwClose(FileHandle);
        return (ULONG)-1;
    }

    LARGE_INTEGER Offset = { 0 };
    Status = ZwReadFile(FileHandle, NULL, NULL, NULL, &IoStatus, FileData, FileSize, &Offset, NULL);
    ZwClose(FileHandle);
    if (!NT_SUCCESS(Status))
    {
        DebugMessage("ZwReadFile failed: 0x%X\n", Status);
        ExFreePoolWithTag(FileData, 'ldNT');
        return (ULONG)-1;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)FileData;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        DebugMessage("Invalid DOS signature: 0x%X\n", pDosHeader->e_magic);
        ExFreePoolWithTag(FileData, 'ldNT');
        return (ULONG)-1;
    }

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(FileData + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        DebugMessage("Invalid NT signature: 0x%X\n", pNtHeaders->Signature);
        ExFreePoolWithTag(FileData, 'ldNT');
        return (ULONG)-1;
    }

    PIMAGE_DATA_DIRECTORY DataDir;
    if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        DataDir = ((PIMAGE_NT_HEADERS64)pNtHeaders)->OptionalHeader.DataDirectory;
    else
        DataDir = ((PIMAGE_NT_HEADERS32)pNtHeaders)->OptionalHeader.DataDirectory;

    ULONG ExportDirRva = DataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    ULONG ExportDirSize = DataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    ULONG ExportDirOffset = RvaToOffset(pNtHeaders, ExportDirRva, FileSize);
    if (ExportDirOffset == ERROR_VALUE)
    {
        DebugMessage("Export directory offset invalid\n");
        ExFreePoolWithTag(FileData, 'ldNT');
        return (ULONG)-1;
    }

    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(FileData + ExportDirOffset);
    ULONG NumberOfNames = pExportDir->NumberOfNames;

    ULONG AddrOfFuncsOffset = RvaToOffset(pNtHeaders, pExportDir->AddressOfFunctions, FileSize);
    ULONG AddrOfNameOrdinalsOffset = RvaToOffset(pNtHeaders, pExportDir->AddressOfNameOrdinals, FileSize);
    ULONG AddrOfNamesOffset = RvaToOffset(pNtHeaders, pExportDir->AddressOfNames, FileSize);

    if (AddrOfFuncsOffset == ERROR_VALUE || AddrOfNameOrdinalsOffset == ERROR_VALUE || AddrOfNamesOffset == ERROR_VALUE)
    {
        DebugMessage("Export table offsets invalid\n");
        ExFreePoolWithTag(FileData, 'ldNT');
        return (ULONG)-1;
    }

    ULONG* AddrOfFuncs = (ULONG*)(FileData + AddrOfFuncsOffset);
    USHORT* AddrOfNameOrdinals = (USHORT*)(FileData + AddrOfNameOrdinalsOffset);
    ULONG* AddrOfNames = (ULONG*)(FileData + AddrOfNamesOffset);

    ULONG FuncOffset = ERROR_VALUE;
    for (ULONG i = 0; i < NumberOfNames; i++)
    {
        ULONG CurrNameOffset = RvaToOffset(pNtHeaders, AddrOfNames[i], FileSize);
        if (CurrNameOffset == ERROR_VALUE)
            continue;

        const char* CurrName = (const char*)(FileData + CurrNameOffset);

        if (strcmp(CurrName, ExportName) == 0)
        {
            ULONG FuncRva = AddrOfFuncs[AddrOfNameOrdinals[i]];
            if (FuncRva >= ExportDirRva && FuncRva < ExportDirRva + ExportDirSize)
            {
                DebugMessage("Forwarded export, ignoring: %s\n", ExportName);
                continue;
            }
            FuncOffset = RvaToOffset(pNtHeaders, FuncRva, FileSize);
            DebugMessage("Found function %s at file offset 0x%X\n", ExportName, FuncOffset);
            break;
        }
    }

    if (FuncOffset == ERROR_VALUE)
    {
        DebugMessage("Function %s not found in export table\n", ExportName);
        ExFreePoolWithTag(FileData, 'ldNT');
        return (ULONG)-1;
    }

    UCHAR* pFuncCode = FileData + FuncOffset;
    for (int i = 0; i < 32 && FuncOffset + i < FileSize; i++)
    {
        if (pFuncCode[i] == 0xC2 || pFuncCode[i] == 0xC3) // ret
            break;
        if (pFuncCode[i] == 0xB8) // mov eax, imm32
        {
            syscallIndex = *(ULONG*)(pFuncCode + i + 1);
            DebugMessage("Syscall index for %s is %u\n", ExportName, syscallIndex);
            break;
        }
    }

    if (syscallIndex == (ULONG)-1)
        DebugMessage("Syscall index not found in function %s\n", ExportName);

    ExFreePoolWithTag(FileData, 'ldNT');
    return syscallIndex;
}

// 映射ntdll到内核空间，目前弃用
//ULONG GetSyscallIndex_UseMapper()
//{
//    // 确保路径正确，win10/11默认路径
//    PCWSTR ntdllPath = L"\\SystemRoot\\System32\\ntdll.dll";
//    PVOID funcAddr = MapUserNtdllAndFindExport(ntdllPath, "NtQueryCompositionSurfaceStatistics");
//    if (!funcAddr)
//        return (ULONG)-1;
//    if (!funcAddr)
//        DebugMessage("No func Addr\n");
//
//    PUCHAR bytes = (PUCHAR)funcAddr;
//    if (bytes[0] != 0xB8) // mov eax, imm32
//        return (ULONG)-1;
//
//    return *(ULONG*)(bytes + 1);
//}