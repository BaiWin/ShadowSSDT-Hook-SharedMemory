#include "ClientIncludes.h"
#include <Tlhelp32.h>
#include <iostream>
#include <vector>

int BufferReadStart = 0;
std::atomic<int> g_CommandSeq{-1};

MemoryResult<uintptr_t> GetModuleBase(ULONG pid)
{
	int currentSeq = CommandSequenceGenerator();

	COMMAND_PACKET cmd;
	cmd.Type = CMD_MODULE_BASE;
	cmd.Address = 0;
	cmd.Offset = 0;
	cmd.Value = 0;
	cmd.Size = sizeof(uintptr_t);

	SendCommandToKernel(cmd, currentSeq);

	MemoryResult<uintptr_t> result{};
	result.Value = ProcessSingleResult<uintptr_t>(&BufferReadStart); // 得到 T
	result.Sequence = currentSeq;                      // 保存序号
	return result;
}

MemoryResult<std::vector<uint8_t>> ReadBufferAbsolute(uintptr_t address, uintptr_t offset, ULONG dataSize)
{
	int currentSeq = CommandSequenceGenerator();

	COMMAND_PACKET cmd;
	cmd.Type = CMD_READ_MEMORY;
	cmd.Address = address;
	cmd.Offset = offset;
	cmd.Size = dataSize;
	cmd.Value = 0;

	SendCommandToKernel(cmd, currentSeq);

	MemoryResult<std::vector<uint8_t>> result{};
	result.Value = ProcessSingleResult<std::vector<uint8_t>>(&BufferReadStart, dataSize); // 得到 T
	result.Sequence = currentSeq;                      // 保存序号
	return result;
}

MemoryResult<std::vector<uint8_t>> ReadBuffer(const MemoryResult<uintptr_t>& base, uintptr_t offset, ULONG dataSize)
{
	int currentSeq = CommandSequenceGenerator();

	int packOffset = currentSeq - base.Sequence;

	COMMAND_PACKET cmd;
	cmd.Type = CMD_READ_MEMORY;
	cmd.Address = packOffset;   // 表示是包偏移
	cmd.Offset = offset;
	cmd.Size = dataSize;
	cmd.Value = 0;

	SendCommandToKernel(cmd, currentSeq);

	MemoryResult<std::vector<uint8_t>> result{};
	result.Value = ProcessSingleResult<std::vector<uint8_t>>(&BufferReadStart, dataSize); // 得到 T
	result.Sequence = currentSeq;                      // 保存序号
	return result;
}

void IncrementStartBySize(int* start, int size)
{
	*start += size;
}

int FillChunkToSize(int size)
{
	int currentSeq = CommandSequenceGenerator();
	int sizeToFill = BufferReadStart - size;

	COMMAND_PACKET cmd;
	cmd.Type = CMD_FILL_EMPTY;
	cmd.Address = 0;
	cmd.Offset = 0;
	cmd.Size = sizeToFill;
	cmd.Value = 0;

	SendCommandToKernel(cmd, currentSeq);

	IncrementStartBySize(&BufferReadStart, sizeToFill);

	return currentSeq;
}

DWORD GetProcessID(const wchar_t* processName)
{
	DWORD PID = 0;
	HANDLE hProcessSnapshot;
	PROCESSENTRY32 PE32;

	// Take a snapshot of all processes in the system.
	hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hProcessSnapshot == INVALID_HANDLE_VALUE)
	{
		std::cout << "<CreateToolhelp32Snapshot> Invalid handle";
		return 0;
	}

	// Set the size of the structure before using it.
	PE32.dwSize = sizeof(PROCESSENTRY32);

	// Retrieves information about the first process and exit if unsuccessful
	if (!Process32First(hProcessSnapshot, &PE32))
	{
		std::cout << "<Process32First> Error " << GetLastError() << '\n';
		CloseHandle(hProcessSnapshot);
		return 0;
	}

	// Now walk the snapshot of processes,
	// and find the right process then get its PID
	do
	{
		// Returns 0 value indicates that both wchar_t* string are equal
		if (wcscmp(processName, PE32.szExeFile) == 0)
		{
			PID = PE32.th32ProcessID;
			break;
		}
	} while (Process32Next(hProcessSnapshot, &PE32));

	CloseHandle(hProcessSnapshot);
	return PID;
}