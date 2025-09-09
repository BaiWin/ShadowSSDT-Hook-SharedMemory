#include "ClientIncludes.h"
#include <Tlhelp32.h>
#include <iostream>

int BufferReadStart = 0;
std::atomic<int> g_CommandSeq{-1};

MemoryResult<uintptr_t> GetModuleBase(int pid)
{
	int currentSeq = CommandSequenceGenerator();

	COMMAND_PACKET cmd;
	cmd.Type = CMD_MODULE_BASE;
	cmd.Address = 0;
	cmd.Offset = 0;
	cmd.Value = 0;
	cmd.Size = sizeof(uintptr_t);

	printf("Send: Type=%d, Address=0x%p, Size=%llu\n", cmd.Type, (void*)cmd.Address, cmd.Size);

	SendCommandToKernel(cmd, currentSeq);

	MemoryResult<uintptr_t> result{};
	result.Value = ProcessSingleResult<uintptr_t>(&BufferReadStart); // µ√µΩ T
	result.Sequence = currentSeq;                      // ±£¥Ê–Ú∫≈
	return result;
}

void ExchangeBuffer()
{
	COMMAND_PACKET cmd;
	cmd.Type = CMD_EX_BUFFER;
	cmd.Address = 0;
	cmd.Offset = 0;
	cmd.Size = 0;
	cmd.Value = 0;
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