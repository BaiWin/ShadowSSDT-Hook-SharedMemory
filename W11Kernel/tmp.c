#pragma once
#include <ntifs.h>
#include <intrin.h>
#include <stdarg.h>

#ifndef _MDL_DEFINED_
#include <wdm.h>
#endif
#ifndef POOL_FLAG_NON_PAGED
#define POOL_FLAG_NON_PAGED 0x0000000000000040UI64
#endif
#ifndef MM_COPY_MEMORY
#define MM_COPY_MEMORY 0x1
#endif // Hyperspace

namespace kWalk
{
	constexpr UINT64 PageSize = 0x1000;
	constexpr UINT64 PageMask = 0xFFF;
	constexpr UINT64 PhysMask = 0x0000FFFFFFFFF000;
	constexpr UINT64 BitV = 0x1; // Valid?
	constexpr UINT64 BitW = 0x2; // Writable?
	constexpr UINT64 BitL = 0x80; // Large?

	template <typename X>
	__forceinline X Min(X A, X B)
	{
		return (A < B) ? A : B;
	}
}

namespace kWalk
{
	class Walk
	{
	private:
		PEPROCESS Process;
		UINT64 DB; // Directory Base
		ULONG DTB; // Directory Table Base

		typedef NTSTATUS(NTAPI* v2MmCopyMemory)
			(PVOID, MM_COPY_ADDRESS, SIZE_T, ULONG, PSIZE_T);
		v2MmCopyMemory MmCopyMemory;

		void Log(const char* Format, ...)
		{
			va_list args;
			va_start(args, Format);
			vDbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, Format, args);
			va_end(args);
		}

		PVOID KernelEx(PCWSTR Name)
		{
			UNICODE_STRING Function;
			RtlInitUnicodeString(&Function, Name);
			return MmGetSystemRoutineAddress(&Function);
		}

		UINT64 TableEntry(UINT64 PA)
		{
			if (!MmCopyMemory) return 0;
			MM_COPY_ADDRESS Source;
			Source.PhysicalAddress.QuadPart = PA;
			UINT64 Buffer = 0;
			SIZE_T Bytes = 0;
			NTSTATUS Status = MmCopyMemory(
				&Buffer,
				Source,
				sizeof(UINT64),
				MM_COPY_MEMORY_PHYSICAL,
				&Bytes);
			if (!NT_SUCCESS(Status))
			{
				return 0;
			}
			return Buffer;
		}

		

		ULONG GetDTB()
		{
			Log("[*] Scanning for DTB...\n");

			PEPROCESS SystemProcess = PsInitialSystemProcess;
			if (!SystemProcess) return 0;

			UINT64 VAT = (UINT64)MmCopyMemory;

			for (ULONG i = 0x10; i < 0x200; i += 8)
			{
				UINT64 Elect = *reinterpret_cast<UINT64*>((PUCHAR)SystemProcess + i);

				if ((Elect & 0xFFFFF00000000000) != 0) continue;
				if ((Elect & 0xFFFFFFFFFFFFF000) == 0) continue;

				UINT64 PA = TranslateEx(VAT, Elect);

				if (PA != 0)
				{
					Log("[+] Found DTB Match: 0x%X\n", i);
					return i;
				}
			}
			Log("[!]: DTB Scan Failed!\n");
			Log("[*] Please report back in UnKnoWnCheaTs\n");
			return 0;
		}

	public:
		Walk() : Process(nullptr), DB(0), DTB(0), MmCopyMemory(nullptr) {}
		~Walk() { if (Process) ObDereferenceObject(Process); }

		NTSTATUS Initialize(HANDLE PID)
		{
			Log("[*] Initializing kWalk for PID: %d\n", (ULONG)(ULONG_PTR)PID);
			if (!MmCopyMemory)
			{
				MmCopyMemory = (v2MmCopyMemory)KernelEx(L"MmCopyMemory");
				if (!MmCopyMemory)
				{
					Log("[!] Failed to Resolve MmCopyMemory!\n");
					Log("[*] Please report back in UnKnoWnCheaTs\n");
					return STATUS_ENTRYPOINT_NOT_FOUND;
				}
			}

			if (DTB == 0)
			{
				DTB = GetDTB();
				if (DTB == 0)
				{
					Log("[!] Failed to Determine DTB Offset!\n");
					Log("[*] Please report back in UnKnoWnCheaTs\n");
					return STATUS_DEVICE_CONFIGURATION_ERROR;
				}
			}

			if (Process) ObDereferenceObject(Process);
			NTSTATUS Status = PsLookupProcessByProcessId(PID, &Process);
			if (!NT_SUCCESS(Status))
			{
				Log("[!] PsLookupProcessByProcessId Failed: 0x%X\n", Status);
				Log("[*] Please report back in UnKnoWnCheaTs\n");
				return Status;
			}

			DB = *reinterpret_cast<UINT64*>((PUCHAR)Process + DTB);

			if ((DB & ~kWalk::PhysMask) != 0) DB &= kWalk::PhysMask;

			Log("[+] Process Attached (CR3): %llX\n", DB);

			if (DB == 0)
			{
				Log("[!] Retrieved DirectoryBase is Invalid!");
				Log("[*] Please report back in UnKnoWnCheaTs\n");
				ObDereferenceObject(Process);
				Process = nullptr;
				return STATUS_INVALID_ADDRESS;
			}
			return STATUS_SUCCESS;
		}

		UINT64 Translate(UINT64 VA)
		{
			return TranslateEx(VA, DB);
		}

		NTSTATUS Read(UINT64 Address, PVOID Buffer, SIZE_T Length)
		{
			if (!Process || !Length) return STATUS_INVALID_PARAMETER;
			SIZE_T Left = Length;
			SIZE_T Off = 0;
			PUCHAR Dest = (PUCHAR)Buffer;

			while (Left > 0)
			{
				UINT64 PA = Translate(Address + Off);
				if (!PA) return STATUS_UNSUCCESSFUL;

				UINT64 PO = PA & kWalk::PageMask;
				SIZE_T Bytes = kWalk::Min(kWalk::PageSize - PO, Left);

				MM_COPY_ADDRESS Src;
				Src.PhysicalAddress.QuadPart = PA;
				SIZE_T TX;

				if (!NT_SUCCESS(MmCopyMemory(Dest + Off, Src, Bytes,
					MM_COPY_MEMORY_PHYSICAL, &TX)))
				{
					Log("[!] MmCopyMemory Read Failed: %llX\n", PA);
					Log("[*] Please report back in UnKnoWnCheaTs\n");
					return STATUS_ACCESS_DENIED;
				}

				Left -= Bytes;
				Off += Bytes;
			}
			return STATUS_SUCCESS;
		}

		NTSTATUS Write(UINT64 Address, PVOID Buffer, SIZE_T Length)
		{
			if (!Process || !Length) return STATUS_INVALID_PARAMETER;

			SIZE_T Left = Length;
			SIZE_T Off = 0;
			PUCHAR Src = (PUCHAR)Buffer;

			PVOID Dummy = ExAllocatePool2(POOL_FLAG_NON_PAGED, kWalk::PageSize, 'klaW');
			if (!Dummy)
			{
				Log("[!] Failed to Allocate Dummy Page!\n");
				Log("[*] Please report back in UnKnoWnCheaTs\n");
				return STATUS_INSUFFICIENT_RESOURCES;
			}
			RtlZeroMemory(Dummy, kWalk::PageSize);

			PMDL Mdl = IoAllocateMdl(Dummy, kWalk::PageSize, FALSE, FALSE, NULL);
			if (!Mdl)
			{
				Log("[!] Failed to Allocate MDL!\n");
				Log("[*] Please report back in UnKnoWnCheaTs\n");
				ExFreePool(Dummy);
				return STATUS_INSUFFICIENT_RESOURCES;
			}

			MmBuildMdlForNonPagedPool(Mdl);
			PPFN_NUMBER Array = MmGetMdlPfnArray(Mdl);
			if (!Array)
			{
				Log("[!] Failed to Retrieve PFN Array!\n");
				Log("[*] Please report back in UnKnoWnCheaTs\n");
				IoFreeMdl(Mdl);
				ExFreePool(Dummy);
				return STATUS_INTERNAL_ERROR;
			}

			NTSTATUS Status = STATUS_SUCCESS;

			while (Left > 0)
			{
				UINT64 PA = Translate(Address + Off);
				if (!PA)
				{
					Log("[!] Write Translation Failed: %llX\n", Address + Off);
					Log("[*] Please report back in UnKnoWnCheaTs\n");
					Status = STATUS_UNSUCCESSFUL;
					break;
				}

				UINT64 PO = PA & kWalk::PageMask;
				SIZE_T Bytes = kWalk::Min(kWalk::PageSize - PO, Left);

				PFN_NUMBER Original = Array[0];
				PFN_NUMBER Target = (PFN_NUMBER)(PA >> 12);

				Array[0] = Target;

				PVOID VAM = NULL;
				__try
				{
					VAM = MmMapLockedPagesSpecifyCache(
						Mdl,
						KernelMode,
						MmCached,
						NULL,
						FALSE,
						NormalPagePriority
					);
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					Log("[!] Exception Mapping PFN: %llX\n", Target);
					Log("[*] Please report back in UnKnoWnCheaTs\n");
					VAM = NULL;
				}

				if (VAM)
				{
					__try
					{
						RtlCopyMemory((PUCHAR)VAM + PO, Src + Off, Bytes);
					}
					__except (1)
					{
						Log("[!] Exception During Copy: %llX\n", PA);
						Log("[*] Please report back in UnKnoWnCheaTs\n");
						Status = STATUS_ACCESS_VIOLATION;
					}

					MmUnmapLockedPages(VAM, Mdl);
				}
				else
				{
					Status = STATUS_ACCESS_DENIED;
				}

				Array[0] = Original;

				if (Status != STATUS_SUCCESS) break;

				Left -= Bytes;
				Off += Bytes;

			}

			IoFreeMdl(Mdl);
			ExFreePool(Dummy);
			return Status;
		}

		template <typename X> X Read(UINT64 Address)
		{
			X Buffer{};
			Read(Address, &Buffer, sizeof(X));
			return Buffer;
		}

		template <typename X> NTSTATUS Write(UINT64 Address, X Value)
		{
			return Write(Address, &Value, sizeof(X));
		}
	};
}