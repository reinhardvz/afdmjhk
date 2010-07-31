/*++

Module Name:

    tools.c

Abstract:

    Helpers for everything you need

Author:

    MaD, 12-May-2009

--*/

#include "tools.h"
#include "pe.h"

#if DBG
#define POOLTAG 'LOOT'
#else
#define POOLTAG ' kdD'
#endif

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[ 1 ];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

#define SystemModuleInformation 11

NTSTATUS
NTAPI
ZwQuerySystemInformation(
  __in ULONG SystemInformationClass,
  __inout PVOID SystemInformation,
  __in ULONG SystemInformationLength,
  __out_opt PULONG ReturnLength
);

NTSTATUS
NTAPI
ObReferenceObjectByName(
    IN PUNICODE_STRING ObjectName,
    IN ULONG Attributes,
    IN PACCESS_STATE PassedAccessState OPTIONAL,
    IN ACCESS_MASK DesiredAccess OPTIONAL,
    IN POBJECT_TYPE ObjectType,
    IN KPROCESSOR_MODE AccessMode,
    IN OUT PVOID ParseContext OPTIONAL,
    OUT PVOID *Object
    );

extern POBJECT_TYPE* IoDriverObjectType;

//
// Allocates ChunkSize bytes of memory and fills the MEMORY_CHUNK structure
//

NTSTATUS
NTAPI
  AllocateMemoryChunk(
	__out PMEMORY_CHUNK	MemoryChunk,
	__in  POOL_TYPE		PoolType,
	__in  ULONG			ChunkSize,
	__in  ULONG			Tag
	)
{
	if (!MemoryChunk)
		return STATUS_INVALID_PARAMETER;

	RtlZeroMemory(MemoryChunk, sizeof(MEMORY_CHUNK));

	MemoryChunk->Buffer = ExAllocatePoolWithTag(PoolType, ChunkSize, Tag);
	if (!MemoryChunk->Buffer)
		return STATUS_INSUFFICIENT_RESOURCES;

	MemoryChunk->Size = ChunkSize;
	return STATUS_SUCCESS;
}

//
// Frees the memory in MEMORY_CHUNK and zeroes the structure
//

VOID
NTAPI
  FreeMemoryChunk(
	__in PMEMORY_CHUNK	MemoryChunk
	)
{
	if (!MemoryChunk)
		return;

	if (MemoryChunk->Buffer)
		ExFreePool(MemoryChunk->Buffer);
	RtlZeroMemory(MemoryChunk, sizeof(MEMORY_CHUNK));
}


//
// Reads the file from disk and returns it; you should
// call FreeMemoryChunk() to free FileData
//

NTSTATUS
NTAPI
  GetFileData(
	__in  PUNICODE_STRING	FilePath,
	__out PMEMORY_CHUNK		FileData
  )
{
	OBJECT_ATTRIBUTES	ObjectAttributes = {0};
	IO_STATUS_BLOCK		IoBlock = {0};
	NTSTATUS			Status = STATUS_UNSUCCESSFUL;
	HANDLE				FileHandle = NULL;
	FILE_STANDARD_INFORMATION FileInfo = {0};

	if (!FilePath || !FileData)
		return STATUS_INVALID_PARAMETER;

	RtlZeroMemory(FileData, sizeof(MEMORY_CHUNK));

	InitializeObjectAttributes(&ObjectAttributes, FilePath, OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE, NULL, NULL);

	Status = ZwOpenFile(&FileHandle, GENERIC_READ, &ObjectAttributes, &IoBlock, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
	if (!NT_SUCCESS(Status))
		return Status;

	Status = ZwQueryInformationFile(FileHandle, &IoBlock, &FileInfo, sizeof(FileInfo), FileStandardInformation);
	if (!NT_SUCCESS(Status)) {
		ZwClose(FileHandle);
		return Status;
	}

	// We don't accept really big or zero length files

	if (FileInfo.EndOfFile.HighPart || !FileInfo.EndOfFile.LowPart) {
		ZwClose(FileHandle);
		return STATUS_UNSUCCESSFUL;
	}

	Status = AllocateMemoryChunk(FileData, PagedPool, FileInfo.EndOfFile.LowPart, POOLTAG);
	if (!NT_SUCCESS(Status)) {
		ZwClose(FileHandle);
		return Status;
	}

	// Read the file's content

	Status = ZwReadFile(FileHandle, NULL, NULL, NULL, &IoBlock, FileData->Buffer, FileData->Size, NULL, NULL);
	if (!NT_SUCCESS(Status)) {
		FreeMemoryChunk(FileData);
	}

	if (IoBlock.Information != FileData->Size) {
		FreeMemoryChunk(FileData);
		Status = STATUS_UNSUCCESSFUL;
	}

	ZwClose(FileHandle);
	return Status;
}


//
// Allocates memory for ZwQuerySystemInformation() result;
// you should free the result with ExAllocatePool()
//

NTSTATUS
NTAPI
  GetInfoTable(
	__in  ULONG		TableType,
	__out PVOID*	InfoTable
	)
{
	ULONG		BufferSize = 0x1000, ReturnedSize = 0;
	PVOID		Buffer = NULL;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

	if (!InfoTable)
		return STATUS_INVALID_PARAMETER;

	*InfoTable = NULL;

	do
	{
		Buffer = ExAllocatePoolWithTag(PagedPool, BufferSize, POOLTAG);
		if (!Buffer)
			return STATUS_INSUFFICIENT_RESOURCES;

		Status = ZwQuerySystemInformation(TableType, Buffer, BufferSize, &ReturnedSize); 
		
		if (Status == STATUS_INFO_LENGTH_MISMATCH)
		{
			ExFreePool(Buffer);
			BufferSize *= 2;
		}

	} while (Status == STATUS_INFO_LENGTH_MISMATCH);

	if (!NT_SUCCESS(Status))
	{
		KdPrint(("GetInfoTable(): ZwQuerySystemInformation(%u) failed with status 0x%08X\n", TableType, Status));
		ExFreePool(Buffer);
	}
	else
	{
		*InfoTable = Buffer;
	}

	return Status;
}


//
// Returns the information about the driver's module
//

NTSTATUS
NTAPI
  GetDriverModuleInfo(
	__in  PUNICODE_STRING	DriverName,		// L"\\Driver\\Xxx"
	__out PVOID*			ImageBase,
	__out PULONG			ModuleSize
  )
{
	PDRIVER_OBJECT	DriverObject = NULL;
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;

	if (!DriverName || !ImageBase || !ModuleSize)
		return STATUS_INVALID_PARAMETER;

	Status = ObReferenceObjectByName(
		DriverName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		GENERIC_READ,
		*IoDriverObjectType,
		KernelMode,
		NULL,
		&DriverObject);
	if (!NT_SUCCESS(Status)) {
		KdPrint(("GetDriverModuleInfo(): ObReferenceObjectByName(%wZ) failed with status 0x%08X\n", Status));
		return Status;
	}

	*ImageBase = DriverObject->DriverStart;
	*ModuleSize = DriverObject->DriverSize;

	ObDereferenceObject(DriverObject);
	return Status;
}

//
// Returns the pointer to RTL_PROCESS_MODULE_INFORMATION structure which describe
// the corresponding kernel module; the returned memory must be
// freed by ExFreePool()
//

NTSTATUS
NTAPI
  GetKernelModuleInfo(
	__in  PVOID ModuleAddr,
	__out PRTL_PROCESS_MODULE_INFORMATION* SystemModule
  )
{
	PRTL_PROCESS_MODULES ModulesInfo = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (!ModuleAddr || !SystemModule)
		return STATUS_INVALID_PARAMETER;

	Status = GetInfoTable(SystemModuleInformation, &ModulesInfo);
	if (!NT_SUCCESS(Status)) {
		KdPrint(("GetKernelModuleInfo(): GetInfoTable(SystemModuleInformation) failed with status 0x%08X\n", Status));
		return Status;
	}

	while (ModulesInfo->NumberOfModules--)
	{
		PRTL_PROCESS_MODULE_INFORMATION ModuleInfo = &ModulesInfo->Modules[ModulesInfo->NumberOfModules];

		if ((ULONG_PTR)ModuleAddr >= (ULONG_PTR)ModuleInfo->ImageBase &&
			(ULONG_PTR)ModuleAddr < (ULONG_PTR)ModuleInfo->ImageBase + ModuleInfo->ImageSize)
		{
			RtlMoveMemory(ModulesInfo, ModuleInfo, sizeof(RTL_PROCESS_MODULE_INFORMATION));
			*SystemModule = (PRTL_PROCESS_MODULE_INFORMATION)ModulesInfo;

			return STATUS_SUCCESS;
		}
	}

	ExFreePool(ModulesInfo);
	return STATUS_NOT_FOUND;
}


//
// Loads tcpip.sys module into the memory and maps it; you should
// call FreeMemoryChunk() to free the LoadedTcpip; OriginalTcpip
// represents the original image base and the image size of tcpip.sys
//

NTSTATUS
NTAPI
  GetTcpip(
	__out PMEMORY_CHUNK OriginalTcpip,
	__out PMEMORY_CHUNK LoadedTcpip
  )
{
	UNICODE_STRING	TcpipDriverName = CONST_UNICODE_STRING(L"\\Driver\\tcpip");
	UNICODE_STRING	TcpipDriverPath = CONST_UNICODE_STRING(L"\\SystemRoot\\system32\\drivers\\tcpip.sys");
	MEMORY_CHUNK	FlatFile = {0};
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;

	if (!OriginalTcpip || !LoadedTcpip)
		return STATUS_INVALID_PARAMETER;

	Status = GetDriverModuleInfo(&TcpipDriverName, &OriginalTcpip->Buffer, &OriginalTcpip->Size);
	if (!NT_SUCCESS(Status)) {
		KdPrint(("GetTcpip(): GetDriverModuleInfo(%wZ) failed with status 0x%08X\n", &TcpipDriverName, Status));
		return Status;
	}

	Status = GetFileData(&TcpipDriverPath, &FlatFile);
	if (!NT_SUCCESS(Status)) {
		KdPrint(("GetTcpip(): GetFileData(%wZ) failed with status 0x%08X\n", &TcpipDriverPath, Status));
		return Status;
	}

	Status = MapImage(&FlatFile, LoadedTcpip);
	FreeMemoryChunk(&FlatFile);

	if (!NT_SUCCESS(Status)) {
		KdPrint(("GetTcpip(): MapImage(%wZ) failed with status 0x%08X\n", &TcpipDriverPath, Status));
	}

	return Status;
}

