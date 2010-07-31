#pragma once
#include <ntddk.h>

#define CONST_UNICODE_STRING(x) {sizeof(x) - sizeof(WCHAR), sizeof(x), x}

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;                 // Not filled in
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[ 256 ];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY	InLoadOrderLinks;
	LIST_ENTRY	InMemoryOrderLinks;
	LIST_ENTRY	InInitializationOrderLinks;
	PVOID	DllBase;
	PVOID	EntryPoint;
	ULONG	SizeOfImage;
	UNICODE_STRING	FullDllName;
	UNICODE_STRING	BaseDllName;
	ULONG	Flags;
	USHORT	LoadCount;
	USHORT	TlsIndex;
	union {
		LIST_ENTRY	HashLinks;
		struct {
			PVOID	SectionPointer;
			ULONG	CheckSum;
		};
	};
	ULONG	TimeDateStamp;
	PVOID	LoadedImports;
	PVOID	/*PACTIVATION_CONTEXT*/ EntryPointActivationContext;
	PVOID	PatchInformation;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _MEMORY_CHUNK {
	PVOID	Buffer;
	ULONG	Size;
} MEMORY_CHUNK, *PMEMORY_CHUNK;

NTSTATUS
NTAPI
  AllocateMemoryChunk(
	__out PMEMORY_CHUNK	MemoryChunk,
	__in  POOL_TYPE		PoolType,
	__in  ULONG			ChunkSize,
	__in  ULONG			Tag
	);

VOID
NTAPI
  FreeMemoryChunk(
	__in PMEMORY_CHUNK	MemoryChunk
	);

NTSTATUS
NTAPI
  GetFileData(
	__in  PUNICODE_STRING	FilePath,
	__out PMEMORY_CHUNK		FileData
  );

NTSTATUS
NTAPI
  GetInfoTable(
	__in  ULONG		TableType,
	__out PVOID*	InfoTable
	);

NTSTATUS
NTAPI
  GetDriverModuleInfo(
	__in  PUNICODE_STRING	DriverName,
	__out PVOID*			ImageBase,
	__out PULONG			ModuleSize
  );

NTSTATUS
NTAPI
  GetKernelModuleInfo(
	__in  PVOID ModuleAddr,
	__out PRTL_PROCESS_MODULE_INFORMATION* SystemModule
  );

NTSTATUS
NTAPI
  GetTcpip(
	__out PMEMORY_CHUNK OriginalTcpip,
	__out PMEMORY_CHUNK LoadedTcpip
  );

