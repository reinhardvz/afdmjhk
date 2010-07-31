/*++

Module Name:

    unhooktl.c

Abstract:

    Functions for Transport Layer's tcpip!XxxTlProviderXxxDispatch
	tables unhooking

Author:

    MaD, 12-May-2009

--*/

#include "unhooktl.h"
#include "gettl.h"
#include "tools.h"

//
// Restores the dispatch table's pointers
//

static
NTSTATUS
  RestoreTcpipDispatchTable(
	__in  PMEMORY_CHUNK		OriginalTcpip,
	__in  PVOID*			OriginalDispatchTable,			// in the original tcpip.sys
	__in  PVOID*			RealDispatchTable,
	__in  ULONG				DispatchTableSize
  )
{
	NTSTATUS	Status = STATUS_SUCCESS;
	ULONG		PointerIdx = 0;

	PMDL		OriginalDispatchTableMdl = NULL;
	PVOID*		MappedOriginalDispatchTable = NULL;

	ASSERT( OriginalTcpip );
	ASSERT( OriginalDispatchTable );
	ASSERT( RealDispatchTable );
	ASSERT( DispatchTableSize );


	// We have to be sure that the original dispatch table points into tcpip.sys

	if ((ULONG_PTR)OriginalDispatchTable < (ULONG_PTR)OriginalTcpip->Buffer ||
		(ULONG_PTR)OriginalDispatchTable + DispatchTableSize > (ULONG_PTR)OriginalTcpip->Buffer + OriginalTcpip->Size)
	{
		KdPrint(("RestoreTcpipDispatchTable(): Dispatch table %p is out of tcpip.sys' range %p..%p\n",
			OriginalDispatchTable, OriginalTcpip->Buffer, (ULONG_PTR)OriginalTcpip->Buffer + OriginalTcpip->Size));
		return STATUS_UNSUCCESSFUL;
	}

	// The dispatch table is not hooked

	if (!memcmp(OriginalDispatchTable, RealDispatchTable, DispatchTableSize))
		return STATUS_SUCCESS;

	// Handle the hooked dispatch table

	OriginalDispatchTableMdl = IoAllocateMdl(OriginalDispatchTable, DispatchTableSize, FALSE, FALSE, NULL);
	if (!OriginalDispatchTableMdl)
		return STATUS_INSUFFICIENT_RESOURCES;

	// Going to have write access to the read only memory of tcpip.sys' .rdata section

	__try {
		MmProbeAndLockPages(OriginalDispatchTableMdl, KernelMode, IoWriteAccess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		IoFreeMdl(OriginalDispatchTableMdl);
		return STATUS_ACCESS_VIOLATION;
	}

	MappedOriginalDispatchTable = MmMapLockedPagesSpecifyCache(
		OriginalDispatchTableMdl, KernelMode, MmNonCached, NULL, FALSE, HighPagePriority);
	if (!MappedOriginalDispatchTable) {
		MmUnlockPages(OriginalDispatchTableMdl);
		IoFreeMdl(OriginalDispatchTableMdl);
		return STATUS_UNSUCCESSFUL;
	}

	// Unhook the dispatch table

	RtlCopyMemory(MappedOriginalDispatchTable, RealDispatchTable, DispatchTableSize);

	MmUnmapLockedPages(MappedOriginalDispatchTable, OriginalDispatchTableMdl);
	MmUnlockPages(OriginalDispatchTableMdl);
	IoFreeMdl(OriginalDispatchTableMdl);
	return STATUS_SUCCESS;
}

//
// Unhooks the TcpTlProviderDispatch, UdpTlProviderDispatch
// and RawTlProviderDispatch tables
//

static
NTSTATUS
  UnhookXxxTlProviderDispatch(
	__in PTL_DISPATCH_TABLES	Dispatches,
	__in PMEMORY_CHUNK			OriginalTcpip
  )
{
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;
	ULONG		RestoredPointers = 0;

	ASSERT( Dispatches );
	ASSERT( OriginalTcpip );

	ASSERT( Dispatches->TcpTlProviderDispatch );
	ASSERT( Dispatches->UdpTlProviderDispatch );
	ASSERT( Dispatches->RawTlProviderDispatch );

	Status = RestoreTcpipDispatchTable(
		OriginalTcpip,
		(PVOID*)Dispatches->TcpTlProviderDispatch,
		(PVOID*)&Dispatches->RealTcpTlProviderDispatch,
		sizeof(TL_PROVIDER_DISPATCH));
	if (!NT_SUCCESS(Status)) {
		KdPrint(("UnhookXxxTlProviderDispatch(): RestoreTcpipDispatchTable(TcpTlProviderDispatch) failed with status 0x%08X\n",
			Status));
		return Status;
	}

	Status = RestoreTcpipDispatchTable(
		OriginalTcpip,
		(PVOID*)Dispatches->UdpTlProviderDispatch,
		(PVOID*)&Dispatches->RealUdpTlProviderDispatch,
		sizeof(TL_PROVIDER_DISPATCH));
	if (!NT_SUCCESS(Status)) {
		KdPrint(("UnhookXxxTlProviderDispatch(): RestoreTcpipDispatchTable(UdpTlProviderDispatch) failed with status 0x%08X\n",
			Status));
		return Status;
	}

	Status = RestoreTcpipDispatchTable(
		OriginalTcpip,
		(PVOID*)Dispatches->RawTlProviderDispatch,
		(PVOID*)&Dispatches->RealRawTlProviderDispatch,
		sizeof(TL_PROVIDER_DISPATCH));
	if (!NT_SUCCESS(Status)) {
		KdPrint(("UnhookXxxTlProviderDispatch(): RestoreTcpipDispatchTable(RawTlProviderDispatch) failed with status 0x%08X\n",
			Status));
	}

	return Status;
}



//
// Unhooks the TcpTlProviderEndpointDispatch, UdpTlProviderEndpointDispatch
// and RawTlProviderEndpointDispatch tables
//

static
NTSTATUS
  UnhookXxxTlProviderEndpointDispatch(
	__in PTL_DISPATCH_TABLES	Dispatches,
	__in PMEMORY_CHUNK			OriginalTcpip
  )
{
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;
	ULONG		RestoredPointers = 0;

	ASSERT( Dispatches );
	ASSERT( OriginalTcpip );

	ASSERT( Dispatches->TcpTlProviderEndpointDispatch );
	ASSERT( Dispatches->UdpTlProviderEndpointDispatch );
	ASSERT( Dispatches->RawTlProviderEndpointDispatch );

	Status = RestoreTcpipDispatchTable(
		OriginalTcpip,
		(PVOID*)Dispatches->TcpTlProviderEndpointDispatch,
		(PVOID*)&Dispatches->RealTcpTlProviderEndpointDispatch,
		sizeof(TL_ENDPOINT_DATA_DISPATCH));
	if (!NT_SUCCESS(Status)) {
		KdPrint(("UnhookXxxTlProviderEndpointDispatch(): RestoreTcpipDispatchTable(TcpTlProviderEndpointDispatch) failed with status 0x%08X\n",
			Status));
		return Status;
	}

	Status = RestoreTcpipDispatchTable(
		OriginalTcpip,
		(PVOID*)Dispatches->UdpTlProviderEndpointDispatch,
		(PVOID*)&Dispatches->RealUdpTlProviderEndpointDispatch,
		sizeof(TL_ENDPOINT_DATA_DISPATCH));
	if (!NT_SUCCESS(Status)) {
		KdPrint(("UnhookXxxTlProviderEndpointDispatch(): RestoreTcpipDispatchTable(UdpTlProviderEndpointDispatch) failed with status 0x%08X\n",
			Status));
		return Status;
	}

	Status = RestoreTcpipDispatchTable(
		OriginalTcpip,
		(PVOID*)Dispatches->RawTlProviderEndpointDispatch,
		(PVOID*)&Dispatches->RealRawTlProviderEndpointDispatch,
		sizeof(TL_ENDPOINT_DATA_DISPATCH));
	if (!NT_SUCCESS(Status)) {
		KdPrint(("UnhookXxxTlProviderEndpointDispatch(): RestoreTcpipDispatchTable(RawTlProviderEndpointDispatch) failed with status 0x%08X\n",
			Status));
	}

	return Status;
}




//
// Unhooks TcpTlProviderConnectDispatch and TcpTlProviderListenDispatch tables
//

static
NTSTATUS
  UnhookTcpDispatches(
	__in PTL_DISPATCH_TABLES	Dispatches,
	__in PMEMORY_CHUNK			OriginalTcpip
	)
{
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;
	ULONG		RestoredPointers = 0;

	ASSERT( Dispatches );
	ASSERT( OriginalTcpip );

	ASSERT( Dispatches->TcpTlProviderConnectDispatch );
	ASSERT( Dispatches->TcpTlProviderListenDispatch );

	Status = RestoreTcpipDispatchTable(
		OriginalTcpip,
		(PVOID*)Dispatches->TcpTlProviderConnectDispatch,
		(PVOID*)&Dispatches->RealTcpTlProviderConnectDispatch,
		sizeof(TL_PROVIDER_CONNECT_DISPATCH));
	if (!NT_SUCCESS(Status)) {
		KdPrint(("UnhookTcpDispatches(): RestoreTcpipDispatchTable(TcpTlProviderConnectDispatch) failed with status 0x%08X\n",
			Status));
		return Status;
	}

	Status = RestoreTcpipDispatchTable(
		OriginalTcpip,
		(PVOID*)Dispatches->TcpTlProviderListenDispatch,
		(PVOID*)&Dispatches->RealTcpTlProviderListenDispatch,
		sizeof(TL_PROVIDER_LISTEN_DISPATCH));
	if (!NT_SUCCESS(Status)) {
		KdPrint(("UnhookTcpDispatches(): RestoreTcpipDispatchTable(TcpTlProviderListenDispatch) failed with status 0x%08X\n",
			Status));
	}

	return Status;
}



//
// Unhooks UdpTlProviderMessageDispatch and RawTlProviderMessageDispatch tables
//

static
NTSTATUS
  UnhookMessageDispatches(
	__in PTL_DISPATCH_TABLES	Dispatches,
	__in PMEMORY_CHUNK			OriginalTcpip
	)
{
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;
	ULONG		RestoredPointers = 0;

	ASSERT( Dispatches );
	ASSERT( OriginalTcpip );

	ASSERT( Dispatches->UdpTlProviderMessageDispatch );
	ASSERT( Dispatches->RawTlProviderMessageDispatch );

	Status = RestoreTcpipDispatchTable(
		OriginalTcpip,
		(PVOID*)Dispatches->UdpTlProviderMessageDispatch,
		(PVOID*)&Dispatches->RealUdpTlProviderMessageDispatch,
		sizeof(TL_PROVIDER_MESSAGE_DISPATCH));
	if (!NT_SUCCESS(Status)) {
		KdPrint(("UnhookMessageDispatches(): RestoreTcpipDispatchTable(UdpTlProviderMessageDispatch) failed with status 0x%08X\n",
			Status));
		return Status;
	}

	Status = RestoreTcpipDispatchTable(
		OriginalTcpip,
		(PVOID*)Dispatches->RawTlProviderMessageDispatch,
		(PVOID*)&Dispatches->RealRawTlProviderMessageDispatch,
		sizeof(TL_PROVIDER_MESSAGE_DISPATCH));
	if (!NT_SUCCESS(Status)) {
		KdPrint(("UnhookMessageDispatches(): RestoreTcpipDispatchTable(RawTlProviderMessageDispatch) failed with status 0x%08X\n",
			Status));
	}

	return Status;
}



//
// Unhooks all tcpip.sys' dispatch tables which are hooked
//

NTSTATUS
NTAPI
  UnhookNPI(
	__in PTL_DISPATCH_TABLES DispatchTables
  )
{
	UNICODE_STRING	TcpipDriverName = CONST_UNICODE_STRING(L"\\Driver\\tcpip");
	MEMORY_CHUNK	OriginalTcpip = {0};
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;

	if (!DispatchTables)
		return STATUS_INVALID_PARAMETER;

	Status = GetDriverModuleInfo(&TcpipDriverName, &OriginalTcpip.Buffer, &OriginalTcpip.Size);
	if (!NT_SUCCESS(Status)) {
		KdPrint(("UnhookNPI(): GetDriverModuleInfo(%wZ) failed with status 0x%08X\n", &TcpipDriverName, Status));
		return Status;
	}
	
	do
	{
		// Unhook XxxTlProviderDispatch tables

		Status = UnhookXxxTlProviderDispatch(DispatchTables, &OriginalTcpip);
		if (!NT_SUCCESS(Status)) {
			KdPrint(("UnhookNPI(): UnhookXxxTlProviderDispatch() failed with status 0x%08X\n", Status));
			break;
		}

		// Unhook XxxTlProviderEndpointDispatch tables

		Status = UnhookXxxTlProviderEndpointDispatch(DispatchTables, &OriginalTcpip);
		if (!NT_SUCCESS(Status)) {
			KdPrint(("UnhookNPI(): UnhookXxxTlProviderEndpointDispatch() failed with status 0x%08X\n", Status));
			break;
		}

		// Unhook TcpTlProviderConnectDispatch and TcpTlProviderListenDispatch tables

		Status = UnhookTcpDispatches(DispatchTables, &OriginalTcpip);
		if (!NT_SUCCESS(Status)) {
			KdPrint(("UnhookNPI(): UnhookTcpDispatches() failed with status 0x%08X\n", Status));
			break;
		}

		// Unhook UdpTlProviderMessageDispatch and RawTlProviderMessageDispatch tables

		Status = UnhookMessageDispatches(DispatchTables, &OriginalTcpip);
		if (!NT_SUCCESS(Status)) {
			KdPrint(("UnhookNPI(): UnhookMessageDispatches() failed with status 0x%08X\n", Status));
			break;
		}

	} while (0);

	return Status;

}
