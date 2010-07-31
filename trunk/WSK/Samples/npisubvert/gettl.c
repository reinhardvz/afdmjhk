/*++

Module Name:

    gettl.c

Abstract:

    Functions for Transport Layer's tcpip!XxxTlProviderXxxDispatch
	tables retrieving

Author:

    MaD, 12-May-2009

--*/

#include "gettl.h"
#include "tools.h"

typedef struct _GET_DISPATCH_CONTEXT {
	PVOID*		DispatchTable;
	PVOID		Endpoint;
} GET_DISPATCH_CONTEXT, *PGET_DISPATCH_CONTEXT;

typedef NTSTATUS (NTAPI* GET_DISPATCH) (
	__in PVOID		Context,
	__in NTSTATUS	Status,
	__in PVOID		Endpoint,
	__in PVOID		DispatchTable
);

#ifdef _AMD64_
#pragma pack(push, 8)
#else
#pragma pack(push, 4)
#endif

typedef struct _PROVIDER_DISPATCH_UNK1 {
	UCHAR	Padding[512];
} PROVIDER_DISPATCH_UNK1, *PPROVIDER_DISPATCH_UNK1;

typedef struct _TL_ENDPOINT_DATA {
	GET_DISPATCH	GetDispatch;
	PVOID			GetDispatchContext;
	PVOID			Flags;
	USHORT			Family;			// must be equal to AF_XXX for endpoint establishing calls
#ifndef _AMD64_
	PVOID			Unk5;
#endif
	PEPROCESS		Process;		// must not be NULL
	PETHREAD		Thread;			// must not be NULL
	PVOID			Object;
	PSOCKADDR_IN	Addr1;			// must not be NULL for CONNECT/LISTEN/MESSAGE calls
	PVOID			Unk10;
	PVOID			Unk11;
	PSOCKADDR_IN	Addr2;			// must not be NULL for CONNECT calls
	PVOID			Unk13;
	PVOID			Unk14;
	PVOID			Unk15;
	PVOID			Unk16;
	UCHAR			Padding[32*sizeof(PVOID)];
} TL_ENDPOINT_DATA, *PTL_ENDPOINT_DATA;

#pragma pack(pop)


static NPIID NPI_TRANSPORT_LAYER_ID = {
	0x2227E804, 0x8D8B, 0x11D4,
	{0xAB, 0xAD, 0x00, 0x90, 0x27, 0x71, 0x9E, 0x09}
};

static NPI_MODULEID NPI_MS_TCP_MODULEID = {
	sizeof(NPI_MODULEID),
	MIT_GUID,
	{0xEB004A03, 0x9B1A, 0x11D4,
	{0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xBC}}
};

static NPI_MODULEID NPI_MS_UDP_MODULEID = {
	sizeof(NPI_MODULEID),
	MIT_GUID,
	{0xEB004A02, 0x9B1A, 0x11D4,
	{0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xBC}}
};

static NPI_MODULEID NPI_MS_RAW_MODULEID = {
	sizeof(NPI_MODULEID),
	MIT_GUID,
	{0xEB004A07, 0x9B1A, 0x11D4,
	{0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xBC}}
};


//
// Returns pointers to the real handlers
//

static
NTSTATUS
  GetRealTcpipDispatchTable(
	__in  PMEMORY_CHUNK		OriginalTcpip,
	__in  PMEMORY_CHUNK		LoadedTcpip,
	__in  PVOID*			OriginalDispatchTable,			// in the original tcpip.sys
	__out PVOID*			RealDispatchTable,
	__in  ULONG				PointersCount
  )
{
	NTSTATUS	Status = STATUS_SUCCESS;
	ULONG		PointerIdx = 0;

	ASSERT( OriginalTcpip );
	ASSERT( LoadedTcpip );
	ASSERT( OriginalDispatchTable );
	ASSERT( RealDispatchTable );

	// We have to be sure that the original dispatch table points into tcpip.sys

	if ((ULONG_PTR)OriginalDispatchTable < (ULONG_PTR)OriginalTcpip->Buffer ||
		(ULONG_PTR)OriginalDispatchTable + PointersCount * sizeof(PVOID) > (ULONG_PTR)OriginalTcpip->Buffer + OriginalTcpip->Size)
	{
		KdPrint(("GetRealTcpipDispatchTable(): Dispatch table %p is out of tcpip.sys' range %p..%p\n",
			OriginalDispatchTable, OriginalTcpip->Buffer, (ULONG_PTR)OriginalTcpip->Buffer + OriginalTcpip->Size));
		return STATUS_UNSUCCESSFUL;
	}

	for (PointerIdx=0; PointerIdx<PointersCount; PointerIdx++)
	{
		PVOID LoadedPointer = NULL, GenuinePointer = NULL;

		LoadedPointer = *(PVOID*)((ULONG_PTR)LoadedTcpip->Buffer  +
				((ULONG_PTR)(OriginalDispatchTable + PointerIdx) - (ULONG_PTR)OriginalTcpip->Buffer));

		if ((ULONG_PTR)LoadedPointer < (ULONG_PTR)LoadedTcpip->Buffer ||
			(ULONG_PTR)LoadedPointer + sizeof(PVOID) > (ULONG_PTR)LoadedTcpip->Buffer + LoadedTcpip->Size)
		{
			Status = STATUS_UNSUCCESSFUL;
			break;
		}

		GenuinePointer = (PVOID)((ULONG_PTR)OriginalTcpip->Buffer +
				((ULONG_PTR)LoadedPointer - (ULONG_PTR)LoadedTcpip->Buffer));

		if ((ULONG_PTR)GenuinePointer < (ULONG_PTR)OriginalTcpip->Buffer ||
			(ULONG_PTR)GenuinePointer + sizeof(PVOID) > (ULONG_PTR)OriginalTcpip->Buffer + OriginalTcpip->Size)
		{
			Status = STATUS_UNSUCCESSFUL;
			break;
		}

		RealDispatchTable[PointerIdx] = GenuinePointer;
	}

	return Status;
}

//
// Returns the real TcpTlProviderDispatch, UdpTlProviderDispatch
// and RawTlProviderDispatch tables' handlers
//

static
NTSTATUS
  GetRealXxxTlProviderDispatch(
	__inout PTL_DISPATCH_TABLES	Dispatches,
	__in PMEMORY_CHUNK				OriginalTcpip,
	__in PMEMORY_CHUNK				LoadedTcpip
  )
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	ASSERT( Dispatches );
	ASSERT( OriginalTcpip );
	ASSERT( LoadedTcpip );

	ASSERT( Dispatches->TcpTlProviderDispatch );
	ASSERT( Dispatches->UdpTlProviderDispatch );
	ASSERT( Dispatches->RawTlProviderDispatch );

	Status = GetRealTcpipDispatchTable(
		OriginalTcpip,
		LoadedTcpip,
		(PVOID*)Dispatches->TcpTlProviderDispatch,
		(PVOID*)&Dispatches->RealTcpTlProviderDispatch,
		sizeof(TL_PROVIDER_DISPATCH) / sizeof(PVOID));
	if (!NT_SUCCESS(Status)) {
		KdPrint(("GetRealXxxTlProviderDispatch(): GetRealTcpipDispatchTable(TcpTlProviderDispatch) failed with status 0x%08X\n",
			Status));
		return Status;
	}

	Status = GetRealTcpipDispatchTable(
		OriginalTcpip,
		LoadedTcpip,
		(PVOID*)Dispatches->UdpTlProviderDispatch,
		(PVOID*)&Dispatches->RealUdpTlProviderDispatch,
		sizeof(TL_PROVIDER_DISPATCH) / sizeof(PVOID));
	if (!NT_SUCCESS(Status)) {
		KdPrint(("GetRealXxxTlProviderDispatch(): GetRealTcpipDispatchTable(UdpTlProviderDispatch) failed with status 0x%08X\n",
			Status));
		return Status;
	}

	Status = GetRealTcpipDispatchTable(
		OriginalTcpip,
		LoadedTcpip,
		(PVOID*)Dispatches->RawTlProviderDispatch,
		(PVOID*)&Dispatches->RealRawTlProviderDispatch,
		sizeof(TL_PROVIDER_DISPATCH) / sizeof(PVOID));
	if (!NT_SUCCESS(Status)) {
		KdPrint(("GetRealXxxTlProviderDispatch(): GetRealDispatchTable(RawTlProviderDispatch) failed with status 0x%08X\n",
			Status));
	}

	return Status;
}


//
// This function will be called by tcpip.sys to let us know
// the internal dispatch table pointer
//

static
NTSTATUS
NTAPI
  GetDispatchCallback(
	__in PGET_DISPATCH_CONTEXT	Context,
	__in NTSTATUS				Status,
	__in PVOID					Endpoint,
	__in PVOID					DispatchTable
)
{
	if (!Context || !Context->DispatchTable)
		return STATUS_INVALID_PARAMETER;

	Context->Endpoint = Endpoint;
	*Context->DispatchTable = DispatchTable;

	return STATUS_SUCCESS;
}


//
// Returns the pointers on TcpTlProviderEndpointDispatch, UdpTlProviderEndpointDispatch
// and RawTlProviderEndpointDispatch tables placed in tcpip.sys
//

static
NTSTATUS
  GetEndpointDispatches(
	__inout PTL_DISPATCH_TABLES Dispatches
	)
{
	PROVIDER_DISPATCH_UNK1	DispatchUnk1 = {0};
	TL_ENDPOINT_DATA		EndpointData = {0};
	GET_DISPATCH_CONTEXT	GetDispatchContext = {0};
	NTSTATUS				Status = STATUS_UNSUCCESSFUL;

	ASSERT( Dispatches );

	ASSERT( Dispatches->RealTcpTlProviderDispatch.Endpoint );
	ASSERT( Dispatches->RealUdpTlProviderDispatch.Endpoint );
	ASSERT( Dispatches->RealRawTlProviderDispatch.Endpoint );

	EndpointData.GetDispatch		= GetDispatchCallback;
	EndpointData.GetDispatchContext	= &GetDispatchContext;
	EndpointData.Family				= AF_INET;
	EndpointData.Process			= PsGetCurrentProcess();
	EndpointData.Thread				= PsGetCurrentThread();

	//
	// Get TcpTlProviderEndpointDispatch
	//

	GetDispatchContext.DispatchTable = &Dispatches->TcpTlProviderEndpointDispatch;
	GetDispatchContext.Endpoint = NULL;
	Dispatches->TcpTlProviderEndpointDispatch = NULL;

	Status = Dispatches->RealTcpTlProviderDispatch.Endpoint(&DispatchUnk1, &EndpointData);
	if (!NT_SUCCESS(Status)) {
		KdPrint(("GetXxxTlProviderEndpointDispatch(): TcpTlProviderDispatch->Endpoint() failed with status 0x%08X\n", Status));
		return Status;
	}

	ASSERTMSG("GetXxxTlProviderEndpointDispatch(): Epic fail", GetDispatchContext.Endpoint);

	// Deregister the endpoint

	if (GetDispatchContext.Endpoint) {
		Status = Dispatches->TcpTlProviderEndpointDispatch->CloseEndpoint(GetDispatchContext.Endpoint, NULL);
		if (!NT_SUCCESS(Status)) {
			KdPrint(("GetXxxTlProviderEndpointDispatch(): TcpTlProviderDispatch->CloseEndpoint() failed with status 0x%08X\n", Status));
		}
	}

	if (!Dispatches->TcpTlProviderEndpointDispatch) {
		KdPrint(("GetXxxTlProviderEndpointDispatch(): TcpTlProviderDispatch->Endpoint() didn't return anything\n"));
		return STATUS_UNSUCCESSFUL;
	}

	//
	// Get UdpTlProviderEndpointDispatch
	//

	GetDispatchContext.DispatchTable = &Dispatches->UdpTlProviderEndpointDispatch;
	GetDispatchContext.Endpoint = NULL;
	Dispatches->UdpTlProviderEndpointDispatch = NULL;

	Status = Dispatches->RealUdpTlProviderDispatch.Endpoint(&DispatchUnk1, &EndpointData);
	if (!NT_SUCCESS(Status)) {
		KdPrint(("GetXxxTlProviderEndpointDispatch(): UdpTlProviderDispatch->Endpoint() failed with status 0x%08X\n", Status));
		return Status;
	}

	ASSERTMSG("GetXxxTlProviderEndpointDispatch(): Epic fail", GetDispatchContext.Endpoint);

	// Deregister the endpoint

	if (GetDispatchContext.Endpoint) {
		Status = Dispatches->UdpTlProviderEndpointDispatch->CloseEndpoint(GetDispatchContext.Endpoint, NULL);
		if (!NT_SUCCESS(Status)) {
			KdPrint(("GetXxxTlProviderEndpointDispatch(): UdpTlProviderEndpointDispatch->CloseEndpoint() failed with status 0x%08X\n", Status));
		}
	}

	if (!Dispatches->UdpTlProviderEndpointDispatch) {
		KdPrint(("GetXxxTlProviderEndpointDispatch(): UdpTlProviderDispatch->Endpoint() didn't return anything\n"));
		return STATUS_UNSUCCESSFUL;
	}

	//
	// Get RawTlProviderEndpointDispatch
	//

	GetDispatchContext.DispatchTable = &Dispatches->RawTlProviderEndpointDispatch;
	GetDispatchContext.Endpoint = NULL;
	Dispatches->RawTlProviderEndpointDispatch = NULL;

	Status = Dispatches->RealRawTlProviderDispatch.Endpoint(&DispatchUnk1, &EndpointData);
	if (!NT_SUCCESS(Status)) {
		KdPrint(("GetXxxTlProviderEndpointDispatch(): RawTlProviderDispatch->Endpoint() failed with status 0x%08X\n", Status));
		return Status;
	}

	ASSERTMSG("GetXxxTlProviderEndpointDispatch(): Epic fail", GetDispatchContext.Endpoint);

	// Deregister the endpoint

	if (GetDispatchContext.Endpoint) {
		Status = Dispatches->RawTlProviderEndpointDispatch->CloseEndpoint(GetDispatchContext.Endpoint, NULL);
		if (!NT_SUCCESS(Status)) {
			KdPrint(("GetXxxTlProviderEndpointDispatch(): RawTlProviderEndpointDispatch->CloseEndpoint() failed with status 0x%08X\n", Status));
		}
	}

	if (!Dispatches->RawTlProviderEndpointDispatch) {
		KdPrint(("GetXxxTlProviderEndpointDispatch(): RawTlProviderDispatch->Endpoint() didn't return anything\n"));
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}


//
// Returns the real TcpTlProviderEndpointDispatch, UdpTlProviderEndpointDispatch
// and RawTlProviderEndpointDispatch tables' handlers
//

static
NTSTATUS
  GetRealXxxTlProviderEndpointDispatch(
	__inout PTL_DISPATCH_TABLES	Dispatches,
	__in PMEMORY_CHUNK				OriginalTcpip,
	__in PMEMORY_CHUNK				LoadedTcpip
  )
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	ASSERT( Dispatches );
	ASSERT( OriginalTcpip );
	ASSERT( LoadedTcpip );

	ASSERT( Dispatches->TcpTlProviderEndpointDispatch );
	ASSERT( Dispatches->UdpTlProviderEndpointDispatch );
	ASSERT( Dispatches->RawTlProviderEndpointDispatch );

	Status = GetRealTcpipDispatchTable(
		OriginalTcpip,
		LoadedTcpip,
		(PVOID*)Dispatches->TcpTlProviderEndpointDispatch,
		(PVOID*)&Dispatches->RealTcpTlProviderEndpointDispatch,
		sizeof(TL_ENDPOINT_DATA_DISPATCH) / sizeof(PVOID));
	if (!NT_SUCCESS(Status)) {
		KdPrint(("GetRealXxxTlProviderEndpointDispatch(): GetRealTcpipDispatchTable(TcpTlProviderEndpointDispatch) failed with status 0x%08X\n",
			Status));
		return Status;
	}

	Status = GetRealTcpipDispatchTable(
		OriginalTcpip,
		LoadedTcpip,
		(PVOID*)Dispatches->UdpTlProviderEndpointDispatch,
		(PVOID*)&Dispatches->RealUdpTlProviderEndpointDispatch,
		sizeof(TL_ENDPOINT_DATA_DISPATCH) / sizeof(PVOID));
	if (!NT_SUCCESS(Status)) {
		KdPrint(("GetRealXxxTlProviderEndpointDispatch(): GetRealTcpipDispatchTable(UdpTlProviderEndpointDispatch) failed with status 0x%08X\n",
			Status));
		return Status;
	}

	Status = GetRealTcpipDispatchTable(
		OriginalTcpip,
		LoadedTcpip,
		(PVOID*)Dispatches->RawTlProviderEndpointDispatch,
		(PVOID*)&Dispatches->RealRawTlProviderEndpointDispatch,
		sizeof(TL_ENDPOINT_DATA_DISPATCH) / sizeof(PVOID));
	if (!NT_SUCCESS(Status)) {
		KdPrint(("GetRealXxxTlProviderEndpointDispatch(): GetRealTcpipDispatchTable(RawTlProviderEndpointDispatch) failed with status 0x%08X\n",
			Status));
	}

	return Status;
}


//
// Returns the pointers on TcpTlProviderListenDispatch and
// TcpTlProviderConnectDispatch tables placed in tcpip.sys
//

static
NTSTATUS
  GetTcpDispatches(
	__inout PTL_DISPATCH_TABLES Dispatches
	)
{
	PROVIDER_DISPATCH_UNK1	DispatchUnk1 = {0};
	TL_ENDPOINT_DATA		ListenData = {0};
	TL_ENDPOINT_DATA		ConnectData = {0};
	GET_DISPATCH_CONTEXT	GetDispatchContext = {0};
	SOCKADDR_IN				Addr1 = {0}, Addr2 = {0};
	NTSTATUS				Status = STATUS_UNSUCCESSFUL;

	ASSERT( Dispatches );

	ASSERT( Dispatches->RealTcpTlProviderDispatch.Listen );
	ASSERT( Dispatches->RealTcpTlProviderDispatch.Connect );

	Addr1.sin_family = AF_INET;

	ListenData.GetDispatch			= GetDispatchCallback;
	ListenData.GetDispatchContext	= &GetDispatchContext;
	ListenData.Process				= PsGetCurrentProcess();
	ListenData.Thread				= PsGetCurrentThread();
	ListenData.Addr1				= &Addr1;

	//
	// Get TcpTlProviderListenDispatch
	//

	GetDispatchContext.DispatchTable = &Dispatches->TcpTlProviderListenDispatch;
	GetDispatchContext.Endpoint = NULL;
	Dispatches->TcpTlProviderListenDispatch = NULL;

	Status = Dispatches->RealTcpTlProviderDispatch.Listen(&DispatchUnk1, &ListenData);
	if (!NT_SUCCESS(Status)) {
		KdPrint(("GetTcpDispatches(): TcpTlProviderDispatch->Listen() failed with status 0x%08X\n", Status));
		return Status;
	}

	ASSERTMSG("GetTcpDispatches(): Epic fail", GetDispatchContext.Endpoint);

	// Deregister the endpoint

	if (GetDispatchContext.Endpoint) {
		Status = Dispatches->TcpTlProviderListenDispatch->CloseEndpoint(GetDispatchContext.Endpoint, NULL);
		if (!NT_SUCCESS(Status)) {
			KdPrint(("GetTcpDispatches(): TcpTlProviderListenDispatch->CloseEndpoint() failed with status 0x%08X\n", Status));
		}
	}

	if (!Dispatches->TcpTlProviderListenDispatch) {
		KdPrint(("GetTcpDispatches(): TcpTlProviderDispatch->Listen() didn't return anything\n"));
		return STATUS_UNSUCCESSFUL;
	}

	Addr2.sin_family = AF_INET;
	Addr2.sin_port = 123;

	ConnectData.GetDispatch			= GetDispatchCallback;
	ConnectData.GetDispatchContext	= &GetDispatchContext;
	ConnectData.Process				= PsGetCurrentProcess();
	ConnectData.Thread				= PsGetCurrentThread();
	ConnectData.Addr1				= &Addr1;
	ConnectData.Addr2				= &Addr2;

	//
	// Get TcpTlProviderConnectDispatch
	//

	GetDispatchContext.DispatchTable = &Dispatches->TcpTlProviderConnectDispatch;
	GetDispatchContext.Endpoint = NULL;
	Dispatches->TcpTlProviderConnectDispatch = NULL;

	Status = Dispatches->RealTcpTlProviderDispatch.Connect(&DispatchUnk1, &ConnectData);
	if (!NT_SUCCESS(Status)) {
		KdPrint(("GetTcpDispatches(): TcpTlProviderDispatch->Connect() failed with status 0x%08X\n", Status));
		return Status;
	}

	ASSERTMSG("GetTcpDispatches(): Epic fail", GetDispatchContext.Endpoint);

	// Deregister the endpoint

	if (GetDispatchContext.Endpoint) {
		Status = Dispatches->TcpTlProviderConnectDispatch->CloseEndpoint(GetDispatchContext.Endpoint, NULL);
		if (!NT_SUCCESS(Status)) {
			KdPrint(("GetTcpDispatches(): TcpTlProviderConnectDispatch->CloseEndpoint() failed with status 0x%08X\n", Status));
		}
	}

	if (!Dispatches->TcpTlProviderConnectDispatch) {
		KdPrint(("GetTcpDispatches(): TcpTlProviderDispatch->Connect() didn't return anything\n"));
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}



//
// Returns the original TcpTlProviderListenDispatch and
// TcpTlProviderConnectDispatch tables' handlers
//

static
NTSTATUS
  GetRealTcpDispatches(
	__inout PTL_DISPATCH_TABLES	Dispatches,
	__in PMEMORY_CHUNK				OriginalTcpip,
	__in PMEMORY_CHUNK				LoadedTcpip
	)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	ASSERT( Dispatches );
	ASSERT( OriginalTcpip );
	ASSERT( LoadedTcpip );

	ASSERT( Dispatches->TcpTlProviderConnectDispatch );
	ASSERT( Dispatches->TcpTlProviderListenDispatch );

	Status = GetRealTcpipDispatchTable(
		OriginalTcpip,
		LoadedTcpip,
		(PVOID*)Dispatches->TcpTlProviderConnectDispatch,
		(PVOID*)&Dispatches->RealTcpTlProviderConnectDispatch,
		sizeof(TL_PROVIDER_CONNECT_DISPATCH) / sizeof(PVOID));
	if (!NT_SUCCESS(Status)) {
		KdPrint(("GetRealTcpTlProviderListenDispatch(): GetRealTcpipDispatchTable(TcpTlProviderListenDispatch) failed with status 0x%08X\n",
			Status));
		return Status;
	}

	Status = GetRealTcpipDispatchTable(
		OriginalTcpip,
		LoadedTcpip,
		(PVOID*)Dispatches->TcpTlProviderListenDispatch,
		(PVOID*)&Dispatches->RealTcpTlProviderListenDispatch,
		sizeof(TL_PROVIDER_LISTEN_DISPATCH) / sizeof(PVOID));
	if (!NT_SUCCESS(Status)) {
		KdPrint(("GetRealTcpTlProviderListenDispatch(): GetRealTcpipDispatchTable(TcpTlProviderListenDispatch) failed with status 0x%08X\n",
			Status));
	}

	return Status;
}


//
// Returns the pointers on UdpTlProviderMessageDispatch and
// RawTlProviderMessageDispatch tables placed in tcpip.sys
//

static
NTSTATUS
  GetMessageDispatches(
	__inout PTL_DISPATCH_TABLES Dispatches
	)
{
	PROVIDER_DISPATCH_UNK1	DispatchUnk1 = {0};
	TL_ENDPOINT_DATA		MessageData = {0};
	GET_DISPATCH_CONTEXT	GetDispatchContext = {0};
	SOCKADDR_IN				Addr = {0};
	NTSTATUS				Status = STATUS_UNSUCCESSFUL;

	ASSERT( Dispatches );

	ASSERT( Dispatches->RealUdpTlProviderDispatch.Message );
	ASSERT( Dispatches->RealRawTlProviderDispatch.Message );

	Addr.sin_family = AF_INET;

	MessageData.GetDispatch			= GetDispatchCallback;
	MessageData.GetDispatchContext	= &GetDispatchContext;
	MessageData.Process				= PsGetCurrentProcess();
	MessageData.Thread				= PsGetCurrentThread();
	MessageData.Addr1				= &Addr;

	//
	// Get UdpTlProviderMessageDispatch
	//

	GetDispatchContext.DispatchTable = &Dispatches->UdpTlProviderMessageDispatch;
	GetDispatchContext.Endpoint = NULL;
	Dispatches->UdpTlProviderMessageDispatch = NULL;

	Status = Dispatches->RealUdpTlProviderDispatch.Message(&DispatchUnk1, &MessageData);
	if (!NT_SUCCESS(Status)) {
		KdPrint(("GetMessageDispatches(): UdpTlProviderDispatch->Message() failed with status 0x%08X\n", Status));
		return Status;
	}

	ASSERTMSG("GetMessageDispatches(): Epic fail", GetDispatchContext.Endpoint);

	// Deregister the endpoint

	if (GetDispatchContext.Endpoint) {
		Status = Dispatches->UdpTlProviderMessageDispatch->CloseEndpoint(GetDispatchContext.Endpoint, NULL);
		if (!NT_SUCCESS(Status)) {
			KdPrint(("GetMessageDispatches(): UdpTlProviderMessageDispatch->CloseEndpoint() failed with status 0x%08X\n", Status));
		}
	}

	if (!Dispatches->UdpTlProviderMessageDispatch) {
		KdPrint(("GetXxxTlProviderEndpointDispatch(): UdpTlProviderDispatch->Message() didn't return anything\n"));
		return STATUS_UNSUCCESSFUL;
	}

	//
	// Get RawTlProviderMessageDispatch
	//

	GetDispatchContext.DispatchTable = &Dispatches->RawTlProviderMessageDispatch;
	GetDispatchContext.Endpoint = NULL;
	Dispatches->RawTlProviderMessageDispatch = NULL;

	Status = Dispatches->RealRawTlProviderDispatch.Message(&DispatchUnk1, &MessageData);
	if (!NT_SUCCESS(Status)) {
		KdPrint(("GetMessageDispatches(): RawTlProviderDispatch->Message() failed with status 0x%08X\n", Status));
		return Status;
	}

	ASSERTMSG("GetMessageDispatches(): Epic fail", GetDispatchContext.Endpoint);

	// Deregister the endpoint

	if (GetDispatchContext.Endpoint) {
		Status = Dispatches->RawTlProviderMessageDispatch->CloseEndpoint(GetDispatchContext.Endpoint, NULL);
		if (!NT_SUCCESS(Status)) {
			KdPrint(("GetMessageDispatches(): RawTlProviderMessageDispatch->CloseEndpoint() failed with status 0x%08X\n", Status));
		}
	}

	if (!Dispatches->RawTlProviderMessageDispatch) {
		KdPrint(("GetMessageDispatches(): RawTlProviderDispatch->Message() didn't return anything\n"));
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

//
// Returns the original UdpTlProviderMessageDispatch and
// RawTlProviderMessageDispatch tables' handlers
//

static
NTSTATUS
  GetRealMessageDispatches(
	__inout PTL_DISPATCH_TABLES	Dispatches,
	__in PMEMORY_CHUNK				OriginalTcpip,
	__in PMEMORY_CHUNK				LoadedTcpip
	)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	ASSERT( Dispatches );
	ASSERT( OriginalTcpip );
	ASSERT( LoadedTcpip );

	ASSERT( Dispatches->UdpTlProviderMessageDispatch );
	ASSERT( Dispatches->RawTlProviderMessageDispatch );

	Status = GetRealTcpipDispatchTable(
		OriginalTcpip,
		LoadedTcpip,
		(PVOID*)Dispatches->UdpTlProviderMessageDispatch,
		(PVOID*)&Dispatches->RealUdpTlProviderMessageDispatch,
		sizeof(TL_PROVIDER_MESSAGE_DISPATCH) / sizeof(PVOID));
	if (!NT_SUCCESS(Status)) {
		KdPrint(("GetRealMessageDispatches(): GetRealTcpipDispatchTable(UdpTlProviderMessageDispatch) failed with status 0x%08X\n",
			Status));
		return Status;
	}

	Status = GetRealTcpipDispatchTable(
		OriginalTcpip,
		LoadedTcpip,
		(PVOID*)Dispatches->RawTlProviderMessageDispatch,
		(PVOID*)&Dispatches->RealRawTlProviderMessageDispatch,
		sizeof(TL_PROVIDER_MESSAGE_DISPATCH) / sizeof(PVOID));
	if (!NT_SUCCESS(Status)) {
		KdPrint(("GetRealMessageDispatches(): GetRealTcpipDispatchTable(RawTlProviderMessageDispatch) failed with status 0x%08X\n",
			Status));		
	}

	return Status;
}


//
// Retrieves the rest of dispatch tables; assumes that we got
// XxxTlProviderDispatch tables already
//

static
NTSTATUS
  GetInternalTcpipDispatchTables(
	__in PTL_DISPATCH_TABLES DispatchTables
  )
{

	MEMORY_CHUNK	OriginalTcpip = {0}, LoadedTcpip = {0};
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;

	ASSERT( DispatchTables );

	Status = GetTcpip(&OriginalTcpip, &LoadedTcpip);
	if (!NT_SUCCESS(Status)) {
		KdPrint(("GetInternalTcpipDispatchTables(): GetTcpip() failed with status 0x%08X\n", Status));
		return Status;
	}

	do
	{
		// Get the original XxxTlProviderDispatch tables' handlers

		Status = GetRealXxxTlProviderDispatch(DispatchTables, &OriginalTcpip, &LoadedTcpip);
		if (!NT_SUCCESS(Status)) {
			KdPrint(("GetInternalTcpipDispatchTables(): GetRealXxxTlProviderDispatch() failed with status 0x%08X\n", Status));
			break;
		}

		// Get the XxxTlProviderEndpointDispatch tables

		Status = GetEndpointDispatches(DispatchTables);
		if (!NT_SUCCESS(Status)) {
			KdPrint(("GetInternalTcpipDispatchTables(): GetEndpointDispatches() failed with status 0x%08X\n", Status));
			break;
		}

		// Get the original XxxTlProviderEndpointDispatch tables' handlers

		Status = GetRealXxxTlProviderEndpointDispatch(DispatchTables, &OriginalTcpip, &LoadedTcpip);
		if (!NT_SUCCESS(Status)) {
			KdPrint(("GetInternalTcpipDispatchTables(): GetRealXxxTlProviderEndpointDispatch() failed with status 0x%08X\n", Status));
			break;
		}

		// Get TcpTlProviderListenDispatch and TcpTlProviderConnectDispatch tables

		Status = GetTcpDispatches(DispatchTables);
		if (!NT_SUCCESS(Status)) {
			KdPrint(("GetInternalTcpipDispatchTables(): GetTcpDispatches() failed with status 0x%08X\n", Status));
			break;
		}

		// Get the original TcpTlProviderListenDispatch and TcpTlProviderConnectDispatch tables' handlers

		Status = GetRealTcpDispatches(DispatchTables, &OriginalTcpip, &LoadedTcpip);
		if (!NT_SUCCESS(Status)) {
			KdPrint(("GetInternalTcpipDispatchTables(): GetRealTcpDispatches() failed with status 0x%08X\n", Status));
			break;
		}

		// Get UdpTlProviderMessageDispatch and RawTlProviderMessageDispatch tables

		Status = GetMessageDispatches(DispatchTables);
		if (!NT_SUCCESS(Status)) {
			KdPrint(("GetInternalTcpipDispatchTables(): GetMessageDispatches() failed with status 0x%08X\n", Status));
			break;
		}

		// Get the original UdpTlProviderMessageDispatch and RawTlProviderMessageDispatch tables' handlers

		Status = GetRealMessageDispatches(DispatchTables, &OriginalTcpip, &LoadedTcpip);
		if (!NT_SUCCESS(Status)) {
			KdPrint(("GetInternalTcpipDispatchTables(): GetRealMessageDispatches() failed with status 0x%08X\n", Status));
			break;
		}

	} while (0);

	FreeMemoryChunk(&LoadedTcpip);
	return Status;
}




//
// NMR calls this function in the case of attaching to
// the transport provider tcpip.sys
//

static
NTSTATUS
NTAPI
  FakeClientAttachProvider(
    __in HANDLE NmrBindingHandle,
    __in PTL_DISPATCH_TABLES DispatchTables,
    __in PNPI_REGISTRATION_INSTANCE ProviderRegistrationInstance
    )
{
	NTSTATUS	Status = STATUS_NOINTERFACE;
	PVOID		ProviderContext = NULL;

	ASSERT( DispatchTables );
	ASSERT( ProviderRegistrationInstance );

	if (!memcmp(ProviderRegistrationInstance->ModuleId, &NPI_MS_TCP_MODULEID, sizeof(NPI_MODULEID)))
	{
		ASSERT( !DispatchTables->TcpTlProviderDispatch );

		// Get TcpTlProviderDispatch table

		Status = NmrClientAttachProvider(
			NmrBindingHandle, NULL, NULL, &ProviderContext, &DispatchTables->TcpTlProviderDispatch);
		if (!NT_SUCCESS(Status)) {
			KdPrint(("FakeClientAttachProvider(): NmrClientAttachProvider(TcpTlProviderDispatch) failed with status 0x%08X\n", Status));
		}
	}
	else if (!memcmp(ProviderRegistrationInstance->ModuleId, &NPI_MS_UDP_MODULEID, sizeof(NPI_MODULEID)))
	{
		ASSERT( !DispatchTables->UdpTlProviderDispatch );

		// Get UdpTlProviderDispatch table

		Status = NmrClientAttachProvider(
			NmrBindingHandle, NULL, NULL, &ProviderContext, &DispatchTables->UdpTlProviderDispatch);
		if (!NT_SUCCESS(Status)) {
			KdPrint(("FakeClientAttachProvider(): NmrClientAttachProvider(UdpTlProviderDispatch) failed with status 0x%08X\n", Status));
		}
	}
	else if (!memcmp(ProviderRegistrationInstance->ModuleId, &NPI_MS_RAW_MODULEID, sizeof(NPI_MODULEID)))
	{
		ASSERT( !DispatchTables->RawTlProviderDispatch );

		// Get RawTlProviderDispatch table

		Status = NmrClientAttachProvider(
			NmrBindingHandle, NULL, NULL, &ProviderContext, &DispatchTables->RawTlProviderDispatch);
		if (!NT_SUCCESS(Status)) {
			KdPrint(("FakeClientAttachProvider(): NmrClientAttachProvider(RawTlProviderDispatch) failed with status 0x%08X\n", Status));
		}
	}

	return Status;
}

//
// NMR calls this function in the case of detaching from
// the transport provider tcpip.sys
//

static
NTSTATUS
NTAPI
  FakeClientDetachProvider(
    __in PVOID  ClientBindingContext
    )
{
	return STATUS_SUCCESS;
}

//
// Returns the pointers on XxxTlProviderXxxDispatch tables
// and their internals
//

NTSTATUS
NTAPI
  GetTcpipDispatchTables(
	__in  PLDR_DATA_TABLE_ENTRY		DriverEntry,
	__out PTL_DISPATCH_TABLES		DispatchTables
  )
{
	HANDLE			hClientHandle = NULL;
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;
	UNICODE_STRING	OriginalFullDllName = {0};

	NPI_MODULEID FakeModuleId = {
		sizeof(NPI_MODULEID),
		MIT_GUID,
		{0x01020304, 0x0506, 0x0708,
		{0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}}
	};

	NPI_CLIENT_CHARACTERISTICS ClientChars = {
		0, sizeof(NPI_CLIENT_CHARACTERISTICS), FakeClientAttachProvider, FakeClientDetachProvider, NULL,
		{0, sizeof(NPI_REGISTRATION_INSTANCE), &NPI_TRANSPORT_LAYER_ID, &FakeModuleId, 0, NULL}
	};

	if (!DriverEntry || !DispatchTables)
		return STATUS_INVALID_PARAMETER;

	ASSERT( (ULONG_PTR)FakeClientAttachProvider > (ULONG_PTR)DriverEntry->DllBase &&
			(ULONG_PTR)FakeClientAttachProvider < (ULONG_PTR)DriverEntry->DllBase + DriverEntry->SizeOfImage );

	RtlZeroMemory(DispatchTables, sizeof(TL_DISPATCH_TABLES));

	// We pretend to be afd.sys for the moment

	RtlCopyMemory(&OriginalFullDllName, &DriverEntry->FullDllName, sizeof(UNICODE_STRING));
	RtlInitUnicodeString(&DriverEntry->FullDllName, L"\\SystemRoot\\system32\\drivers\\afd.sys");

	Status = NmrRegisterClient(&ClientChars, DispatchTables, &hClientHandle);
	if (NT_SUCCESS(Status)) {
		NmrDeregisterClient(hClientHandle);
	} else {
		KdPrint(("GetTcpipDispatchTables(): NmrRegisterClient() failed with status 0x%08X\n", Status));
	}

	// Restore the previous FullDllName

	RtlCopyMemory(&DriverEntry->FullDllName, &OriginalFullDllName, sizeof(UNICODE_STRING));

	if (!NT_SUCCESS(Status))
		return Status;

	if (!DispatchTables->TcpTlProviderDispatch ||
		!DispatchTables->UdpTlProviderDispatch ||
		!DispatchTables->RawTlProviderDispatch)
	{
		return STATUS_UNSUCCESSFUL;
	}

	// Get the rest of the handlers

	Status = GetInternalTcpipDispatchTables(DispatchTables);
	if (!NT_SUCCESS(Status)) {
		KdPrint(("GetTcpipDispatchTables(): GetInternalTcpipDispatchTables() failed with status 0x%08X\n", Status));
	}

	return Status;
}