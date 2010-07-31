/*++

Module Name:

    npisubvert.c

Abstract:

    NPI firewalls subvert example

Author:

    MaD, 12-May-2009

--*/

#include "npisubvert.h"
#include "gettl.h"
#include "unhooktl.h"
#include "tools.h"


//
// Prints the internals of XxxTlProviderDispatch to the debug output
//

static
VOID
  PrintProviderDispatch(
	__in PCHAR					VarName,
	__in PTL_PROVIDER_DISPATCH	Dispatch,
	__in PTL_PROVIDER_DISPATCH	RealDispatch
  )
{
	PRTL_PROCESS_MODULE_INFORMATION ModuleInfo = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	ASSERT( VarName );
	ASSERT( Dispatch );
	ASSERT( RealDispatch );

	DbgPrint("%s:         0x%p\n",
		VarName,
		Dispatch);

	DbgPrint("    IoControl:                 0x%p (0x%p real) %s%s\n",
		Dispatch->IoControl,
		RealDispatch->IoControl,
		Dispatch->IoControl == RealDispatch->IoControl ? "" : "HOOKED by ",
		Dispatch->IoControl == RealDispatch->IoControl ? "" :
		( NT_SUCCESS(Status = GetKernelModuleInfo(Dispatch->IoControl, &ModuleInfo)) ?
			ModuleInfo->FullPathName + ModuleInfo->OffsetToFileName : "unknown" ));

	if (NT_SUCCESS(Status)) {
		ExFreePool(ModuleInfo);
		Status = STATUS_UNSUCCESSFUL;
	}

	DbgPrint("    QueryDispatch:             0x%p (0x%p real) %s%s\n",
		Dispatch->QueryDispatch,
		RealDispatch->QueryDispatch,
		Dispatch->QueryDispatch == RealDispatch->QueryDispatch ? "" : "HOOKED by ",
		Dispatch->QueryDispatch == RealDispatch->QueryDispatch ? "" :
		( NT_SUCCESS(Status = GetKernelModuleInfo(Dispatch->QueryDispatch, &ModuleInfo)) ?
			ModuleInfo->FullPathName + ModuleInfo->OffsetToFileName : "unknown" ));

	if (NT_SUCCESS(Status)) {
		ExFreePool(ModuleInfo);
		Status = STATUS_UNSUCCESSFUL;
	}

	DbgPrint("    Endpoint:                  0x%p (0x%p real) %s%s\n",
		Dispatch->Endpoint,
		RealDispatch->Endpoint,
		Dispatch->Endpoint == RealDispatch->Endpoint ? "" : "HOOKED by ",
		Dispatch->Endpoint == RealDispatch->Endpoint ? "" :
		( NT_SUCCESS(Status = GetKernelModuleInfo(Dispatch->Endpoint, &ModuleInfo)) ?
			ModuleInfo->FullPathName + ModuleInfo->OffsetToFileName : "unknown" ));

	if (NT_SUCCESS(Status)) {
		ExFreePool(ModuleInfo);
		Status = STATUS_UNSUCCESSFUL;
	}

	DbgPrint("    Message:                   0x%p (0x%p real) %s%s\n",
		Dispatch->Message,
		RealDispatch->Message,
		Dispatch->Message == RealDispatch->Message ? "" : "HOOKED by ",
		Dispatch->Message == RealDispatch->Message ? "" :
		( NT_SUCCESS(Status = GetKernelModuleInfo(Dispatch->Message, &ModuleInfo)) ?
			ModuleInfo->FullPathName + ModuleInfo->OffsetToFileName : "unknown" ));

	if (NT_SUCCESS(Status)) {
		ExFreePool(ModuleInfo);
		Status = STATUS_UNSUCCESSFUL;
	}

	DbgPrint("    Listen:                    0x%p (0x%p real) %s%s\n",
		Dispatch->Listen,
		RealDispatch->Listen,
		Dispatch->Listen == RealDispatch->Listen ? "" : "HOOKED by ",
		Dispatch->Listen == RealDispatch->Listen ? "" :
		( NT_SUCCESS(Status = GetKernelModuleInfo(Dispatch->Listen, &ModuleInfo)) ?
			ModuleInfo->FullPathName + ModuleInfo->OffsetToFileName : "unknown" ));

	if (NT_SUCCESS(Status)) {
		ExFreePool(ModuleInfo);
		Status = STATUS_UNSUCCESSFUL;
	}

	DbgPrint("    ReleaseIndicationList:     0x%p (0x%p real) %s%s\n",
		Dispatch->ReleaseIndicationList,
		RealDispatch->ReleaseIndicationList,
		Dispatch->ReleaseIndicationList == RealDispatch->ReleaseIndicationList ? "" : "HOOKED by ",
		Dispatch->ReleaseIndicationList == RealDispatch->ReleaseIndicationList ? "" :
		( NT_SUCCESS(Status = GetKernelModuleInfo(Dispatch->ReleaseIndicationList, &ModuleInfo)) ?
			ModuleInfo->FullPathName + ModuleInfo->OffsetToFileName : "unknown" ));

	if (NT_SUCCESS(Status)) {
		ExFreePool(ModuleInfo);
		Status = STATUS_UNSUCCESSFUL;
	}

	DbgPrint("    Cancel:                    0x%p (0x%p real) %s%s\n",
		Dispatch->Cancel,
		RealDispatch->Cancel,
		Dispatch->Cancel == RealDispatch->Cancel ? "" : "HOOKED by ",
		Dispatch->Cancel == RealDispatch->Cancel ? "" :
		( NT_SUCCESS(Status = GetKernelModuleInfo(Dispatch->Cancel, &ModuleInfo)) ?
			ModuleInfo->FullPathName + ModuleInfo->OffsetToFileName : "unknown" ));

	if (NT_SUCCESS(Status)) {
		ExFreePool(ModuleInfo);
	}

	DbgPrint("\n");
}

//
// Prints the internals of XxxTlProviderEndpointDispatch to the debug output
//

static
VOID
  PrintProviderEndpointDispatch(
	__in PCHAR						VarName,
	__in PTL_ENDPOINT_DATA_DISPATCH	Dispatch,
	__in PTL_ENDPOINT_DATA_DISPATCH	RealDispatch
  )
{
	PRTL_PROCESS_MODULE_INFORMATION ModuleInfo = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	ASSERT( VarName );
	ASSERT( Dispatch );
	ASSERT( RealDispatch );

	DbgPrint("%s: 0x%p\n",
		VarName,
		Dispatch);

	DbgPrint("    CloseEndpoint:             0x%p (0x%p real) %s%s\n",
		Dispatch->CloseEndpoint,
		RealDispatch->CloseEndpoint,
		Dispatch->CloseEndpoint == RealDispatch->CloseEndpoint ? "" : "HOOKED by ",
		Dispatch->CloseEndpoint == RealDispatch->CloseEndpoint ? "" :
		( NT_SUCCESS(Status = GetKernelModuleInfo(Dispatch->CloseEndpoint, &ModuleInfo)) ?
			ModuleInfo->FullPathName + ModuleInfo->OffsetToFileName : "unknown" ));

	if (NT_SUCCESS(Status)) {
		ExFreePool(ModuleInfo);
		Status = STATUS_UNSUCCESSFUL;
	}

	DbgPrint("    IoControlEndpoint:         0x%p (0x%p real) %s%s\n",
		Dispatch->IoControlEndpoint,
		RealDispatch->IoControlEndpoint,
		Dispatch->IoControlEndpoint == RealDispatch->IoControlEndpoint ? "" : "HOOKED by ",
		Dispatch->IoControlEndpoint == RealDispatch->IoControlEndpoint ? "" :
		( NT_SUCCESS(Status = GetKernelModuleInfo(Dispatch->IoControlEndpoint, &ModuleInfo)) ?
			ModuleInfo->FullPathName + ModuleInfo->OffsetToFileName : "unknown" ));

	if (NT_SUCCESS(Status)) {
		ExFreePool(ModuleInfo);
		Status = STATUS_UNSUCCESSFUL;
	}

	DbgPrint("    QueryDispatchEndpoint:     0x%p (0x%p real) %s%s\n",
		Dispatch->QueryDispatchEndpoint,
		RealDispatch->QueryDispatchEndpoint,
		Dispatch->QueryDispatchEndpoint == RealDispatch->QueryDispatchEndpoint ? "" : "HOOKED by ",
		Dispatch->QueryDispatchEndpoint == RealDispatch->QueryDispatchEndpoint ? "" :
		( NT_SUCCESS(Status = GetKernelModuleInfo(Dispatch->QueryDispatchEndpoint, &ModuleInfo)) ?
			ModuleInfo->FullPathName + ModuleInfo->OffsetToFileName : "unknown" ));

	if (NT_SUCCESS(Status)) {
		ExFreePool(ModuleInfo);
	}

	DbgPrint("\n");
}

//
// Prints the internals of TcpTlProviderConnectDispatch to the debug output
//

static
VOID
  PrintProviderConnectDispatch(
	__in PTL_PROVIDER_CONNECT_DISPATCH	Dispatch,
	__in PTL_PROVIDER_CONNECT_DISPATCH	RealDispatch
  )
{
	PRTL_PROCESS_MODULE_INFORMATION ModuleInfo = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	ASSERT( Dispatch );
	ASSERT( RealDispatch );

	DbgPrint("TcpTlProviderConnectDispatch:  0x%p\n",
		Dispatch);

	DbgPrint("    CloseEndpoint:             0x%p (0x%p real) %s%s\n",
		Dispatch->CloseEndpoint,
		RealDispatch->CloseEndpoint,
		Dispatch->CloseEndpoint == RealDispatch->CloseEndpoint ? "" : "HOOKED by ",
		Dispatch->CloseEndpoint == RealDispatch->CloseEndpoint ? "" :
		( NT_SUCCESS(Status = GetKernelModuleInfo(Dispatch->CloseEndpoint, &ModuleInfo)) ?
			ModuleInfo->FullPathName + ModuleInfo->OffsetToFileName : "unknown" ));

	if (NT_SUCCESS(Status)) {
		ExFreePool(ModuleInfo);
		Status = STATUS_UNSUCCESSFUL;
	}

	DbgPrint("    IoControlEndpoint:         0x%p (0x%p real) %s%s\n",
		Dispatch->IoControlEndpoint,
		RealDispatch->IoControlEndpoint,
		Dispatch->IoControlEndpoint == RealDispatch->IoControlEndpoint ? "" : "HOOKED by ",
		Dispatch->IoControlEndpoint == RealDispatch->IoControlEndpoint ? "" :
		( NT_SUCCESS(Status = GetKernelModuleInfo(Dispatch->IoControlEndpoint, &ModuleInfo)) ?
			ModuleInfo->FullPathName + ModuleInfo->OffsetToFileName : "unknown" ));

	if (NT_SUCCESS(Status)) {
		ExFreePool(ModuleInfo);
		Status = STATUS_UNSUCCESSFUL;
	}

	DbgPrint("    QueryDispatchEndpoint:     0x%p (0x%p real) %s%s\n",
		Dispatch->QueryDispatchEndpoint,
		RealDispatch->QueryDispatchEndpoint,
		Dispatch->QueryDispatchEndpoint == RealDispatch->QueryDispatchEndpoint ? "" : "HOOKED by ",
		Dispatch->QueryDispatchEndpoint == RealDispatch->QueryDispatchEndpoint ? "" :
		( NT_SUCCESS(Status = GetKernelModuleInfo(Dispatch->QueryDispatchEndpoint, &ModuleInfo)) ?
			ModuleInfo->FullPathName + ModuleInfo->OffsetToFileName : "unknown" ));

	if (NT_SUCCESS(Status)) {
		ExFreePool(ModuleInfo);
		Status = STATUS_UNSUCCESSFUL;
	}

	DbgPrint("    Send:                      0x%p (0x%p real) %s%s\n",
		Dispatch->Send,
		RealDispatch->Send,
		Dispatch->Send == RealDispatch->Send ? "" : "HOOKED by ",
		Dispatch->Send == RealDispatch->Send ? "" :
		( NT_SUCCESS(Status = GetKernelModuleInfo(Dispatch->Send, &ModuleInfo)) ?
			ModuleInfo->FullPathName + ModuleInfo->OffsetToFileName : "unknown" ));

	if (NT_SUCCESS(Status)) {
		ExFreePool(ModuleInfo);
		Status = STATUS_UNSUCCESSFUL;
	}

	DbgPrint("    Receive:                   0x%p (0x%p real) %s%s\n",
		Dispatch->Receive,
		RealDispatch->Receive,
		Dispatch->Receive == RealDispatch->Receive ? "" : "HOOKED by ",
		Dispatch->Receive == RealDispatch->Receive ? "" :
		( NT_SUCCESS(Status = GetKernelModuleInfo(Dispatch->Receive, &ModuleInfo)) ?
			ModuleInfo->FullPathName + ModuleInfo->OffsetToFileName : "unknown" ));

	if (NT_SUCCESS(Status)) {
		ExFreePool(ModuleInfo);
		Status = STATUS_UNSUCCESSFUL;
	}

	DbgPrint("    Disconnect:                0x%p (0x%p real) %s%s\n",
		Dispatch->Disconnect,
		RealDispatch->Disconnect,
		Dispatch->Disconnect == RealDispatch->Disconnect ? "" : "HOOKED by ",
		Dispatch->Disconnect == RealDispatch->Disconnect ? "" :
		( NT_SUCCESS(Status = GetKernelModuleInfo(Dispatch->Disconnect, &ModuleInfo)) ?
			ModuleInfo->FullPathName + ModuleInfo->OffsetToFileName : "unknown" ));

	if (NT_SUCCESS(Status)) {
		ExFreePool(ModuleInfo);
	}

	DbgPrint("\n");
}

//
// Prints the internals of TcpTlProviderListenDispatch to the debug output
//

static
VOID
  PrintProviderListenDispatch(
	__in PTL_PROVIDER_LISTEN_DISPATCH	Dispatch,
	__in PTL_PROVIDER_LISTEN_DISPATCH	RealDispatch
  )
{
	PRTL_PROCESS_MODULE_INFORMATION ModuleInfo = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	ASSERT( Dispatch );
	ASSERT( RealDispatch );

	DbgPrint("TcpTlProviderListenDispatch:   0x%p\n",
		Dispatch);

	DbgPrint("    CloseEndpoint:             0x%p (0x%p real) %s%s\n",
		Dispatch->CloseEndpoint,
		RealDispatch->CloseEndpoint,
		Dispatch->CloseEndpoint == RealDispatch->CloseEndpoint ? "" : "HOOKED by ",
		Dispatch->CloseEndpoint == RealDispatch->CloseEndpoint ? "" :
		( NT_SUCCESS(Status = GetKernelModuleInfo(Dispatch->CloseEndpoint, &ModuleInfo)) ?
			ModuleInfo->FullPathName + ModuleInfo->OffsetToFileName : "unknown" ));

	if (NT_SUCCESS(Status)) {
		ExFreePool(ModuleInfo);
		Status = STATUS_UNSUCCESSFUL;
	}

	DbgPrint("    IoControlEndpoint:         0x%p (0x%p real) %s%s\n",
		Dispatch->IoControlEndpoint,
		RealDispatch->IoControlEndpoint,
		Dispatch->IoControlEndpoint == RealDispatch->IoControlEndpoint ? "" : "HOOKED by ",
		Dispatch->IoControlEndpoint == RealDispatch->IoControlEndpoint ? "" :
		( NT_SUCCESS(Status = GetKernelModuleInfo(Dispatch->IoControlEndpoint, &ModuleInfo)) ?
			ModuleInfo->FullPathName + ModuleInfo->OffsetToFileName : "unknown" ));

	if (NT_SUCCESS(Status)) {
		ExFreePool(ModuleInfo);
		Status = STATUS_UNSUCCESSFUL;
	}

	DbgPrint("    QueryDispatchEndpoint:     0x%p (0x%p real) %s%s\n",
		Dispatch->QueryDispatchEndpoint,
		RealDispatch->QueryDispatchEndpoint,
		Dispatch->QueryDispatchEndpoint == RealDispatch->QueryDispatchEndpoint ? "" : "HOOKED by ",
		Dispatch->QueryDispatchEndpoint == RealDispatch->QueryDispatchEndpoint ? "" :
		( NT_SUCCESS(Status = GetKernelModuleInfo(Dispatch->QueryDispatchEndpoint, &ModuleInfo)) ?
			ModuleInfo->FullPathName + ModuleInfo->OffsetToFileName : "unknown" ));

	if (NT_SUCCESS(Status)) {
		ExFreePool(ModuleInfo);
		Status = STATUS_UNSUCCESSFUL;
	}

	DbgPrint("    ResumeConnection:          0x%p (0x%p real) %s%s\n",
		Dispatch->ResumeConnection,
		RealDispatch->ResumeConnection,
		Dispatch->ResumeConnection == RealDispatch->ResumeConnection ? "" : "HOOKED by ",
		Dispatch->ResumeConnection == RealDispatch->ResumeConnection ? "" :
		( NT_SUCCESS(Status = GetKernelModuleInfo(Dispatch->ResumeConnection, &ModuleInfo)) ?
			ModuleInfo->FullPathName + ModuleInfo->OffsetToFileName : "unknown" ));

	if (NT_SUCCESS(Status)) {
		ExFreePool(ModuleInfo);
	}

	DbgPrint("\n");
}


//
// Prints the internals of XxxTlProviderMessageDispatch to the debug output
//

static
VOID
  PrintProviderMessageDispatch(
	__in PCHAR							VarName,
	__in PTL_PROVIDER_MESSAGE_DISPATCH	Dispatch,
	__in PTL_PROVIDER_MESSAGE_DISPATCH	RealDispatch
  )
{
	PRTL_PROCESS_MODULE_INFORMATION ModuleInfo = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	ASSERT( VarName );
	ASSERT( Dispatch );
	ASSERT( RealDispatch );

	DbgPrint("%s:  0x%p\n",
		VarName,
		Dispatch);

	DbgPrint("    CloseEndpoint:             0x%p (0x%p real) %s%s\n",
		Dispatch->CloseEndpoint,
		RealDispatch->CloseEndpoint,
		Dispatch->CloseEndpoint == RealDispatch->CloseEndpoint ? "" : "HOOKED by ",
		Dispatch->CloseEndpoint == RealDispatch->CloseEndpoint ? "" :
		( NT_SUCCESS(Status = GetKernelModuleInfo(Dispatch->CloseEndpoint, &ModuleInfo)) ?
			ModuleInfo->FullPathName + ModuleInfo->OffsetToFileName : "unknown" ));

	if (NT_SUCCESS(Status)) {
		ExFreePool(ModuleInfo);
		Status = STATUS_UNSUCCESSFUL;
	}

	DbgPrint("    IoControlEndpoint:         0x%p (0x%p real) %s%s\n",
		Dispatch->IoControlEndpoint,
		RealDispatch->IoControlEndpoint,
		Dispatch->IoControlEndpoint == RealDispatch->IoControlEndpoint ? "" : "HOOKED by ",
		Dispatch->IoControlEndpoint == RealDispatch->IoControlEndpoint ? "" :
		( NT_SUCCESS(Status = GetKernelModuleInfo(Dispatch->IoControlEndpoint, &ModuleInfo)) ?
			ModuleInfo->FullPathName + ModuleInfo->OffsetToFileName : "unknown" ));

	if (NT_SUCCESS(Status)) {
		ExFreePool(ModuleInfo);
		Status = STATUS_UNSUCCESSFUL;
	}

	DbgPrint("    QueryDispatchEndpoint:     0x%p (0x%p real) %s%s\n",
		Dispatch->QueryDispatchEndpoint,
		RealDispatch->QueryDispatchEndpoint,
		Dispatch->QueryDispatchEndpoint == RealDispatch->QueryDispatchEndpoint ? "" : "HOOKED by ",
		Dispatch->QueryDispatchEndpoint == RealDispatch->QueryDispatchEndpoint ? "" :
		( NT_SUCCESS(Status = GetKernelModuleInfo(Dispatch->QueryDispatchEndpoint, &ModuleInfo)) ?
			ModuleInfo->FullPathName + ModuleInfo->OffsetToFileName : "unknown" ));

	if (NT_SUCCESS(Status)) {
		ExFreePool(ModuleInfo);
		Status = STATUS_UNSUCCESSFUL;
	}

	DbgPrint("    SendMessages:              0x%p (0x%p real) %s%s\n",
		Dispatch->SendMessages,
		RealDispatch->SendMessages,
		Dispatch->SendMessages == RealDispatch->SendMessages ? "" : "HOOKED by ",
		Dispatch->SendMessages == RealDispatch->SendMessages ? "" :
		( NT_SUCCESS(Status = GetKernelModuleInfo(Dispatch->SendMessages, &ModuleInfo)) ?
			ModuleInfo->FullPathName + ModuleInfo->OffsetToFileName : "unknown" ));

	if (NT_SUCCESS(Status)) {
		ExFreePool(ModuleInfo);
	}

	DbgPrint("\n");
}


static
VOID
NTAPI
  DriverUnload(
	__in PDRIVER_OBJECT DriverObject
	)
{

}

NTSTATUS
NTAPI
  DriverEntry(
	__in PDRIVER_OBJECT		DriverObject,
	__in PUNICODE_STRING	RegPath
	)
{
	UNICODE_STRING		TcpipDriverName = CONST_UNICODE_STRING(L"\\Driver\\tcpip");
	MEMORY_CHUNK		Tcpip = {0};
	TL_DISPATCH_TABLES	DispatchTables = {0};
	NTSTATUS			Status = STATUS_UNSUCCESSFUL;
	
	Status = GetDriverModuleInfo(&TcpipDriverName, &Tcpip.Buffer, &Tcpip.Size);
	if (!NT_SUCCESS(Status)) {
		DbgPrint("DriverEntry(): GetDriverModuleInfo(%wZ) failed with status 0x%08X\n", &TcpipDriverName, Status);
		return Status;
	}

	Status = GetTcpipDispatchTables((PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection, &DispatchTables);
	if (!NT_SUCCESS(Status)) {
		DbgPrint("DriverEntry(): GetTcpipDispatchTables() failed with status 0x%08X\n", Status);
		return Status;
	}

	DbgPrint("TCPIP.SYS image region:        0x%p..0x%p\n\n",
		Tcpip.Buffer, (ULONG_PTR)Tcpip.Buffer + Tcpip.Size);

	PrintProviderDispatch(
		"TcpTlProviderDispatch",
		DispatchTables.TcpTlProviderDispatch,
		&DispatchTables.RealTcpTlProviderDispatch);
	PrintProviderEndpointDispatch(
		"TcpTlProviderEndpointDispatch",
		DispatchTables.TcpTlProviderEndpointDispatch,
		&DispatchTables.RealTcpTlProviderEndpointDispatch);
	PrintProviderConnectDispatch(
		DispatchTables.TcpTlProviderConnectDispatch,
		&DispatchTables.RealTcpTlProviderConnectDispatch);
	PrintProviderListenDispatch(
		DispatchTables.TcpTlProviderListenDispatch,
		&DispatchTables.RealTcpTlProviderListenDispatch);

	PrintProviderDispatch(
		"UdpTlProviderDispatch",
		DispatchTables.UdpTlProviderDispatch,
		&DispatchTables.RealUdpTlProviderDispatch);
	PrintProviderEndpointDispatch(
		"UdpTlProviderEndpointDispatch",
		DispatchTables.UdpTlProviderEndpointDispatch,
		&DispatchTables.RealUdpTlProviderEndpointDispatch);
	PrintProviderMessageDispatch(
		"UdpTlProviderMessageDispatch",
		DispatchTables.UdpTlProviderMessageDispatch,
		&DispatchTables.RealUdpTlProviderMessageDispatch);

	PrintProviderDispatch(
		"RawTlProviderDispatch",
		DispatchTables.RawTlProviderDispatch,
		&DispatchTables.RealRawTlProviderDispatch);
	PrintProviderEndpointDispatch(
		"RawTlProviderEndpointDispatch",
		DispatchTables.RawTlProviderEndpointDispatch,
		&DispatchTables.RealRawTlProviderEndpointDispatch);
	PrintProviderMessageDispatch(
		"RawTlProviderMessageDispatch",
		DispatchTables.RawTlProviderMessageDispatch,
		&DispatchTables.RealRawTlProviderMessageDispatch);

	Status = UnhookNPI(&DispatchTables);
	if (!NT_SUCCESS(Status)) {
		DbgPrint("DriverEntry(): UnhookNPI() failed with status 0x%08X\n", Status);
		return Status;
	}

	DbgPrint("The NPI hooks have been cleaned successfully\n");

	DriverObject->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;

}