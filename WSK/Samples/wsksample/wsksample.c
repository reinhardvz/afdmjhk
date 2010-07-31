/*++

Module Name:

    wsksample.c

Abstract:

    The WSK sample connects to the rootkit.com, retrieves
	the current date and prints it to the debug output

Author:

    MaD, 12-May-2009

--*/

#include "wsksample.h"

static PETHREAD		g_ConnectionThread;
static KEVENT		g_ConnectionThreadShutdownEvent;

static WSK_REGISTRATION		g_WskRegistration;
static WSK_PROVIDER_NPI		g_WskProvider;
static WSK_CLIENT_DISPATCH	g_WskDispatch = {MAKE_WSK_VERSION(1,0), 0, NULL};

#define BUFFER_SIZE						0x400
#define WSK_CAPTURE_WAIT_TIMEOUT_MSEC	5 * 1000
#define CONNECT_CYCLE_TIMEOUT_SECONDS	5

#define HOST_NAME		"google.com"
#define HOST_ADDRESS	IP4_ADDR(74,125,45,100)
#define HOST_PORT		80



//
// Just signals the completion event
//

static
NTSTATUS
NTAPI
  CompletionRoutine(
    __in PDEVICE_OBJECT	DeviceObject,
    __in PIRP			Irp,
    __in PKEVENT		CompletionEvent
    )
{
	ASSERT( CompletionEvent );

	KeSetEvent(CompletionEvent, IO_NO_INCREMENT, FALSE);
	return STATUS_MORE_PROCESSING_REQUIRED;
}



//
// Initializes the WSK_BUF structure which can be passed to the WSK functions
//

static
NTSTATUS
  InitializeWskBuffer(
	__in  PVOID		HttpResponse,
	__in  ULONG		BufferSize,
	__out PWSK_BUF	WskHttpResponse
	)
{
	NTSTATUS Status = STATUS_SUCCESS;

	ASSERT( HttpResponse );
	ASSERT( BufferSize );
	ASSERT( WskHttpResponse );

	WskHttpResponse->Offset = 0;
	WskHttpResponse->Length = BufferSize;

	WskHttpResponse->Mdl = IoAllocateMdl(HttpResponse, BufferSize, FALSE, FALSE, NULL);
	if (!WskHttpResponse->Mdl) {
		DbgPrint("InitializeWskBuffer(): IoAllocateMdl(%p) failed\n", HttpResponse);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	__try {
		MmProbeAndLockPages(WskHttpResponse->Mdl, KernelMode, IoWriteAccess);
	}
	__except(EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint("InitializeWskBuffer(): MmProbeAndLockPages(%p) failed\n", HttpResponse);
		IoFreeMdl(WskHttpResponse->Mdl);
		Status = STATUS_ACCESS_VIOLATION;
	}

	return Status;
}

//
// Frees the memory which had been previously allocated by InitializeWskBuffer()
//

static
VOID
  DeinitializeWskBuffer(
	__in PWSK_BUF	WskHttpResponse
	)
{
	ASSERT( WskHttpResponse );

	MmUnlockPages(WskHttpResponse->Mdl);
	IoFreeMdl(WskHttpResponse->Mdl);
}


//
// Closes the WSK socket
//

static
NTSTATUS
  CloseWskSocket(
	__in PWSK_PROVIDER_CONNECTION_DISPATCH SocketDispatch,
	__in PWSK_SOCKET WskSocket
  )
{
	KEVENT		CompletionEvent = {0};
	PIRP		Irp = NULL;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

	ASSERT( SocketDispatch );
	ASSERT( WskSocket );

	Irp = IoAllocateIrp(1, FALSE);
	if (!Irp) {
		DbgPrint("CloseWskSocket(): IoAllocateIrp() failed\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	KeInitializeEvent(&CompletionEvent, SynchronizationEvent, FALSE);
	IoSetCompletionRoutine(Irp, CompletionRoutine, &CompletionEvent, TRUE, TRUE, TRUE);

	//
	// Close the socket
	//

	Status = SocketDispatch->WskCloseSocket(WskSocket, Irp);
	if (Status == STATUS_PENDING) {
		KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
		Status = Irp->IoStatus.Status;
	}

	if (!NT_SUCCESS(Status)) {
		DbgPrint("CloseWskSocket(): WskCloseSocket() failed with status 0x%08X\n", Status);
	}

	IoFreeIrp(Irp);
	return Status;
}

//
// Allocates NumberOfBytes bytes of memory and
// fills the WSK_BUF structure
//

static
PVOID
  AllocateWskBuffer(
	__in  POOL_TYPE		PoolType,
	__in  SIZE_T		NumberOfBytes,
	__out PWSK_BUF		WskBuffer
  )
{
	PVOID Buffer = NULL;

	ASSERT( NumberOfBytes );
	ASSERT( WskBuffer );

	if (Buffer = ExAllocatePool(PoolType, NumberOfBytes))
	{
		NTSTATUS Status = InitializeWskBuffer(Buffer, (ULONG)NumberOfBytes, WskBuffer);
		if (!NT_SUCCESS(Status)) {
			ExFreePool(Buffer);
			Buffer = NULL;
		}
	}

	return Buffer;
}


//
// Frees the memory in WSK_BUF
//

static
VOID
  FreeWskBuffer(
	__in PVOID		Buffer,
	__in PWSK_BUF	WskBuffer
  )
{
	ASSERT( Buffer );
	ASSERT( WskBuffer );

	DeinitializeWskBuffer(WskBuffer);
	ExFreePool(Buffer);
}


//
// Just concatenates two MDLs
//

static
BOOLEAN
  ConcatMdls(
	__out PMDL		DstMdl,
	__in  ULONG		DstBufferSize,
	__in  PMDL		SrcMdl,
	__in  ULONG		SrcBufferSize
  )
{
	PVOID DstBuffer = NULL, SrcBuffer = NULL;

	ASSERT( DstMdl );
	ASSERT( SrcMdl );
	ASSERT( SrcBufferSize );

	__try
	{
		DstBuffer = MmMapLockedPagesSpecifyCache(DstMdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
		SrcBuffer = MmMapLockedPagesSpecifyCache(SrcMdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		if (DstBuffer)
			MmUnmapLockedPages(DstBuffer, DstMdl);
		return FALSE;
	}

	RtlCopyMemory(
		(PCHAR)DstBuffer + DstBufferSize,
		SrcBuffer,
		SrcBufferSize);

	MmUnmapLockedPages(DstBuffer, DstMdl);
	MmUnmapLockedPages(SrcBuffer, SrcMdl);

	return TRUE;
}



//
// Receives the web-server's response; the response can be
// reduced in the case of small HttpResponse buffer
//

static
NTSTATUS
  ReceiveHttpResponse(
	__in  PWSK_PROVIDER_CONNECTION_DISPATCH SocketDispatch,
	__in  PWSK_SOCKET WskSocket,
	__out PWSK_BUF HttpResponse
  )
{
	KEVENT		CompletionEvent = {0};
	PIRP		Irp = NULL;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;
	WSK_BUF		WskBuffer = {0};
	PVOID		Buffer = NULL;
	ULONG		HttpResponseLength = 0, ReceivedChunkSize = 0;

	ASSERT( SocketDispatch );
	ASSERT( WskSocket );
	ASSERT( HttpResponse );

	Irp = IoAllocateIrp(1, FALSE);
	if (!Irp) {
		DbgPrint("ReceiveHttpResponse(): IoAllocateIrp() failed\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// Allocate some buffer for chunks receiving

	Buffer = AllocateWskBuffer(PagedPool, 0x100, &WskBuffer);
	if (!Buffer) {
		DbgPrint("ReceiveHttpResponse(): AllocateWskBuffer() failed\n");
		IoFreeIrp(Irp);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	KeInitializeEvent(&CompletionEvent, SynchronizationEvent, FALSE);
	IoSetCompletionRoutine(Irp, CompletionRoutine, &CompletionEvent, TRUE, TRUE, TRUE);

	//
	// Collect the response's chunks
	//

	for (;;)
	{
		Status = SocketDispatch->WskReceive(
			WskSocket,
			&WskBuffer,
			0,
			Irp);
		if (Status == STATUS_PENDING) {
			KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
			Status = Irp->IoStatus.Status;
		}

		if (!NT_SUCCESS(Status)) {
			DbgPrint("ReceiveHttpResponse(): WskReceive() failed with status 0x%08X\n", Status);
			break;
		}

		ReceivedChunkSize = MIN((ULONG)Irp->IoStatus.Information, (ULONG)HttpResponse->Length - HttpResponseLength);

		if (!Irp->IoStatus.Information ||
			!ConcatMdls(HttpResponse->Mdl, HttpResponseLength, WskBuffer.Mdl, ReceivedChunkSize))
		{
			Status = STATUS_SUCCESS;
			break;
		}

		if ((HttpResponseLength += ReceivedChunkSize) >= HttpResponse->Length)
			break;

		KeResetEvent(&CompletionEvent);
		IoReuseIrp(Irp, STATUS_UNSUCCESSFUL);
		IoSetCompletionRoutine(Irp, CompletionRoutine, &CompletionEvent, TRUE, TRUE, TRUE);
	}

	HttpResponse->Length = HttpResponseLength;

	if (!HttpResponse->Length)
		Status = STATUS_UNSUCCESSFUL;

	FreeWskBuffer(Buffer, &WskBuffer);
	IoFreeIrp(Irp);
	return Status;
}

//
// Sends HTTP request and returns the response
//

static
NTSTATUS
  MakeHttpRequest(
	__in  PWSK_PROVIDER_NPI	WskProvider,
	__in  PSOCKADDR_IN		LocalAddress,
	__in  PSOCKADDR_IN		RemoteAddress,
	__in  PWSK_BUF			HttpRequest,
	__out PWSK_BUF			HttpResponse,
	__in  PIRP				Irp				// can be reused
  )
{
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;
	KEVENT		CompletionEvent = {0};

	PWSK_PROVIDER_CONNECTION_DISPATCH SocketDispatch = NULL;
	PWSK_SOCKET	WskSocket = NULL;

	ASSERT( WskProvider );
	ASSERT( LocalAddress );
	ASSERT( RemoteAddress );
	ASSERT( HttpRequest );
	ASSERT( HttpResponse );
	ASSERT( Irp );

	KeInitializeEvent(&CompletionEvent, SynchronizationEvent, FALSE);

	IoReuseIrp(Irp, STATUS_UNSUCCESSFUL);
	IoSetCompletionRoutine(Irp, CompletionRoutine, &CompletionEvent, TRUE, TRUE, TRUE);

	//
	// Create the socket
	//

	Status = WskProvider->Dispatch->WskSocket(
		WskProvider->Client,
		AF_INET,
		SOCK_STREAM,
		IPPROTO_TCP,
		WSK_FLAG_CONNECTION_SOCKET,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		Irp);
	if (Status == STATUS_PENDING) {
		KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
		Status = Irp->IoStatus.Status;
	}
	
	if (!NT_SUCCESS(Status)) {
		DbgPrint("MakeHttpRequest(): WskSocket() failed with status 0x%08X\n", Status);
		return Status;
	}

	WskSocket = (PWSK_SOCKET)Irp->IoStatus.Information;
	SocketDispatch = (PWSK_PROVIDER_CONNECTION_DISPATCH)WskSocket->Dispatch;

	KeResetEvent(&CompletionEvent);
	IoReuseIrp(Irp, STATUS_UNSUCCESSFUL);
	IoSetCompletionRoutine(Irp, CompletionRoutine, &CompletionEvent, TRUE, TRUE, TRUE);

	//
	// Bind the socket
	//

	Status = SocketDispatch->WskBind(
		WskSocket,
		(PSOCKADDR)LocalAddress,
		0,
		Irp);
	if (Status == STATUS_PENDING) {
		KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
		Status = Irp->IoStatus.Status;
	}
	
	if (!NT_SUCCESS(Status)) {
		DbgPrint("MakeHttpRequest(): WskBind() failed with status 0x%08X\n", Status);
		CloseWskSocket(SocketDispatch, WskSocket);
		return Status;
	}

	DbgPrint("MakeHttpRequest(): Connecting to the %u.%u.%u.%u:%u...\n",
		RemoteAddress->sin_addr.S_un.S_un_b.s_b1,
		RemoteAddress->sin_addr.S_un.S_un_b.s_b2,
		RemoteAddress->sin_addr.S_un.S_un_b.s_b3,
		RemoteAddress->sin_addr.S_un.S_un_b.s_b4,
		HTONS(RemoteAddress->sin_port));

	KeResetEvent(&CompletionEvent);
	IoReuseIrp(Irp, STATUS_UNSUCCESSFUL);
	IoSetCompletionRoutine(Irp, CompletionRoutine, &CompletionEvent, TRUE, TRUE, TRUE);

	//
	// Establish a connection with the destination host
	//

	Status = SocketDispatch->WskConnect(			// You can use WskSocketConnect() instead of sequence
		WskSocket,									// of WskSocket(), WskBind(), WskConnect() calls
		(PSOCKADDR)RemoteAddress,
		0,
		Irp);
	if (Status == STATUS_PENDING) {
		KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
		Status = Irp->IoStatus.Status;
	}

	if (!NT_SUCCESS(Status)) {
		DbgPrint("MakeHttpRequest(): WskConnect() failed with status 0x%08X\n", Status);
		CloseWskSocket(SocketDispatch, WskSocket);
		return Status;
	}

	DbgPrint("MakeHttpRequest(): Connected, sending the request...\n");

	KeResetEvent(&CompletionEvent);
	IoReuseIrp(Irp, STATUS_UNSUCCESSFUL);
	IoSetCompletionRoutine(Irp, CompletionRoutine, &CompletionEvent, TRUE, TRUE, TRUE);

	//
	// Now we can send the request
	//

	Status = SocketDispatch->WskSend(
		WskSocket,
		HttpRequest,
		0,
		Irp);
	if (Status == STATUS_PENDING) {
		KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
		Status = Irp->IoStatus.Status;
	}
	
	if (!NT_SUCCESS(Status)) {
		DbgPrint("MakeHttpRequest(): WskSend() failed with status 0x%08X\n", Status);
		CloseWskSocket(SocketDispatch, WskSocket);
		return Status;
	}

	if (Irp->IoStatus.Information != HttpRequest->Length) {
		DbgPrint("MakeHttpRequest(): Sent %u bytes of the request instead of %u bytes\n",
			Irp->IoStatus.Information, HttpRequest->Length);
		CloseWskSocket(SocketDispatch, WskSocket);
		return Status;
	}

	DbgPrint("MakeHttpRequest(): %u bytes of the request sent successfully\n", HttpRequest->Length);
	DbgPrint("MakeHttpRequest(): Receiving the answer...\n");

	//
	// Receive the server's answer
	//

	Status = ReceiveHttpResponse(SocketDispatch, WskSocket, HttpResponse);

	if (NT_SUCCESS(Status)) {
		DbgPrint("MakeHttpRequest(): Received %u bytes of data\n", HttpResponse->Length);
	}

	CloseWskSocket(SocketDispatch, WskSocket);
	return Status;
}


//
// Parses the web-server's response and shows the 'Date' field
//

static
VOID
  HandleResponse(
	__in PCHAR	HostName,
	__in PCHAR	HttpResponse		// must be zero terminated
  )
{
	PCHAR HeaderEnd = NULL, Data = NULL, LineEnd = NULL;

	ASSERT( HostName );
	ASSERT( HttpResponse );

	if (!( HeaderEnd = strstr(HttpResponse, "\r\n\r\n") )) {
		DbgPrint("HandleResponse(): Cannot find the response's header ending\n");
		return;
	}

	*HeaderEnd = 0;

	if (!( Data = strstr(HttpResponse, "\r\nDate: ") )) {
		DbgPrint("HandleResponse(): The server didn't reply with 'Date' field\n");
		return;
	}

	Data += sizeof("\r\nDate: ") - 1;

	if (!( LineEnd = strstr(Data, "\r\n") )) {
		DbgPrint("HandleResponse(): Cannot find the 'Date' field line's ending\n");
		return;
	}

	*LineEnd = 0;

	DbgPrint("==> %s says that today is: %s\n", HostName, Data);
}

//
// Attempts to establish a connection with HOST_NAME every
// CONNECT_CYCLE_TIMEOUT_SECONDS period of time 
//

static
NTSTATUS
  ConnectionCycle(
	__in PWSK_PROVIDER_NPI	WskProvider,
	__in PKEVENT			ShutdownEvent
	)
{
	WSK_BUF				WskHttpResponse = {0};
	WSK_BUF				WskHttpRequest = {0};
	PIRP				Irp = NULL;

	SOCKADDR_IN			LocalAddress = {0};
	SOCKADDR_IN			RemoteAddress = {0};

	NTSTATUS			Status = STATUS_UNSUCCESSFUL;
	LARGE_INTEGER		WaitInterval = {0};
	PCHAR				HttpResponse = NULL;

	CHAR HttpRequest[]=
		"GET / HTTP/1.1\r\n"
		"Host: "HOST_NAME"\r\n"
		"Connection: close\r\n"
		"\r\n";

	ASSERT( WskProvider );
	ASSERT( ShutdownEvent );

	// Allocate some memory for receiving process

	HttpResponse = AllocateWskBuffer(PagedPool, BUFFER_SIZE, &WskHttpResponse);
	if (!HttpResponse) {
		DbgPrint("ConnectionCycle(): AllocateWskBuffer(%u) failed\n", BUFFER_SIZE);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	Status = InitializeWskBuffer(HttpRequest, sizeof(HttpRequest), &WskHttpRequest);
	if (!NT_SUCCESS(Status)) {
		DbgPrint("ConnectionCycle(): InitializeWskBuffer(HttpRequest) failed with status 0x%08X\n", Status);
		FreeWskBuffer(HttpResponse, &WskHttpResponse);
		return Status;
	}

	Irp = IoAllocateIrp(1, FALSE);
	if (!Irp) {
		DbgPrint("ConnectionCycle(): IoAllocateIrp() failed\n");
		DeinitializeWskBuffer(&WskHttpRequest);
		FreeWskBuffer(HttpResponse, &WskHttpResponse);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	WaitInterval.QuadPart = RELATIVE(SECONDS(CONNECT_CYCLE_TIMEOUT_SECONDS));

	LocalAddress.sin_family			= AF_INET;
	LocalAddress.sin_addr.s_addr	= INADDR_ANY;
	LocalAddress.sin_port			= 0;

	RemoteAddress.sin_family		= AF_INET;
	RemoteAddress.sin_addr.s_addr	= HOST_ADDRESS;
	RemoteAddress.sin_port			= HTONS(HOST_PORT);

	do
	{
		WskHttpResponse.Length = BUFFER_SIZE - 1;

		Status = MakeHttpRequest(
			WskProvider,
			&LocalAddress,
			&RemoteAddress,
			&WskHttpRequest,
			&WskHttpResponse,
			Irp);

		if (NT_SUCCESS(Status))
		{
			ASSERT( WskHttpResponse.Length < BUFFER_SIZE );

			HttpResponse[WskHttpResponse.Length] = 0;

			HandleResponse(HOST_NAME, HttpResponse);
		}
	}
	while (KeWaitForSingleObject(ShutdownEvent, Executive, KernelMode, FALSE, &WaitInterval) == STATUS_TIMEOUT);

	DeinitializeWskBuffer(&WskHttpRequest);
	FreeWskBuffer(HttpResponse, &WskHttpResponse);
	IoFreeIrp(Irp);
	return Status;
}


static VOID NTAPI ConnectionThread(PVOID p)
{
	NTSTATUS Status =
		ConnectionCycle(&g_WskProvider, &g_ConnectionThreadShutdownEvent);

	PsTerminateSystemThread(Status);
}

//
// Signals the shutdown event and waits for the thread's completion
//

static
VOID
  ShutdownThread(
	__in_opt PETHREAD	Thread,
	__in PKEVENT		ShutdownEvent
	)
{
	ASSERT( ShutdownEvent );

	KeSetEvent(ShutdownEvent, IO_NO_INCREMENT, FALSE);

	if (Thread) {
		KeWaitForSingleObject(Thread, Executive, KernelMode, FALSE, NULL);
		ObDereferenceObject(Thread);
	}
}


static
VOID
NTAPI
  DriverUnload(
	__in PDRIVER_OBJECT DriverObject
	)
{
	// Shut down ConnectionThread() thread

	ShutdownThread(g_ConnectionThread, &g_ConnectionThreadShutdownEvent);

	// Unregister ourselves

	WskReleaseProviderNPI(&g_WskRegistration);
	WskDeregister(&g_WskRegistration);
}


NTSTATUS
NTAPI
  DriverEntry(
	__in PDRIVER_OBJECT		DriverObject,
	__in PUNICODE_STRING	RegPath
	)
{
	WSK_CLIENT_NPI	WskClient = {0};
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;
	HANDLE			hThread = NULL;

	KeInitializeEvent(&g_ConnectionThreadShutdownEvent, NotificationEvent, FALSE);

	WskClient.ClientContext = NULL;
	WskClient.Dispatch = &g_WskDispatch;

	// Register as a WSK application

	Status = WskRegister(&WskClient, &g_WskRegistration);
	if (!NT_SUCCESS(Status)) {
		DbgPrint("DriverEntry(): WskRegister() failed with status 0x%08X\n", Status);
		return Status;
	}

	// Wait for attach to a transport driver

	Status = WskCaptureProviderNPI(&g_WskRegistration, WSK_CAPTURE_WAIT_TIMEOUT_MSEC, &g_WskProvider);
	if (!NT_SUCCESS(Status)) {
		DbgPrint("DriverEntry(): WskCaptureProviderNPI() failed with status 0x%08X\n", Status);
		WskDeregister(&g_WskRegistration);
		return Status;
	}

	// Create ConnectionThread() thread

	Status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, ConnectionThread, NULL);
	if (!NT_SUCCESS(Status)) {
		DbgPrint("DriverEntry(): PsCreateSystemThread(ConnectionThread) failed with status 0x%08X\n", Status);
		WskReleaseProviderNPI(&g_WskRegistration);
		WskDeregister(&g_WskRegistration);
		return Status;
	}

	Status = ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, NULL, KernelMode, &g_ConnectionThread, NULL);
	ZwClose(hThread);

	if (!NT_SUCCESS(Status)) {
		DbgPrint("DriverEntry(): ObReferenceObjectByHandle() failed with status 0x%08X\n", Status);
		ShutdownThread(NULL, &g_ConnectionThreadShutdownEvent);
		WskReleaseProviderNPI(&g_WskRegistration);
		WskDeregister(&g_WskRegistration);
		return Status;
	}

	DriverObject->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}