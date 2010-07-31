/*++

Module Name:

    echoserv.c

Abstract:

    simplewsk library echo server test

Author:

    MaD, 12-May-2009

--*/

#include "echoserv.h"
#include "simplewsk.h"


static PETHREAD g_ServerThread;

static volatile LONG	g_ClientsCount = 0;
static PWSK_SOCKET		g_ServerSocket = NULL;

#define SERVER_PORT	667


//
// Client thread routine
//

static VOID NTAPI ClientThread(PWSK_SOCKET Socket)
{
	UCHAR	Buffer[256] = {0};
	LONG	BufferSize = 0;
	CHAR	GreetMessage[] = "Hello there\r\n";

	if (Send(Socket, GreetMessage, sizeof(GreetMessage)-1, 0) == sizeof(GreetMessage)-1)
	{
		while (( BufferSize = Receive(Socket, Buffer, sizeof(Buffer), 0)) > 0)
		{
			Send(Socket, Buffer, BufferSize, 0);
		}
	}

	CloseSocket(Socket);
	InterlockedDecrement(&g_ClientsCount);
	PsTerminateSystemThread(STATUS_SUCCESS);
}

//
// Server thread routine
//

static VOID NTAPI ServerThread(PVOID p)
{
	SOCKADDR_IN		LocalAddress = {0}, RemoteAddress = {0};
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;
	PWSK_SOCKET		Socket = NULL;

	// Create the listening socket

	g_ServerSocket = CreateSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, WSK_FLAG_LISTEN_SOCKET);
	if (g_ServerSocket == NULL) {
		DbgPrint("ServerThread(): CreateSocket() returned NULL\n");
		PsTerminateSystemThread(STATUS_SUCCESS);
	}

	LocalAddress.sin_family			= AF_INET;
	LocalAddress.sin_addr.s_addr	= INADDR_ANY;
	LocalAddress.sin_port			= HTONS(SERVER_PORT);

	// Bind to 0.0.0.0:SERVER_PORT

	Status = Bind(g_ServerSocket, (PSOCKADDR)&LocalAddress);
	if (!NT_SUCCESS(Status)) {
		DbgPrint("ServerThread(): Bind() failed with status 0x%08X\n", Status);
		CloseSocket(g_ServerSocket);
		g_ServerSocket = NULL;
		PsTerminateSystemThread(Status);
	}

	DbgPrint("ServerThread(): Listening on %u.%u.%u.%u:%u...\n",
		LocalAddress.sin_addr.S_un.S_un_b.s_b1,
		LocalAddress.sin_addr.S_un.S_un_b.s_b2,
		LocalAddress.sin_addr.S_un.S_un_b.s_b3,
		LocalAddress.sin_addr.S_un.S_un_b.s_b4,
		HTONS(LocalAddress.sin_port));

	// Accept incoming connections

	while (( Socket = Accept(g_ServerSocket, (PSOCKADDR)&LocalAddress, (PSOCKADDR)&RemoteAddress)) != NULL)
	{
		HANDLE hThread = NULL;

		DbgPrint("ServerThread(): %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u connected\n",
			RemoteAddress.sin_addr.S_un.S_un_b.s_b1,
			RemoteAddress.sin_addr.S_un.S_un_b.s_b2,
			RemoteAddress.sin_addr.S_un.S_un_b.s_b3,
			RemoteAddress.sin_addr.S_un.S_un_b.s_b4,
			HTONS(RemoteAddress.sin_port),
			LocalAddress.sin_addr.S_un.S_un_b.s_b1,
			LocalAddress.sin_addr.S_un.S_un_b.s_b2,
			LocalAddress.sin_addr.S_un.S_un_b.s_b3,
			LocalAddress.sin_addr.S_un.S_un_b.s_b4,
			HTONS(LocalAddress.sin_port));

		Status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, (PKSTART_ROUTINE)ClientThread, (PVOID)Socket);
		if (!NT_SUCCESS(Status)) {
			DbgPrint("ServerThread(): PsCreateSystemThread(ClientThread) failed with status 0x%08X\n", Status);
			CloseSocket(Socket);
			continue;
		}

		InterlockedIncrement(&g_ClientsCount);
		ZwClose(hThread);
	}

	DbgPrint("ServerThread(): Shutting down server...\n");

	// g_ServerSocket will be closed in DriverUnload()
	PsTerminateSystemThread(STATUS_SUCCESS);
}

static
VOID
NTAPI
  DriverUnload(
	__in PDRIVER_OBJECT DriverObject
	)
{
	LARGE_INTEGER Interval = {0};

	if (g_ServerSocket != NULL) {
		CloseSocket(g_ServerSocket);
		g_ServerSocket = NULL;
	}

	// Shut down ServerThread() thread

	KeWaitForSingleObject(g_ServerThread, Executive, KernelMode, FALSE, NULL);
	ObDereferenceObject(g_ServerThread);

	// Wait for the clients' threads

	Interval.QuadPart = RELATIVE(MILLISECONDS(100));
	while (g_ClientsCount)
		KeDelayExecutionThread(KernelMode, FALSE, &Interval);

	SocketsDeinit();
}


NTSTATUS
NTAPI
  DriverEntry(
	__in PDRIVER_OBJECT		DriverObject,
	__in PUNICODE_STRING	RegPath
	)
{
	HANDLE		hThread = NULL;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

	Status = SocketsInit();
	if (!NT_SUCCESS(Status)) {
		DbgPrint("DriverEntry(): SocketsInit() failed with status 0x%08X\n", Status);
		return Status;
	}

	// Create ServerThread() thread

	Status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, ServerThread, NULL);
	if (!NT_SUCCESS(Status)) {
		DbgPrint("DriverEntry(): PsCreateSystemThread(ServerThread) failed with status 0x%08X\n", Status);
		SocketsDeinit();
		return Status;
	}

	Status = ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, NULL, KernelMode, &g_ServerThread, NULL);
	ZwClose(hThread);

	if (!NT_SUCCESS(Status)) {
		DbgPrint("DriverEntry(): ObReferenceObjectByHandle() failed with status 0x%08X\n", Status);
		SocketsDeinit();
		return Status;
	}

	DriverObject->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}