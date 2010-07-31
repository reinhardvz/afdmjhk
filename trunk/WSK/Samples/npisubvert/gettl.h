#pragma once
#include <ntddk.h>
#include <netioddk.h>
#include "tools.h"

typedef NTSTATUS (NTAPI* PROVIDER_DISPATCH) (
	__in PVOID	Endpoint,
	__in PVOID	ProviderData
);

typedef struct _TL_PROVIDER_DISPATCH {				// TCP, UDP, RawIP
	PROVIDER_DISPATCH	IoControl;
	PROVIDER_DISPATCH	QueryDispatch;
	PROVIDER_DISPATCH	Endpoint;
	PROVIDER_DISPATCH	Message;
	PROVIDER_DISPATCH	Listen;
	PROVIDER_DISPATCH	Connect;
	PROVIDER_DISPATCH	ReleaseIndicationList;
	PROVIDER_DISPATCH	Cancel;
} TL_PROVIDER_DISPATCH, *PTL_PROVIDER_DISPATCH;

typedef struct _TL_ENDPOINT_DATA_DISPATCH {			// TCP, UDP, RawIP
	PROVIDER_DISPATCH	CloseEndpoint;
	PROVIDER_DISPATCH	IoControlEndpoint;
	PROVIDER_DISPATCH	QueryDispatchEndpoint;
} TL_ENDPOINT_DATA_DISPATCH, *PTL_ENDPOINT_DATA_DISPATCH;

typedef struct _TL_PROVIDER_CONNECT_DISPATCH {		// TCP only
	PROVIDER_DISPATCH	CloseEndpoint;
	PROVIDER_DISPATCH	IoControlEndpoint;
	PROVIDER_DISPATCH	QueryDispatchEndpoint;
	PROVIDER_DISPATCH	Send;
	PROVIDER_DISPATCH	Receive;
	PROVIDER_DISPATCH	Disconnect;
} TL_PROVIDER_CONNECT_DISPATCH, *PTL_PROVIDER_CONNECT_DISPATCH;

typedef struct _TL_PROVIDER_LISTEN_DISPATCH {		// TCP only
	PROVIDER_DISPATCH	CloseEndpoint;
	PROVIDER_DISPATCH	IoControlEndpoint;
	PROVIDER_DISPATCH	QueryDispatchEndpoint;
	PROVIDER_DISPATCH	ResumeConnection;
} TL_PROVIDER_LISTEN_DISPATCH, *PTL_PROVIDER_LISTEN_DISPATCH;

typedef struct _TL_PROVIDER_MESSAGE_DISPATCH {		// UDP & RawIP
	PROVIDER_DISPATCH	CloseEndpoint;
	PROVIDER_DISPATCH	IoControlEndpoint;
	PROVIDER_DISPATCH	QueryDispatchEndpoint;
	PROVIDER_DISPATCH	SendMessages;
} TL_PROVIDER_MESSAGE_DISPATCH, *PTL_PROVIDER_MESSAGE_DISPATCH;


typedef struct _TL_DISPATCH_TABLES {

	// Genuine tcpip.sys handlers

	TL_PROVIDER_DISPATCH			RealTcpTlProviderDispatch;
	TL_ENDPOINT_DATA_DISPATCH		RealTcpTlProviderEndpointDispatch;
	TL_PROVIDER_CONNECT_DISPATCH	RealTcpTlProviderConnectDispatch;
	TL_PROVIDER_LISTEN_DISPATCH		RealTcpTlProviderListenDispatch;

	TL_PROVIDER_DISPATCH			RealUdpTlProviderDispatch;
	TL_ENDPOINT_DATA_DISPATCH		RealUdpTlProviderEndpointDispatch;
	TL_PROVIDER_MESSAGE_DISPATCH	RealUdpTlProviderMessageDispatch;

	TL_PROVIDER_DISPATCH			RealRawTlProviderDispatch;
	TL_ENDPOINT_DATA_DISPATCH		RealRawTlProviderEndpointDispatch;
	TL_PROVIDER_MESSAGE_DISPATCH	RealRawTlProviderMessageDispatch;

	// XxxTlProviderXxxDispatch tables pointers

	PTL_PROVIDER_DISPATCH			TcpTlProviderDispatch;
	PTL_ENDPOINT_DATA_DISPATCH		TcpTlProviderEndpointDispatch;
	PTL_PROVIDER_CONNECT_DISPATCH	TcpTlProviderConnectDispatch;
	PTL_PROVIDER_LISTEN_DISPATCH	TcpTlProviderListenDispatch;

	PTL_PROVIDER_DISPATCH			UdpTlProviderDispatch;
	PTL_ENDPOINT_DATA_DISPATCH		UdpTlProviderEndpointDispatch;
	PTL_PROVIDER_MESSAGE_DISPATCH	UdpTlProviderMessageDispatch;

	PTL_PROVIDER_DISPATCH			RawTlProviderDispatch;
	PTL_ENDPOINT_DATA_DISPATCH		RawTlProviderEndpointDispatch;
	PTL_PROVIDER_MESSAGE_DISPATCH	RawTlProviderMessageDispatch;
} TL_DISPATCH_TABLES, *PTL_DISPATCH_TABLES;


NTSTATUS
NTAPI
  GetTcpipDispatchTables(
	__in  struct _LDR_DATA_TABLE_ENTRY*	DriverEntry,
	__out PTL_DISPATCH_TABLES		DispatchTables
  );

