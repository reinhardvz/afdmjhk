///////////////////////////////////////////////////////////////////////////
//				AFD Hook Filter Driver (Win2K)
//					2005.4.20.
//				Copyright   Zealot		All Rights Reserved.   			 
//								http://zpacket.tistory.com						 
//                         		x86ddk@gmail.com 					     
///////////////////////////////////////////////////////////////////////////

#include "precomp.h"

//#pragma code_seg("INIT")


NTKERNELAPI
NTSTATUS
ObReferenceObjectByName (
    IN PUNICODE_STRING  ObjectName,
    IN ULONG            Attributes,
    IN PACCESS_STATE    PassedAccessState OPTIONAL,
    IN ACCESS_MASK      DesiredAccess OPTIONAL,
    IN POBJECT_TYPE     ObjectType OPTIONAL,
    IN KPROCESSOR_MODE  AccessMode,
    IN OUT PVOID        ParseContext OPTIONAL,
    OUT PVOID           *Object
);

extern POBJECT_TYPE IoDriverObjectType;

/*
typedef NTSTATUS (*pOldMJCodeDispatchRequestHK) (
			IN PDEVICE_OBJECT DeviceObject,
			IN PIRP Irp
			);

pOldMJCodeDispatchRequestHK		oldMJCodeDispatchRequestHK	= NULL;
*/

DRIVER_OBJECT g_old_DriverObject;
PFAST_IO_DEVICE_CONTROL old_FastIoDeviceControl ;

//BOOLEAN g_hooked = FALSE;

/*
FAST_IO_DISPATCH AfdhkFastIoDispatch = {
    11,                        // SizeOfFastIoDispatch
    NULL,                      // FastIoCheckIfPossible
    AfdFastIoRead,             // FastIoRead
    AfdFastIoWrite,            // FastIoWrite
    NULL,                      // FastIoQueryBasicInfo
    NULL,                      // FastIoQueryStandardInfo
    NULL,                      // FastIoLock
    NULL,                      // FastIoUnlockSingle
    NULL,                      // FastIoUnlockAll
    NULL,                      // FastIoUnlockAllByKey
    AfdFastIoDeviceControl     // FastIoDeviceControl
};

*/



NTSTATUS DriverFilter(DRIVER_OBJECT *old_DriverObject, BOOLEAN b_hook)
{
	UNICODE_STRING drv_name;
	NTSTATUS status;
	PDRIVER_OBJECT new_DriverObject;
	int i;

	RtlInitUnicodeString(&drv_name, L"\\Driver\\Afd");

	status = ObReferenceObjectByName(&drv_name, OBJ_CASE_INSENSITIVE, (ULONG)NULL, 0,
		IoDriverObjectType, KernelMode,(ULONG) NULL, &new_DriverObject);
	if (status != STATUS_SUCCESS) {
		KdPrint(("[Afdhk] hook_driver: ObReferenceObjectByName fail\n"));
		return status;
	}
	
	if(b_hook) {
		old_FastIoDeviceControl = new_DriverObject->FastIoDispatch->FastIoDeviceControl;
		new_DriverObject->FastIoDispatch->FastIoDeviceControl = AfdhkFastIoDeviceControl;
	} else {
		new_DriverObject->FastIoDispatch->FastIoDeviceControl = old_FastIoDeviceControl;
	}
	
	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
		if (b_hook) {
			old_DriverObject->MajorFunction[i] = new_DriverObject->MajorFunction[i];
			new_DriverObject->MajorFunction[i] = AfdhkDriverDispatch;
			
		} else
			new_DriverObject->MajorFunction[i] = old_DriverObject->MajorFunction[i];
	}
	
	return STATUS_SUCCESS;	
}

NTSTATUS DriverEntry( 
			IN PDRIVER_OBJECT DriverObject,
			IN PUNICODE_STRING RegistryPath
			)
{
	NTSTATUS status = STATUS_SUCCESS;
	

	// Create device
	status = DeviceInit ( DriverObject, RegistryPath );

	if (status != STATUS_SUCCESS) {
		KdPrint(("[Afdhk] DriverEntry: DeviceInit: 0x%x\n", status));
		goto FAIL;
	}

	status = DriverFilter(&g_old_DriverObject, TRUE);
		
	return status;

FAIL:
	if (status != STATUS_SUCCESS) {
		// cleanup
		OnUnload(DriverObject);
	}

    return status;

}
typedef struct _DEVICE_EXTENSION {
	unsigned int aaa;
}DEVICE_EXTENSION,*PDEVICE_EXTENSION;

NTSTATUS DeviceInit ( 
			IN PDRIVER_OBJECT DriverObject,
			IN PUNICODE_STRING RegistryPath
			)
{
	UNICODE_STRING	DeviceName;
	UNICODE_STRING	SymbolicLinkName;
	PDEVICE_OBJECT	DeviceObject;
	UINT			Counter = 0;
	NTSTATUS		Status = STATUS_SUCCESS;	

	// Initialize device name string
   	RtlInitUnicodeString ( &DeviceName, L"\\Device\\AFDHK" );
	
	// Create new device
	Status = IoCreateDevice (
				DriverObject,
				sizeof(DEVICE_EXTENSION),
				&DeviceName,
				FILE_DEVICE_NETWORK,
				0,
				TRUE,
				&DeviceObject
				);

	if ( Status == STATUS_SUCCESS ) {
		// Create symbolic link for device
		RtlInitUnicodeString ( &SymbolicLinkName, L"\\DosDevices\\AFDHK" );

		IoCreateSymbolicLink ( &SymbolicLinkName, &DeviceName );

//		DeviceObject->Flags = DO_DIRECT_IO;

		// Initiaize dispatcher handler
//		for(Counter = 0; Counter < IRP_MJ_MAXIMUM_FUNCTION; Counter++)
//			DriverObject->MajorFunction[Counter] = AfdhkDispatchRequest;

		DriverObject->MajorFunction [ IRP_MJ_CREATE ] = AfdhkOpenClose;
		DriverObject->MajorFunction [ IRP_MJ_CLOSE ] = AfdhkOpenClose;
//		DriverObject->MajorFunction [ IRP_MJ_CLEANUP ] = AfdhkOpenClose;
		DriverObject->MajorFunction [IRP_MJ_DEVICE_CONTROL] = AfdhkDispatchRequest;

//		DriverObject->FastIoDispatch = &AfdFastIoDispatch;
		DriverObject->DriverUnload = OnUnload;
	}

	return Status;
}

//#pragma code_seg()

NTSTATUS AfdhkDispatchRequest (
			IN PDEVICE_OBJECT DeviceObject,
			IN PIRP Irp
			)
{
	NTSTATUS			Status = STATUS_SUCCESS;
//	PUCHAR				pBuffer;
//	DWORD				InputBufferLength, OutputBufferLength, ControlCode, ReturnedSize = 0;
    PIO_STACK_LOCATION  irpStack = IoGetCurrentIrpStackLocation ( Irp );
/*
	switch ( irpStack->MajorFunction )
	{
		case IRP_MJ_DEVICE_CONTROL:
			{
				pBuffer = ( PUCHAR ) Irp -> AssociatedIrp.SystemBuffer;
				InputBufferLength = irpStack -> Parameters.DeviceIoControl.InputBufferLength;
				OutputBufferLength = irpStack -> Parameters.DeviceIoControl.OutputBufferLength;
				ControlCode = irpStack -> Parameters.DeviceIoControl.IoControlCode;
				Status = STATUS_SUCCESS;
				// Call common for all versions device I/O control handler
				if   ( 
					IOControlHandler ( 
						ControlCode, 
						pBuffer, 
						InputBufferLength, 
						pBuffer, 
						OutputBufferLength, 
						&ReturnedSize ) != STATUS_SUCCESS
					)
				{
					Status = STATUS_INVALID_PARAMETER;
					ReturnedSize = 0;
				}
				
				break;
			}

		default:
			break;
	}
*/
	Irp -> IoStatus.Status = Status;
	Irp -> IoStatus.Information = 0;

	IoCompleteRequest ( Irp, IO_NO_INCREMENT );

	return Status;
}

NTSTATUS AfdhkOpenClose (
			IN PDEVICE_OBJECT DeviceObject,
			IN PIRP Irp
			)
{
	Irp -> IoStatus.Status = STATUS_SUCCESS;
    Irp -> IoStatus.Information = 0;

    IoCompleteRequest ( Irp, IO_NO_INCREMENT );

    return STATUS_SUCCESS;
}

VOID OnUnload(
			  IN PDRIVER_OBJECT DriverObject
			  )
{
	NTSTATUS status;
	UNICODE_STRING	SymbolicLinkName;

	status = DriverFilter(&g_old_DriverObject, FALSE);

	RtlInitUnicodeString ( &SymbolicLinkName, L"\\DosDevices\\AFDHK" );
	IoDeleteSymbolicLink(&SymbolicLinkName);

	IoDeleteDevice(DriverObject->DeviceObject);
	
}


#define IS_DGRAM_ENDPOINT(endp) \
            ((endp)->EndpointType == AfdEndpointTypeDatagram)

BOOLEAN
AfdhkFastIoDeviceControl (
    IN struct _FILE_OBJECT *FileObject,
    IN BOOLEAN Wait,
    IN PVOID InputBuffer OPTIONAL,
    IN ULONG InputBufferLength,
    OUT PVOID OutputBuffer OPTIONAL,
    IN ULONG OutputBufferLength,
    IN ULONG IoControlCode,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN struct _DEVICE_OBJECT *DeviceObject
    )
{
	PAFD_ENDPOINT endpoint;

	endpoint = FileObject->FsContext;

	if(IS_DGRAM_ENDPOINT(endpoint)) {
		switch(IoControlCode) {
		case IOCTL_AFD_SEND:
			KdPrint(("[Afdhk] AfdhkFastIoDeviceControl: DGRAM_ENDPOINT: IOCTL_AFD_SEND\n"));
			break;
		case IOCTL_AFD_RECEIVE:
			KdPrint(("[Afdhk] AfdhkFastIoDeviceControl: DGRAM_ENDPOINT: IOCTL_AFD_RECEIVE\n"));
			break;
		case IOCTL_AFD_SEND_DATAGRAM:
			KdPrint(("[Afdhk] AfdhkFastIoDeviceControl: DGRAM_ENDPOINT: IOCTL_AFD_SEND_DATAGRAM\n"));
			break;
		case IOCTL_AFD_RECEIVE_DATAGRAM:
			KdPrint(("[Afdhk] AfdhkFastIoDeviceControl: DGRAM_ENDPOINT: IOCTL_AFD_RECEIVE_DATAGRAM\n"));
			break;
		default:
			break;
		}
		
		return old_FastIoDeviceControl(
					FileObject,
					Wait,
					InputBuffer,
					InputBufferLength,
					OutputBuffer,
					OutputBufferLength,
					IoControlCode,
					IoStatus,
					DeviceObject);

	} else {
		switch(IoControlCode) {
		case IOCTL_AFD_SEND:
			KdPrint(("[Afdhk] AfdhkFastIoDeviceControl: IOCTL_AFD_SEND\n"));
			break;
		case IOCTL_AFD_RECEIVE:
			KdPrint(("[Afdhk] AfdhkFastIoDeviceControl: IOCTL_AFD_RECEIVE\n"));
			break;
		case IOCTL_AFD_TRANSMIT_FILE:
			KdPrint(("[Afdhk] AfdhkFastIoDeviceControl: IOCTL_AFD_TRANSMIT_FILE\n"));
			
			break;
		default:
			break;
		}
		
		return old_FastIoDeviceControl(
					FileObject,
					Wait,
					InputBuffer,
					InputBufferLength,
					OutputBuffer,
					OutputBufferLength,
					IoControlCode,
					IoStatus,
					DeviceObject);

	}
		
}



NTSTATUS
AfdhkDriverDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP irp)
{
	PIO_STACK_LOCATION		irps;
	NTSTATUS				status;
	PUCHAR					Buffer = NULL;

	// sanity check
	if (irp == NULL) {
		KdPrint(("[Afdhk] DriverDispatch: !irp\n"));
		return STATUS_SUCCESS;
	}
	irps = IoGetCurrentIrpStackLocation(irp);

	// Analyze MajorFunction
	switch (irps->MajorFunction) {
		
	case IRP_MJ_CREATE:
		KdPrint(("[Afdhk] DriverDispatch: IRP_MJ_CREATE\n"));
		break;
	case IRP_MJ_CLEANUP:
		KdPrint(("[Afdhk] DriverDispatch: IRP_MJ_CLEANUP\n"));
		break;
	case IRP_MJ_CLOSE:	
		KdPrint(("[Afdhk] DriverDispatch: IRP_MJ_CLOSE\n"));
		break;
	case IRP_MJ_INTERNAL_DEVICE_CONTROL: 
		KdPrint(("[Afdhk] DriverDispatch: IRP_MJ_INTERNAL_DEVICE_CONTROL\n"));
		break;	
	case IRP_MJ_READ:
		KdPrint(("[Afdhk] DriverDispatch: IRP_MJ_READ\n"));
		break;
	case IRP_MJ_WRITE:
		KdPrint(("[Afdhk] DriverDispatch: IRP_MJ_WRITE\n"));
		break;
	case IRP_MJ_DEVICE_CONTROL:
		AfdhkDispatchDeviceControl(irp,irps);
		//KdPrint(("[Afdhk] DriverDispatch: IRP_MJ_DEVICE_CONTROL, minor 0x%x for 0x%08X\n",irps->MinorFunction, irps->FileObject));
		break;
			
	default:
		KdPrint(("[Afdhk] DriverDispatch: major 0x%x, minor 0x%x for 0x%x\n", irps->MajorFunction, irps->MinorFunction, irps->FileObject));

	}
		
	status = g_old_DriverObject.MajorFunction[irps->MajorFunction](DeviceObject, irp);
	
	return status;

}

/*
ULONG AfdIoctlTable[] = {
		IOCTL_AFD_BIND,
		IOCTL_AFD_CONNECT,
		IOCTL_AFD_START_LISTEN,
		IOCTL_AFD_WAIT_FOR_LISTEN,
		IOCTL_AFD_ACCEPT,
		IOCTL_AFD_RECEIVE,
		IOCTL_AFD_RECEIVE_DATAGRAM,
		IOCTL_AFD_SEND,
		IOCTL_AFD_SEND_DATAGRAM,
		IOCTL_AFD_POLL,
		IOCTL_AFD_PARTIAL_DISCONNECT,
		IOCTL_AFD_GET_ADDRESS,
		IOCTL_AFD_QUERY_RECEIVE_INFO,
		IOCTL_AFD_QUERY_HANDLES,
		IOCTL_AFD_SET_INFORMATION,
		IOCTL_AFD_GET_CONTEXT_LENGTH,
		IOCTL_AFD_GET_CONTEXT,
		IOCTL_AFD_SET_CONTEXT,
		IOCTL_AFD_SET_CONNECT_DATA,
		IOCTL_AFD_SET_CONNECT_OPTIONS,
		IOCTL_AFD_SET_DISCONNECT_DATA,
		IOCTL_AFD_SET_DISCONNECT_OPTIONS,
		IOCTL_AFD_GET_CONNECT_DATA,
		IOCTL_AFD_GET_CONNECT_OPTIONS,
		IOCTL_AFD_GET_DISCONNECT_DATA,
		IOCTL_AFD_GET_DISCONNECT_OPTIONS,
		IOCTL_AFD_SIZE_CONNECT_DATA,
		IOCTL_AFD_SIZE_CONNECT_OPTIONS,
		IOCTL_AFD_SIZE_DISCONNECT_DATA,
		IOCTL_AFD_SIZE_DISCONNECT_OPTIONS,
		IOCTL_AFD_GET_INFORMATION,
		IOCTL_AFD_TRANSMIT_FILE,
		IOCTL_AFD_SUPER_ACCEPT,
		IOCTL_AFD_EVENT_SELECT,
		IOCTL_AFD_ENUM_NETWORK_EVENTS,
		IOCTL_AFD_DEFER_ACCEPT,
		IOCTL_AFD_WAIT_FOR_LISTEN_LIFO,
		IOCTL_AFD_SET_QOS,
		IOCTL_AFD_GET_QOS,
		IOCTL_AFD_NO_OPERATION,
		IOCTL_AFD_VALIDATE_GROUP,
		IOCTL_AFD_GET_UNACCEPTED_CONNECT_DATA,		
};


#define NUM_AFD_IOCTLS  ( sizeof(AfdIoctlTable) / sizeof(AfdIoctlTable[0]) )
*/


NTSTATUS
AfdhkDispatchDeviceControl (
    IN PIRP Irp,
    IN PIO_STACK_LOCATION IrpSp
    )
{
    ULONG code;
    ULONG request;
    NTSTATUS status = STATUS_SUCCESS; 

	code = IrpSp->Parameters.DeviceIoControl.IoControlCode;

    request = _AFD_REQUEST(code);
	
//	if( _AFD_BASE(code) == FSCTL_AFD_BASE && request < NUM_AFD_IOCTLS && AfdIoctlTable[request] == code ) {
	switch( request ) {
	case AFD_BIND:
		KdPrint(("AfdDispatchDeviceControl: AFD_BIND %08lX\n", code));
		return status;
	case AFD_CONNECT:
		KdPrint(("AfdDispatchDeviceControl: AFD_CONNECT %08lX\n", code));
		return status;
		
	case AFD_SEND:
		KdPrint(("AfdDispatchDeviceControl: AFD_SEND IOCTL %08lX\n", code));
		return status;
	case AFD_SEND_DATAGRAM:
		KdPrint(("AfdDispatchDeviceControl: AFD_SEND_DATAGRAM IOCTL %08lX\n", code));
		return status;
	case AFD_RECEIVE:
		KdPrint(("AfdDispatchDeviceControl: AFD_RECEIVE %08lX\n", code));
		return status;
	case AFD_RECEIVE_DATAGRAM:
		KdPrint(("AfdDispatchDeviceControl: AFD_RECEIVE_DATAGRAM %08lX\n", code));
		return status;
	case AFD_TRANSMIT_FILE:
		KdPrint(("AfdDispatchDeviceControl: AFD_TRANSMIT_FILE %08lX\n", code));
		return status;
		
	case AFD_START_LISTEN:
		KdPrint(("AfdDispatchDeviceControl: AFD_START_LISTEN %08lX\n", code));
		return status;
	case AFD_WAIT_FOR_LISTEN:
		KdPrint(("AfdDispatchDeviceControl: AFD_WAIT_FOR_LISTEN %08lX\n", code));
		return status;
	case AFD_WAIT_FOR_LISTEN_LIFO:
		KdPrint(("AfdDispatchDeviceControl: AFD_WAIT_FOR_LISTEN_LIFO %08lX\n", code));
		return status;
	case AFD_ACCEPT:
		KdPrint(("AfdDispatchDeviceControl: AFD_ACCEPT %08lX\n", code));
		return status;
	case AFD_PARTIAL_DISCONNECT:
		KdPrint(("AfdDispatchDeviceControl: AFD_PARTIAL_DISCONNECT %08lX\n", code));
		return status;
	case AFD_GET_ADDRESS:
		KdPrint(("AfdDispatchDeviceControl: AFD_GET_ADDRESS %08lX\n", code));
		return status;
	case AFD_POLL:
		KdPrint(("AfdDispatchDeviceControl: AFD_POLL %08lX\n", code));
		return status;
	case AFD_QUERY_RECEIVE_INFO:	
		KdPrint(("AfdDispatchDeviceControl: AFD_QUERY_RECEIVE_INFO %08lX\n", code));
		return status;
	case AFD_QUERY_HANDLES:
		KdPrint(("AfdDispatchDeviceControl: AFD_QUERY_HANDLES %08lX\n", code));
		return status;
	case AFD_GET_CONTEXT_LENGTH:
		KdPrint(("AfdDispatchDeviceControl: AFD_GET_CONTEXT_LENGTH %08lX\n", code));
		return status;
	case AFD_GET_CONTEXT:
		KdPrint(("AfdDispatchDeviceControl: AFD_GET_CONTEXT %08lX\n", code));
		return status;
	case AFD_SET_CONTEXT:
		KdPrint(("AfdDispatchDeviceControl: AFD_SET_CONTEXT %08lX\n", code));
		return status;
	case AFD_SET_INFORMATION:
		KdPrint(("AfdDispatchDeviceControl: AFD_SET_INFORMATION %08lX\n", code));
		return status;
	case AFD_GET_INFORMATION:
		KdPrint(("AfdDispatchDeviceControl: AFD_GET_INFORMATION %08lX\n", code));
		return status;
	case AFD_SET_CONNECT_DATA:
		KdPrint(("AfdDispatchDeviceControl: AFD_SET_CONNECT_DATA %08lX\n", code));
		return status;
	case AFD_SET_CONNECT_OPTIONS:
		KdPrint(("AfdDispatchDeviceControl: AFD_SET_CONNECT_OPTIONS %08lX\n", code));
		return status;
	case AFD_SET_DISCONNECT_DATA:
		KdPrint(("AfdDispatchDeviceControl: AFD_SET_DISCONNECT_DATA %08lX\n", code));
		return status;
	case AFD_SET_DISCONNECT_OPTIONS:
		KdPrint(("AfdDispatchDeviceControl: AFD_SET_DISCONNECT_OPTIONS %08lX\n", code));
		return status;
	case AFD_SIZE_CONNECT_DATA:
		KdPrint(("AfdDispatchDeviceControl: AFD_SIZE_CONNECT_DATA %08lX\n", code));
		return status;
	case AFD_SIZE_CONNECT_OPTIONS:
		KdPrint(("AfdDispatchDeviceControl: AFD_SIZE_CONNECT_OPTIONS %08lX\n", code));
		return status;
	case AFD_SIZE_DISCONNECT_DATA:
		KdPrint(("AfdDispatchDeviceControl: AFD_SIZE_DISCONNECT_DATA %08lX\n", code));
		return status;
	case AFD_SIZE_DISCONNECT_OPTIONS:
		KdPrint(("AfdDispatchDeviceControl: AFD_SIZE_DISCONNECT_OPTIONS %08lX\n", code));
		return status;
	case AFD_GET_CONNECT_DATA:
		KdPrint(("AfdDispatchDeviceControl: AFD_GET_CONNECT_DATA %08lX\n", code));
		return status;
	case AFD_GET_CONNECT_OPTIONS:
		KdPrint(("AfdDispatchDeviceControl: AFD_GET_CONNECT_OPTIONS %08lX\n", code));
		return status;
	case AFD_GET_DISCONNECT_DATA:
		KdPrint(("AfdDispatchDeviceControl: AFD_GET_DISCONNECT_DATA %08lX\n", code));
		return status;
	case AFD_GET_DISCONNECT_OPTIONS:
		KdPrint(("AfdDispatchDeviceControl: AFD_GET_DISCONNECT_OPTIONS %08lX\n", code));
		return status;
	case AFD_SUPER_ACCEPT:
		KdPrint(("AfdDispatchDeviceControl: AFD_SUPER_ACCEPT %08lX\n", code));
		return status;
	case AFD_EVENT_SELECT :
		KdPrint(("AfdDispatchDeviceControl: AFD_EVENT_SELECT %08lX\n", code));
		return status;
	case AFD_ENUM_NETWORK_EVENTS :
		KdPrint(("AfdDispatchDeviceControl: AFD_ENUM_NETWORK_EVENTS %08lX\n", code));
		return status;
	case AFD_DEFER_ACCEPT:
		KdPrint(("AfdDispatchDeviceControl: AFD_DEFER_ACCEPT %08lX\n", code));
		return status;
	case AFD_SET_QOS :
		KdPrint(("AfdDispatchDeviceControl: AFD_SET_QOS %08lX\n", code));
		return status;
	case AFD_GET_QOS :
		KdPrint(("AfdDispatchDeviceControl: AFD_GET_QOS %08lX\n", code));
		return status;
	case AFD_NO_OPERATION :
		KdPrint(("AfdDispatchDeviceControl: AFD_NO_OPERATION %08lX\n", code));
		return status;
	case AFD_VALIDATE_GROUP :
		KdPrint(("AfdDispatchDeviceControl: AFD_VALIDATE_GROUP %08lX\n", code));
		return status;
	case AFD_GET_UNACCEPTED_CONNECT_DATA :
		KdPrint(("AfdDispatchDeviceControl: AFD_GET_UNACCEPTED_CONNECT_DATA %08lX\n", code));
		//		case AFD_QUEUE_APC :
		//			KdPrint(("AfdDispatchDeviceControl: AFD_QUEUE_APC\n"));
		
		return status;
	default:
		KdPrint(("AfdDispatchDeviceControl: default %08lX\n", code));
		return status;
	}
//	}

//    KdPrint(("AfdDispatchDeviceControl: invalid IOCTL %08lX\n", code));

    return STATUS_INVALID_DEVICE_REQUEST;
}
