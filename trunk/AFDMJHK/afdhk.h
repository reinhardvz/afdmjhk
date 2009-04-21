#ifndef __AFDHK_H__
#define __AFDHK_H__


NTSTATUS AfdhkDispatchRequest ( 
			IN PDEVICE_OBJECT DeviceObject,
			IN PIRP Irp
			);
NTSTATUS AfdhkOpenClose (
			IN PDEVICE_OBJECT DeviceObject,
			IN PIRP Irp
			);

NTSTATUS DeviceInit (
			IN PDRIVER_OBJECT DriverObject,
			IN PUNICODE_STRING RegistryPath
			);

VOID OnUnload(
			  IN PDRIVER_OBJECT DriverObject
			  );

NTSTATUS DriverFilter(DRIVER_OBJECT *old_DriverObject, BOOLEAN b_hook);

NTSTATUS	AfdhkDriverDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP irp);

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
    );

NTSTATUS
AfdhkDispatchDeviceControl (
    IN PIRP Irp,
    IN PIO_STACK_LOCATION IrpSp
    );

#endif