#ifndef __IOCTL_H__
#define __IOCTL_H__

NDIS_STATUS IOControlHandler ( 
				DWORD	ControlCode, 
				PUCHAR	pInBuffer, 
				DWORD	InputBufferLength, 
				PUCHAR	pOutBuffer, 
				DWORD	OutputBufferLength, 
				PDWORD	pReturnedSize 
				);
#endif //__IOCTL_H__
