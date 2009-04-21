#ifndef __COMMON_H__
#define __COMMON_H__

#ifdef _WINDOWS
#include <WinIoctl.h>   // Compiling Win32 Applications Or DLL's
#endif // _WINDOWS

#define AFDHK_BASE_VERSION		   0x00000001


// Specify Structure Packing
#pragma pack(1)      

// Specify here packed structures for data exchange with driver

// Restore Default Structure Packing
#pragma pack()                  


//**********************************************************************************
//					IOCTL Codes For TDI Hooking Driver
//**********************************************************************************

#define FILE_DEVICE_PROTOCOL			0x8000
#define IOCTL_AFDHK_BASE				FILE_DEVICE_PROTOCOL

#define IOCTL_AFDHK_GET_VERSION \
   CTL_CODE(IOCTL_AFDHK_BASE, 0, METHOD_BUFFERED, FILE_ANY_ACCESS)

#endif // __COMMON_H__


