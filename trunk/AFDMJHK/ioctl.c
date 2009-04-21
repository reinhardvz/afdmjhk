
#include "precomp.h"

NDIS_STATUS IOControlHandler ( 
				DWORD	ControlCode, 
				PUCHAR	pInBuffer, 
				DWORD	InputBufferLength, 
				PUCHAR	pOutBuffer, 
				DWORD	OutputBufferLength, 
				PDWORD	pReturnedSize 
				)
{
	switch ( ControlCode ) {
		case IOCTL_AFDHK_GET_VERSION:
			{
				*((PDWORD) pOutBuffer) = AFDHK_BASE_VERSION;
				*pReturnedSize = sizeof (DWORD);
				return NDIS_STATUS_SUCCESS;
			}
	}

	return NDIS_STATUS_NOT_RECOGNIZED;
}