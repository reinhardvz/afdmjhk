#pragma once
#include <ntddk.h>

NTSTATUS
NTAPI
  UnhookNPI(
	__in struct _TL_DISPATCH_TABLES* DispatchTables
  );


