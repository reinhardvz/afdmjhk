#pragma once
#include <ntddk.h>
#include <ntimage.h>
#include "tools.h"

NTSTATUS
NTAPI
  GetPEHeaders(
	__in PMEMORY_CHUNK					Image,
	__out_opt PIMAGE_FILE_HEADER*		FileHeader,
	__out_opt PVOID*					OptionalHeader,
	__out_opt PIMAGE_SECTION_HEADER*	SectionHeader
  );

NTSTATUS
NTAPI
  MapImage(
	__in  PMEMORY_CHUNK		FlatImage,
	__out PMEMORY_CHUNK		MappedImage
  );

