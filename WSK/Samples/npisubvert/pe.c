/*++

Module Name:

    pe.c

Abstract:

    Functions for PE32/PE32+ format handling; we have ability
	to handle PE32+ modules for x86-64 build

Author:

    MaD, 12-May-2009

--*/

#include "pe.h"

#if DBG
#define POOLTAG '  EP'
#else
#define POOLTAG ' kdD'
#endif

#pragma pack(push,1)

typedef struct {
	USHORT	offset:12;
	USHORT	type:4;
} IMAGE_FIXUP_ENTRY, *PIMAGE_FIXUP_ENTRY;

#pragma pack(pop)

#define RVATOVA(Base, Offset) ((PVOID)((ULONG_PTR)(Base) + (ULONG_PTR)(Offset)))
#define MIN(_a, _b) ((_a) < (_b)? (_a): (_b))

//
// Returns pointers on the internal sub-headers
// if the module is correct
//

NTSTATUS
NTAPI
  GetPEHeaders(
	__in PMEMORY_CHUNK					Image,
	__out_opt PIMAGE_FILE_HEADER*		FileHeader,
	__out_opt PVOID*					OptionalHeader,
	__out_opt PIMAGE_SECTION_HEADER*	SectionHeader
  )
{
	PIMAGE_NT_HEADERS			NTHeaders = NULL;
	PIMAGE_DOS_HEADER			MZHeader = NULL;
	PIMAGE_FILE_HEADER			LocalFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32	LocalOptionalHeader = NULL;
	PIMAGE_SECTION_HEADER		LocalSectionHeader = NULL, pSection = NULL;
	
	ULONG		HeadersSize = 0, SectionIdx = 0;
	PUCHAR		ImageBase = NULL;
	ULONG		ImageSize = 0;

	if (!Image || !Image->Buffer || Image->Size < sizeof(IMAGE_DOS_HEADER))
		return STATUS_INVALID_PARAMETER;

	if (FileHeader)
		*FileHeader = NULL;
	if (OptionalHeader)
		*OptionalHeader = NULL;
	if (SectionHeader)
		*SectionHeader = NULL;

	ImageBase = (PUCHAR)Image->Buffer;
	ImageSize = Image->Size;

	//
	// Check the MS-DOS header
	//

	MZHeader = (PIMAGE_DOS_HEADER)ImageBase;
	if (MZHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return STATUS_INVALID_IMAGE_FORMAT;

	HeadersSize = MZHeader->e_lfanew + sizeof(IMAGE_FILE_HEADER);
	if (HeadersSize > ImageSize)
		return STATUS_BUFFER_OVERFLOW;

	NTHeaders = (PIMAGE_NT_HEADERS)&ImageBase[MZHeader->e_lfanew];
	
	HeadersSize += FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader);
	if (HeadersSize > ImageSize)
		return STATUS_BUFFER_OVERFLOW;

	if (NTHeaders->Signature != IMAGE_NT_SIGNATURE)
		return STATUS_INVALID_IMAGE_FORMAT;

	//
	// Check the file header
	//

	LocalFileHeader = &NTHeaders->FileHeader;

	if (LocalFileHeader->SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER32)
#ifdef _AMD64_
		&& LocalFileHeader->SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER64)
#endif
		)
		return STATUS_INVALID_IMAGE_FORMAT;

	HeadersSize += LocalFileHeader->SizeOfOptionalHeader;
	if (HeadersSize > ImageSize)
		return STATUS_BUFFER_OVERFLOW;

	//
	// Check the optional header
	//

	LocalOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)&NTHeaders->OptionalHeader;

	if (LocalOptionalHeader->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC
#ifdef _AMD64_
		&& LocalOptionalHeader->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC
#endif
		)
		return STATUS_INVALID_IMAGE_FORMAT;

	HeadersSize += LocalFileHeader->NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
	if (HeadersSize > ImageSize)
		return STATUS_BUFFER_OVERFLOW;

	if (LocalOptionalHeader->SizeOfHeaders > ImageSize)
		return STATUS_BUFFER_OVERFLOW;

	//
	// Check the sections headers
	//

	LocalSectionHeader = (PIMAGE_SECTION_HEADER)((PCHAR)LocalOptionalHeader + LocalFileHeader->SizeOfOptionalHeader);

	for (SectionIdx = 0, pSection = LocalSectionHeader; SectionIdx < LocalFileHeader->NumberOfSections; SectionIdx++, pSection++ )
	{
		if ( pSection->PointerToRawData + pSection->SizeOfRawData > ImageSize ||
				pSection->VirtualAddress + pSection->Misc.VirtualSize > LocalOptionalHeader->SizeOfImage )
			return STATUS_INVALID_IMAGE_FORMAT;
	}

	if ( FileHeader )
		*FileHeader = LocalFileHeader;
	if ( OptionalHeader )
		*OptionalHeader = LocalOptionalHeader;
	if ( SectionHeader )
		*SectionHeader = LocalSectionHeader;

	return STATUS_SUCCESS;
}


//
// Fixes the relocations of the mapped module
//

static
NTSTATUS
  FixRelocs(
	__in PMEMORY_CHUNK	MappedImage
  )
{
	PIMAGE_FILE_HEADER			FileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32	OptionalHeader32 = NULL;
#ifdef _AMD64_
	PIMAGE_OPTIONAL_HEADER64	OptionalHeader64 = NULL;
#endif
	PIMAGE_SECTION_HEADER		SectionHeader = NULL;
	PIMAGE_BASE_RELOCATION		BaseReloc = NULL;
	PIMAGE_FIXUP_ENTRY			FixupEntry = NULL;

	ULONG		BaseRelocVA = 0, BaseRelocSize = 0;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;
	ULONG		i = 0, TableSize = 0;

	ASSERT( MappedImage );
	
	Status = GetPEHeaders(MappedImage, &FileHeader, &OptionalHeader32, &SectionHeader);
	if (!NT_SUCCESS(Status)) {
		KdPrint(("FixRelocs(%p): GetPEHeaders() failed with status 0x%08X\n", MappedImage->Buffer, Status));
		return Status;
	}

#ifdef _AMD64_
	if (OptionalHeader32->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		OptionalHeader64 = (PIMAGE_OPTIONAL_HEADER64)OptionalHeader32;
		OptionalHeader32 = NULL;
	}
#endif
	
	if (OptionalHeader32)
	{
		BaseRelocVA = OptionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
		BaseRelocSize = OptionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	}
#ifdef _AMD64_
	else
	{
		BaseRelocVA = OptionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
		BaseRelocSize = OptionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	}
#endif

	// The module has no relocations?

	if (!BaseRelocVA || !BaseRelocSize || FileHeader->Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
		return STATUS_SUCCESS;

	BaseReloc = (PIMAGE_BASE_RELOCATION)RVATOVA(MappedImage->Buffer, BaseRelocVA);

	while (TableSize < BaseRelocSize)
	{
		FixupEntry = (PIMAGE_FIXUP_ENTRY)((PCHAR)BaseReloc + sizeof(IMAGE_BASE_RELOCATION));

		for (i = 0; i < (BaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) >> 1; i++, FixupEntry++)
		{
			if (OptionalHeader32 && FixupEntry->type == IMAGE_REL_BASED_HIGHLOW)
			{
				if (BaseReloc->VirtualAddress + FixupEntry->offset + sizeof(ULONG32) > MappedImage->Size) {
					Status = STATUS_INVALID_IMAGE_FORMAT;
					break;
				}
					
				*(PULONG32)&((PUCHAR)MappedImage->Buffer)[BaseReloc->VirtualAddress + FixupEntry->offset]
					-= (ULONG32)((ULONG_PTR)OptionalHeader32->ImageBase - (ULONG_PTR)MappedImage->Buffer);
			}
#ifdef _AMD64_
			else if (OptionalHeader64 && FixupEntry->type == IMAGE_REL_BASED_DIR64)
			{
				if (BaseReloc->VirtualAddress + FixupEntry->offset + sizeof(ULONG64) > MappedImage->Size) {
					Status = STATUS_INVALID_IMAGE_FORMAT;
					break;
				}

				*(PULONG64)&((PUCHAR)MappedImage->Buffer)[BaseReloc->VirtualAddress + FixupEntry->offset]
					-= OptionalHeader64->ImageBase - (ULONG64)MappedImage->Buffer;
			}
#endif
		}

		TableSize += BaseReloc->SizeOfBlock;
		*(PCHAR*)&BaseReloc += BaseReloc->SizeOfBlock;
	}

	return STATUS_SUCCESS;
}


//
// Allocates memory for the new mapped module and maps it
//

NTSTATUS
NTAPI
  MapImage(
	__in  PMEMORY_CHUNK		FlatImage,
	__out PMEMORY_CHUNK		MappedImage
  )
{
	PIMAGE_FILE_HEADER			FileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32	OptionalHeader = NULL;
	PIMAGE_SECTION_HEADER		SectionHeader = NULL, CurentSection = NULL;
	
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;
	ULONG		SectionIdx = 0;
	PCHAR		EndOfFlatImage = NULL;

	if (!FlatImage || !MappedImage)
		return STATUS_INVALID_PARAMETER;

	Status = GetPEHeaders(FlatImage, &FileHeader, &OptionalHeader, &SectionHeader);
	if (!NT_SUCCESS(Status)) {
		KdPrint(("MapImage(%p): GetPEHeaders() failed with status 0x%08X\n", FlatImage->Buffer, Status));
		return Status;
	}

	Status = AllocateMemoryChunk(MappedImage, PagedPool, OptionalHeader->SizeOfImage, POOLTAG);
	if (!NT_SUCCESS(Status))
		return Status;

	EndOfFlatImage = (PCHAR)FlatImage->Buffer + FlatImage->Size;

	// Copy the headers

	memcpy(MappedImage->Buffer, FlatImage->Buffer, OptionalHeader->SizeOfHeaders);

	// Copy the sections

	Status = STATUS_SUCCESS;

	for (SectionIdx = 0, CurentSection = SectionHeader;
		SectionIdx < FileHeader->NumberOfSections;
		SectionIdx++, CurentSection++)
	{
		ULONG SectionSize = MIN(CurentSection->SizeOfRawData, CurentSection->Misc.VirtualSize);

		if (CurentSection->SizeOfRawData)
		{
			// Checks is the section in range

			if ((PCHAR)RVATOVA(FlatImage->Buffer, CurentSection->PointerToRawData) + SectionSize > EndOfFlatImage) {
				Status = STATUS_INVALID_IMAGE_FORMAT;
				break;
			}

			memcpy(RVATOVA(MappedImage->Buffer, CurentSection->VirtualAddress),
					RVATOVA(FlatImage->Buffer, CurentSection->PointerToRawData),
					 SectionSize);
		}

		// Zero the rest

		RtlZeroMemory(
			(PCHAR)RVATOVA(MappedImage->Buffer, CurentSection->VirtualAddress) + SectionSize,
			CurentSection->Misc.VirtualSize - SectionSize);
	}

	// Fix the relocations

	if (NT_SUCCESS(Status))
	{
		Status = FixRelocs(MappedImage);
		if (!NT_SUCCESS(Status)) {
			KdPrint(("MapImage(%p): FixRelocs() failed with status 0x%08X\n", FlatImage->Buffer, Status));
		}
	}

	if (!NT_SUCCESS(Status))
		FreeMemoryChunk(MappedImage);

	return Status;
}

