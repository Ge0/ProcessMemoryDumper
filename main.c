#include <Windows.h>
#include <stdio.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <Dbghelp.h>
#include "defines.h"

static LPVOID GetBaseAddressOfProcess(HANDLE hProcess);
static BOOL GetProcessEnvironmentBlock(HANDLE hProcess, PPEB pPeb);
static BOOL GetProcessLoaderData(HANDLE hProcess, const PPEB peb, PPEB_LDR_DATA pPebLdrData);
static PDWORD GetThreadsOfProcess(DWORD dwPid, PDWORD lpNumberOfThreads);
static PIMAGE_NT_HEADERS GetImageNtHeadersOfProcess(HANDLE hProcess, LPVOID lpBaseAddress);

int main(int argc, char** argv) {

	DWORD dwPid = 0;
	MODULEINFO moduleInfo;
	HANDLE hProcess;
	DWORD i;
	DWORD dwNumberOfThreads;
	PDWORD lpThreads = NULL;
	PHANDLE lpThreadsHandles = NULL;
	PIMAGE_NT_HEADERS lpImageNtHeaders = NULL;
	LPVOID lpBaseAddressOfProcess = NULL;
	LPSTR lpFileName[30];
	HANDLE hFile;
	LPVOID lpMemorySpace = NULL;
	DWORD dwNumberOfBytesRead;

	if(argc < 2) {
		fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
		ExitProcess(-1);
	}

	dwPid = atoi(argv[1]);

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if(hProcess == NULL) {
		fprintf(stderr, "OpenProcess(): %d\n", GetLastError());
		ExitProcess(-1);
	}

	// Retrieve the base address of the process so we can start dumping it
	if(GetModuleInformation(hProcess, NULL, &moduleInfo, sizeof(MODULEINFO)) == FALSE) {
		fprintf(stderr, "GetModuleInformation(): %d\n", GetLastError());
		ExitProcess(-1);
	}

	lpBaseAddressOfProcess = GetBaseAddressOfProcess(hProcess);
	printf("Base Address is %08X\n", lpBaseAddressOfProcess);

	
	lpThreads = GetThreadsOfProcess(dwPid, &dwNumberOfThreads);
	if(lpThreads != NULL) {
		printf("List of threads:\n");
		for(i = 0; i < dwNumberOfThreads; ++i) {
			printf("TID: %d\n", lpThreads[i]);
		}
	}


	lpThreadsHandles = (PHANDLE)HeapAlloc(GetProcessHeap(), 0, dwNumberOfThreads * sizeof(HANDLE));
	if(lpThreadsHandles == NULL) {
		fprintf(stderr, "[-] HeapAlloc(): %d\n", GetLastError());
		HeapFree(GetProcessHeap(), 0, lpThreads);
		ExitProcess(-1);
	}

	ZeroMemory(lpFileName, 30);
	_snprintf_s((char*)lpFileName, 29, 29, "%d.dmp", dwPid);

	hFile = CreateFileA(
		(LPCSTR)lpFileName,
		GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		0,
		NULL
	);

	if(hFile == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "[-] CreateFileA(): %d!\n", GetLastError());
		HeapFree(GetProcessHeap(), 0, lpThreads);
		HeapFree(GetProcessHeap(), 0, lpThreadsHandles);
		ExitProcess(-1);
	}

	// Suspending all threads
	printf("Suspending all threads...\n");
	for(i = 0; i < dwNumberOfThreads; ++i) {
		// Getting handle on the thread
		lpThreadsHandles[i] = OpenThread(THREAD_ALL_ACCESS, FALSE, lpThreads[i]);
		if(lpThreadsHandles[i] != INVALID_HANDLE_VALUE) {
			// Suspending thread
			if(SuspendThread(lpThreadsHandles[i]) == -1) {
				fprintf(stderr, "[-] Cannot suspend thread %d!\n", lpThreads[i]);
			}
		} else {
			fprintf(stderr, "[-] OpenThread(): %d!\n", GetLastError());
			HeapFree(GetProcessHeap(), 0, lpThreads);
			HeapFree(GetProcessHeap(), 0, lpThreadsHandles);
		}
	}

	// Getting SizeOfImage member
	printf("[*] All Threads suspended!\n");
	lpImageNtHeaders = GetImageNtHeadersOfProcess(hProcess, lpBaseAddressOfProcess);
	if(lpImageNtHeaders == NULL) {
		fprintf(stderr, "[-] Can't get image nt headers of the target process!\n");
		HeapFree(GetProcessHeap(), 0, lpThreads);
		HeapFree(GetProcessHeap(), 0, lpThreadsHandles);
		ExitProcess(-1);
	}

	lpMemorySpace = HeapAlloc(GetProcessHeap(), 0, lpImageNtHeaders->OptionalHeader.SizeOfImage);
	if(lpMemorySpace == NULL) {
		fprintf(stderr, "[-] HeapAlloc(): %d\n", GetLastError());
		HeapFree(GetProcessHeap(), 0, lpImageNtHeaders);
		HeapFree(GetProcessHeap(), 0, lpThreads);
		HeapFree(GetProcessHeap(), 0, lpThreadsHandles);
		ExitProcess(-1);
	}

	printf("[*] Reading process memory...\n");
	
	if(!ReadProcessMemory(hProcess, lpBaseAddressOfProcess, lpMemorySpace, lpImageNtHeaders->OptionalHeader.SizeOfImage, &dwNumberOfBytesRead)) {
		fprintf(stderr, "[-] ReadProcessMemory(): %d\n", GetLastError());
		HeapFree(GetProcessHeap(), 0, lpImageNtHeaders);
		HeapFree(GetProcessHeap(), 0, lpThreads);
		HeapFree(GetProcessHeap(), 0, lpThreadsHandles);
		ExitProcess(-1);
	}

	printf("[*] Writing read memory into file...\n");
	if(!WriteFile(hFile, lpMemorySpace, dwNumberOfBytesRead, &dwNumberOfBytesRead, NULL)) {
		fprintf(stderr, "[-] WriteFile(): %d\n", GetLastError());
		HeapFree(GetProcessHeap(), 0, lpImageNtHeaders);
		HeapFree(GetProcessHeap(), 0, lpThreads);
		HeapFree(GetProcessHeap(), 0, lpThreadsHandles);
		ExitProcess(-1);
	}


	// Resuming threads
	printf("[*] Resuming threads...\n");
	for(i = 0; i < dwNumberOfThreads; ++i) {
		if(ResumeThread(lpThreadsHandles[i]) == -1) {
			fprintf(stderr, "[-] Cannot resume thread %d!\n", lpThreads[i]);
		}
		CloseHandle(lpThreadsHandles[i]);
	}

	HeapFree(GetProcessHeap(), 0, lpImageNtHeaders);
	HeapFree(GetProcessHeap(), 0, lpThreads);
	HeapFree(GetProcessHeap(), 0, lpThreadsHandles);
	CloseHandle(hFile);
	CloseHandle(hProcess);

	return EXIT_SUCCESS;
}


static LPVOID GetBaseAddressOfProcess(HANDLE hProcess) {
	PEB pebOfProcess;
	GetProcessEnvironmentBlock(hProcess, &pebOfProcess);
	return pebOfProcess.ImageBaseAddress;


}

static PDWORD GetThreadsOfProcess(DWORD dwPid, PDWORD lpNumberOfThreads) {
    int 			i = 0, j = 0;
    HANDLE			hSnapshot = NULL;
	PDWORD			lpThreads = NULL;
    THREADENTRY32 	thread;
	*lpNumberOfThreads = 0;

    thread.dwSize = sizeof(THREADENTRY32);

    if((hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)) != INVALID_HANDLE_VALUE) {

        while(i < 2) {
            if(Thread32First(hSnapshot, &thread)) {
                if(thread.th32OwnerProcessID == dwPid)
                {

                    switch(i)
                    {
                    case 0:
                        ++(*lpNumberOfThreads);
                        break;

                    case 1:
                        *(lpThreads+j) = thread.th32ThreadID;
                        ++j;
                        break;
                    }

                }

                while(Thread32Next(hSnapshot, &thread)) {

                    if(thread.th32OwnerProcessID == dwPid) {

                        switch(i) {
                        case 0:
                            ++(*lpNumberOfThreads);
                            break;

                        case 1:
                            *(lpThreads+j) = thread.th32ThreadID;
							++j;
                            break;
                        }

                    }

                }

                if(i == 0) {
                    lpThreads = (PDWORD) HeapAlloc(GetProcessHeap(), 0, (*lpNumberOfThreads) * sizeof(DWORD));
                    if(lpThreads == NULL)
                    {
                        CloseHandle(hSnapshot);
                        ++i;
                    }
                }
                else
                {
                    CloseHandle(hSnapshot);
                }
            }

            ++i;
        }
    }

	return lpThreads;
}

static BOOL GetProcessEnvironmentBlock(HANDLE hProcess, PPEB pPeb) {

	lpfNtQueryInformationProcess NtQueryInformationProcess = NULL;

    PROCESS_BASIC_INFORMATION pbi = {0x0};
    NTSTATUS status;
    DWORD dwLength;
    HMODULE hModule = NULL;
    DWORD dwBytesRead = 0x0;
	BOOL bRet = FALSE;

    SetLastError(0x0);

    hModule = GetModuleHandleA("ntdll.dll");
    if(hModule != NULL) {

        NtQueryInformationProcess = (lpfNtQueryInformationProcess)GetProcAddress(hModule, "NtQueryInformationProcess");

        if(NtQueryInformationProcess != NULL) {
            status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, (PVOID)&pbi, sizeof(PROCESS_BASIC_INFORMATION), &dwLength);
            if(status == 0) {
                if(ReadProcessMemory(hProcess, pbi.PebBaseAddress, pPeb, sizeof(PEB), &dwBytesRead)) {
					bRet = TRUE;
				}

            }
        }

		FreeLibrary(hModule);
    }

	return bRet;
}

static PIMAGE_NT_HEADERS GetImageNtHeadersOfProcess(HANDLE hProcess, LPVOID lpBaseAddress) {
	DWORD dwNumberOfBytesRead;
	IMAGE_DOS_HEADER imageDosHeader;
	LPBYTE lpAddressOfImageNtHeaders;
	PIMAGE_NT_HEADERS lpImageNtHeaders = (PIMAGE_NT_HEADERS)HeapAlloc(GetProcessHeap(), 0, sizeof(IMAGE_NT_HEADERS));
	if(lpImageNtHeaders != NULL) {
		ReadProcessMemory(hProcess, lpBaseAddress, &imageDosHeader, sizeof(IMAGE_DOS_HEADER), &dwNumberOfBytesRead);
		lpAddressOfImageNtHeaders = (LPBYTE)lpBaseAddress + imageDosHeader.e_lfanew;
		ReadProcessMemory(hProcess, lpAddressOfImageNtHeaders, lpImageNtHeaders, sizeof(IMAGE_NT_HEADERS), &dwNumberOfBytesRead);
	}
	return lpImageNtHeaders;
}

static BOOL GetProcessLoaderData(HANDLE hProcess, const PPEB peb, PPEB_LDR_DATA pPebLdrData) {
    DWORD dwBytesRead = 0x0;

    return ReadProcessMemory(
        hProcess,
        peb->LoaderData,
        pPebLdrData,
        sizeof(PEB_LDR_DATA),
        &dwBytesRead
    );

}