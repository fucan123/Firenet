typedef unsigned char* PBYTE;

#include "undocumented.h"
#include "ssdt.h"
#include "ntdll.h"
#include "MemLoadDll.h"
#include <ntifs.h>
#include <intrin.h >

#define PROCESS_TERMINATE         0x0001  
#define PROCESS_VM_OPERATION      0x0008  
#define PROCESS_VM_READ           0x0010  
#define PROCESS_VM_WRITE          0x0020

typedef struct _LDR_DATA_TABLE_ENTRY64
{
	LIST_ENTRY64    InLoadOrderLinks;
	LIST_ENTRY64    InMemoryOrderLinks;
	LIST_ENTRY64    InInitializationOrderLinks;
	PVOID            DllBase;
	PVOID            EntryPoint;
	ULONG            SizeOfImage;
	UNICODE_STRING    FullDllName;
	UNICODE_STRING     BaseDllName;
	ULONG            Flags;
	USHORT            LoadCount;
	USHORT            TlsIndex;
	PVOID            SectionPointer;
	ULONG            CheckSum;
	PVOID            LoadedImports;
	PVOID            EntryPointActivationContext;
	PVOID            PatchInformation;
	LIST_ENTRY64    ForwarderLinks;
	LIST_ENTRY64    ServiceTagLinks;
	LIST_ENTRY64    StaticLinks;
	PVOID            ContextInformation;
	ULONG64            OriginalBase;
	LARGE_INTEGER    LoadTime;
} LDR_DATA_TABLE_ENTRY64, *PLDR_DATA_TABLE_ENTRY64;

PVOID obHandle;//定义一个void*类型的变量，它将会作为ObRegisterCallbacks函数的第二个参数。
HANDLE ProtectPid = 0;
HANDLE ProtectVBoxPid = 0;

#if 0
#include <ntstatus.h>
#endif

static UNICODE_STRING DeviceName;
static UNICODE_STRING Win32Device;

#define TAG_INJECTLIST	'ljni'
#define TAG_INJECTDATA	'djni'

#define IOCTL_SET_INJECT_X86DLL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

#define IOCTL_SET_INJECT_X64DLL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

#define IOCTL_DEL_INJECT_X86DLL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

#define IOCTL_DEL_INJECT_X64DLL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

#define IOCTL_SET_PROTECT_PID \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x100, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

#define IOCTL_SET_PROTECT_VBOX_PID \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x101, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

#define IOCTL_SET_HIDE_PID \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x102, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

#define IOCTL_DECODE_DLL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x200, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_BSOD \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xfff, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

//
//引入函数
//
extern "C"
NTKERNELAPI
PVOID NTAPI PsGetProcessWow64Process(PEPROCESS process);

extern "C"
NTKERNELAPI
NTSTATUS NTAPI PsLookupProcessByProcessId(
	_In_ HANDLE ProcessId,
	_Outptr_ PEPROCESS *Process
);

extern "C"
NTKERNELAPI
UCHAR*  PsGetProcessImageFileName(__in PEPROCESS Process);
//
//注入列表结构体
//
typedef NTSTATUS(NTAPI* fn_NtAllocateVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID *BaseAddress,
	_In_ ULONG_PTR ZeroBits,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG AllocationType,
	_In_ ULONG Protect
	);
typedef NTSTATUS(NTAPI* fn_NtReadVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_Out_ PVOID Buffer,
	_In_ SIZE_T BufferSize,
	_Out_opt_ PSIZE_T NumberOfBytesRead
	);
typedef NTSTATUS(NTAPI* fn_NtWriteVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_In_ CONST VOID *Buffer,
	_In_ SIZE_T BufferSize,
	_Out_opt_ PSIZE_T NumberOfBytesWritten
	);

typedef NTSTATUS(NTAPI* fn_NtProtectVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID *BaseAddress,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG NewProtect,
	_Out_ PULONG OldProtect
	);


typedef struct _INJECT_PROCESSID_LIST {			//注入列表信息
	LIST_ENTRY	link;
	HANDLE pid;
	BOOLEAN	inject;
}INJECT_PROCESSID_LIST, *PINJECT_PROCESSID_LIST;

typedef struct _INJECT_PROCESSID_DATA {			//注入进程数据信息
	HANDLE	pid;
	PVOID	imagebase;
	SIZE_T	imagesize;
}INJECT_PROCESSID_DATA, *PINJECT_PROCESSID_DATA;

typedef struct _INJECT_PROCESSID_DLL {			//内存加载DLL信息
	PVOID	x64dll;
	ULONG	x64dllsize;
	PVOID	x86dll;
	ULONG	x86dllsize;
}INJECT_PROCESSID_DLL, *PINJECT_PROCESSID_DLL;

#pragma pack(push,1)

//
//x86 payload
//
typedef struct _INJECT_PROCESSID_PAYLOAD_X86 {
	UCHAR	saveReg[2]; //pushad //pushfd
	UCHAR	restoneHook[17]; // mov esi,5 mov edi,123 mov esi,456 rep movs byte
	UCHAR	invokeMemLoad[10]; // push xxxxxx call xxxxxx
	UCHAR	eraseDll[14]; // mov al,0 mov ecx,len mov edi,addr rep stos
	UCHAR	restoneReg[2];//popfd popad
	UCHAR	jmpOld[5]; //jmp

	UCHAR	oldData[5];

	UCHAR	dll[1];
	UCHAR	shellcode[1];

}INJECT_PROCESSID_PAYLOAD_X86, *PINJECT_PROCESSID_PAYLOAD_X86;

//
// x64 payload
//
typedef struct _INJECT_PROCESSID_PAYLOAD_X64 {
	UCHAR	saveReg[25];
	UCHAR	subStack[4];
	UCHAR	restoneHook[32]; // mov rcx,xxxx mov rdi,xxxx mov rsi,xxx rep movs byte
	UCHAR	invokeMemLoad[15]; // mov rcx,xxxxx call xxxx
	UCHAR	eraseDll[24]; // mov rdi,xxxx xor eax,eax mov rcx,xxxxx rep stosb
	UCHAR	addStack[4];
	UCHAR	restoneReg[27];
	UCHAR	jmpOld[14]; //jmp qword [0]

	UCHAR	oldData[14];//

	UCHAR	dll[1];
	UCHAR	shellcode[1];

}INJECT_PROCESSID_PAYLOAD_X64, *PINJECT_PROCESSID_PAYLOAD_X64;

#pragma pack(pop)

//
//全局进程链表
//
INJECT_PROCESSID_LIST	g_injectList;
INJECT_PROCESSID_DLL	g_injectDll;
ERESOURCE			g_ResourceMutex;
NPAGED_LOOKASIDE_LIST g_injectListLookaside;
NPAGED_LOOKASIDE_LIST g_injectDataLookaside;

fn_NtAllocateVirtualMemory	pfn_NtAllocateVirtualMemory;
fn_NtReadVirtualMemory		pfn_NtReadVirtualMemory;
fn_NtWriteVirtualMemory		pfn_NtWriteVirtualMemory;
fn_NtProtectVirtualMemory	pfn_NtProtectVirtualMemory;

//
//通过pid查询进程是否已经注入
//
BOOLEAN QueryInjectListStatus(HANDLE	processid)
{
	BOOLEAN result = FALSE;

	KeEnterCriticalRegion();
	ExAcquireResourceSharedLite(&g_ResourceMutex, TRUE);

	PLIST_ENTRY	head = &g_injectList.link;
	PINJECT_PROCESSID_LIST next = (PINJECT_PROCESSID_LIST)g_injectList.link.Blink;

	while (head != (PLIST_ENTRY)next)
	{
		if (next->pid == processid)
		{
			if (next->inject == TRUE)
			{
				result = TRUE;
			}
			
			break;
		}

		next = (PINJECT_PROCESSID_LIST)(next->link.Blink);
	}


	ExReleaseResourceLite(&g_ResourceMutex);
	KeLeaveCriticalRegion();

	return result;
}

//
//设置pid 注入状态为已注入
//
VOID SetInjectListStatus(HANDLE	processid)
{
	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&g_ResourceMutex, TRUE);

	PLIST_ENTRY	head = &g_injectList.link;
	PINJECT_PROCESSID_LIST next = (PINJECT_PROCESSID_LIST)g_injectList.link.Blink;

	while (head != (PLIST_ENTRY)next)
	{
		if (next->pid == processid)
		{
			next->inject = TRUE;
			break;
		}

		next = (PINJECT_PROCESSID_LIST)(next->link.Blink);
	}


	ExReleaseResourceLite(&g_ResourceMutex);
	KeLeaveCriticalRegion();

}

//
//添加pid 到注入列表
//
VOID AddInjectList(HANDLE processid)
{
	//DPRINT("my:%s %d\n", __FUNCTION__, processid);

	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&g_ResourceMutex, TRUE);

	PINJECT_PROCESSID_LIST newLink = (PINJECT_PROCESSID_LIST)\
		ExAllocateFromNPagedLookasideList(&g_injectListLookaside);

	if (newLink == NULL)
	{
		ASSERT(false);
	}
	newLink->pid = processid;
	newLink->inject = false;

	InsertTailList(&g_injectList.link, (PLIST_ENTRY)newLink);

	ExReleaseResourceLite(&g_ResourceMutex);
	KeLeaveCriticalRegion();
}

//
//进程退出 释放pid链表
//
VOID DeleteInjectList(HANDLE processid)
{
	//DPRINT("my:%s %d\n", __FUNCTION__, processid);

	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&g_ResourceMutex, TRUE);

	PLIST_ENTRY	head = &g_injectList.link;
	PINJECT_PROCESSID_LIST next = (PINJECT_PROCESSID_LIST)g_injectList.link.Blink;

	while (head != (PLIST_ENTRY)next)
	{
		if (next->pid == processid)
		{
			RemoveEntryList(&next->link);
			ExFreeToNPagedLookasideList(&g_injectListLookaside, &next->link);
			break;
		}

		next = (PINJECT_PROCESSID_LIST)(next->link.Blink);
	}


	ExReleaseResourceLite(&g_ResourceMutex);
	KeLeaveCriticalRegion();
}

//
//getprocaddress
//
#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(unsigned __int64 *)(name)
#define DEREF_32( name )*(unsigned long *)(name)
#define DEREF_16( name )*(unsigned short *)(name)
#define DEREF_8( name )*(UCHAR *)(name)
ULONG_PTR GetProcAddressR(ULONG_PTR hModule, const char* lpProcName, bool x64Module)
{
	UINT_PTR uiLibraryAddress = 0;
	ULONG_PTR fpResult = NULL;

	if (hModule == NULL)
		return NULL;

	// a module handle is really its base address
	uiLibraryAddress = (UINT_PTR)hModule;

	__try
	{
		UINT_PTR uiAddressArray = 0;
		UINT_PTR uiNameArray = 0;
		UINT_PTR uiNameOrdinals = 0;
		PIMAGE_NT_HEADERS32 pNtHeaders32 = NULL;
		PIMAGE_NT_HEADERS64 pNtHeaders64 = NULL;
		PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
		PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;

		// get the VA of the modules NT Header
		pNtHeaders32 = (PIMAGE_NT_HEADERS32)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);
		pNtHeaders64 = (PIMAGE_NT_HEADERS64)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);
		if (x64Module)
		{
			pDataDirectory = (PIMAGE_DATA_DIRECTORY)&pNtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		}
		else
		{
			pDataDirectory = (PIMAGE_DATA_DIRECTORY)&pNtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		}


		// get the VA of the export directory
		pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(uiLibraryAddress + pDataDirectory->VirtualAddress);

		// get the VA for the array of addresses
		uiAddressArray = (uiLibraryAddress + pExportDirectory->AddressOfFunctions);

		// get the VA for the array of name pointers
		uiNameArray = (uiLibraryAddress + pExportDirectory->AddressOfNames);

		// get the VA for the array of name ordinals
		uiNameOrdinals = (uiLibraryAddress + pExportDirectory->AddressOfNameOrdinals);

		// test if we are importing by name or by ordinal...
		if ((PtrToUlong(lpProcName) & 0xFFFF0000) == 0x00000000)
		{
			// import by ordinal...

			// use the import ordinal (- export ordinal base) as an index into the array of addresses
			uiAddressArray += ((IMAGE_ORDINAL(PtrToUlong(lpProcName)) - pExportDirectory->Base) * sizeof(unsigned long));

			// resolve the address for this imported function
			fpResult = (ULONG_PTR)(uiLibraryAddress + DEREF_32(uiAddressArray));
		}
		else
		{
			// import by name...
			unsigned long dwCounter = pExportDirectory->NumberOfNames;
			while (dwCounter--)
			{
				char * cpExportedFunctionName = (char *)(uiLibraryAddress + DEREF_32(uiNameArray));

				// test if we have a match...
				if (strcmp(cpExportedFunctionName, lpProcName) == 0)
				{
					// use the functions name ordinal as an index into the array of name pointers
					uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(unsigned long));

					// calculate the virtual address for the function
					fpResult = (ULONG_PTR)(uiLibraryAddress + DEREF_32(uiAddressArray));

					// finish...
					break;
				}

				// get the next exported function name
				uiNameArray += sizeof(unsigned long);

				// get the next exported function name ordinal
				uiNameOrdinals += sizeof(unsigned short);
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		fpResult = NULL;
	}

	return fpResult;
}

//
// 搜索字符串,来自blackbone
//
LONG SafeSearchString(IN PUNICODE_STRING source, IN PUNICODE_STRING target, IN BOOLEAN CaseInSensitive)
{
	ASSERT(source != NULL && target != NULL);
	if (source == NULL || target == NULL || source->Buffer == NULL || target->Buffer == NULL)
		return STATUS_INVALID_PARAMETER;

	// Size mismatch
	if (source->Length < target->Length)
		return -1;

	USHORT diff = source->Length - target->Length;
	for (USHORT i = 0; i <= (diff / sizeof(WCHAR)); i++)
	{
 		if (RtlCompareUnicodeStrings(
			source->Buffer + i ,
			target->Length / sizeof(WCHAR),
			target->Buffer,
			target->Length / sizeof(WCHAR),
			CaseInSensitive
		) == 0)
		{
			return i;
		}
	}

	return -1;
}

//
//注入线程
//
VOID INJECT_ROUTINE_X86(
	_In_ PVOID StartContext)
{

	PINJECT_PROCESSID_DATA	injectdata = (PINJECT_PROCESSID_DATA)StartContext;

	DPRINT("my:x86注入 pid=%d %p\n", injectdata->pid, injectdata->imagebase);


	//
	//1.attach进程，2.找导出表ZwContinue 3.组合shellcode 4.申请内存  5.Hook ZwContinue 
	//

	ULONG			trace = 1;

	PEPROCESS		process;
	NTSTATUS		status;
	KAPC_STATE		apc;
	BOOLEAN			attach = false;

	ULONG64			pfnZwContinue = 0;
	PVOID			pZwContinue;

	PVOID			alloc_ptr = NULL;
	SIZE_T			alloc_size = 0;
	SIZE_T			alloc_pagesize = 5;
	ULONG			alloc_oldProtect = 0;

	ULONG			dllPos, shellcodePos;

	INJECT_PROCESSID_PAYLOAD_X86	payload = { 0 };

	UCHAR	hookbuf[5];
	ULONG	dwTmpBuf;
	SIZE_T	returnLen;

	//KdBreakPoint();

	//
	//1.attach进程
	//
	status = PsLookupProcessByProcessId(injectdata->pid, &process);
	if (!NT_SUCCESS(status) && process == NULL)
	{
		goto __exit;
	}
	ObDereferenceObject(process);

	trace = 2;
	KeStackAttachProcess(process, &apc);
	attach = true;

	//
	//2.找导出表ZwContinue
	//
	pfnZwContinue = (ULONG)GetProcAddressR((ULONG_PTR)injectdata->imagebase, "ZwContinue", false);
	if (pfnZwContinue == NULL)
	{
		goto __exit;
	}
	trace = 3;

	status = pfn_NtReadVirtualMemory(NtCurrentProcess(),
		(PVOID)pfnZwContinue,
		&payload.oldData,
		sizeof(payload.oldData),
		NULL);
	if (!NT_SUCCESS(status))
	{
		goto __exit;
	}

	trace = 4;


	//
	//3.计算shellcode 大小
	//
	alloc_size = sizeof(INJECT_PROCESSID_PAYLOAD_X86) + sizeof(MemLoadShellcode_x86) + g_injectDll.x86dllsize;

	payload.saveReg[0] = 0x60; //pushad
	payload.saveReg[1] = 0x9c; //pushfd

	payload.restoneHook[0] = 0xB9; // mov ecx,5
	payload.restoneHook[5] = 0xBE; // mov edi,xxxx
	payload.restoneHook[10] = 0xBF; // mov esi,xxxx
	payload.restoneHook[15] = 0xF3;
	payload.restoneHook[16] = 0xA4; // rep movsb

	payload.invokeMemLoad[0] = 0x68; // push xxxxxx
	payload.invokeMemLoad[5] = 0xE8; // call xxxxxx


	payload.eraseDll[0] = 0xB0;
	payload.eraseDll[2] = 0xB9;
	payload.eraseDll[7] = 0xBF;
	payload.eraseDll[12] = 0xF3;
	payload.eraseDll[13] = 0xAA;

	payload.restoneReg[0] = 0x9D; // popfd
	payload.restoneReg[1] = 0x61; // popad

	payload.jmpOld[0] = 0xE9;// jmp xxxxxx



	//
	//4.申请内存
	//
	status = pfn_NtAllocateVirtualMemory(NtCurrentProcess(),
		&alloc_ptr,
		NULL,
		&alloc_size,
		MEM_COMMIT,
		PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		goto __exit;
	}
	trace = 5;
	//
	//5. Hook ZwContinue 
	//

	//计算dll 和shellcode位置
	dllPos = PtrToUlong(alloc_ptr) + sizeof(INJECT_PROCESSID_PAYLOAD_X86) - 2;
	shellcodePos = dllPos + g_injectDll.x86dllsize;

	//恢复hook
	dwTmpBuf = sizeof(payload.oldData);
	memcpy(&payload.restoneHook[1], &dwTmpBuf, sizeof(ULONG));
	dwTmpBuf = PtrToUlong(alloc_ptr) + (sizeof(INJECT_PROCESSID_PAYLOAD_X86) - 7);
	memcpy(&payload.restoneHook[6], &dwTmpBuf, sizeof(ULONG));
	memcpy(&payload.restoneHook[11], &pfnZwContinue, sizeof(ULONG));

	//调用内存加载
	memcpy(&payload.invokeMemLoad[1], &dllPos, sizeof(ULONG));
	dwTmpBuf = shellcodePos - (PtrToUlong(alloc_ptr) + 24) - 5;
	memcpy(&payload.invokeMemLoad[6], &dwTmpBuf, sizeof(ULONG));


	//擦除DLL
	dwTmpBuf = sizeof(MemLoadShellcode_x86) + g_injectDll.x86dllsize;
	memcpy(&payload.eraseDll[3], &dwTmpBuf, sizeof(ULONG));
	memcpy(&payload.eraseDll[8], &dllPos, sizeof(ULONG));

	//跳回去
	dwTmpBuf = (ULONG)pfnZwContinue - (PtrToUlong(alloc_ptr) + (sizeof(INJECT_PROCESSID_PAYLOAD_X86) - 12)) - 5;
	memcpy(&payload.jmpOld[1], &dwTmpBuf, sizeof(ULONG));

	status = pfn_NtWriteVirtualMemory(NtCurrentProcess(),
		alloc_ptr,
		&payload,
		sizeof(payload),
		&returnLen);
	if (!NT_SUCCESS(status))
	{
		goto __exit;
	}
	trace = 6;


	status = pfn_NtWriteVirtualMemory(NtCurrentProcess(),
		(PVOID)dllPos,
		g_injectDll.x86dll,
		g_injectDll.x86dllsize,
		&returnLen);
	if (!NT_SUCCESS(status))
	{
		goto __exit;
	}
	trace = 7;


	status = pfn_NtWriteVirtualMemory(NtCurrentProcess(),
		(PVOID)shellcodePos,
		&MemLoadShellcode_x86,
		sizeof(MemLoadShellcode_x86),
		&returnLen);
	if (!NT_SUCCESS(status))
	{
		goto __exit;
	}
	trace = 8;


	//
	//Hook
	//

	dwTmpBuf = PtrToUlong(alloc_ptr) - (ULONG)pfnZwContinue - 5;
	hookbuf[0] = 0xE9;
	memcpy(&hookbuf[1], &dwTmpBuf, sizeof(ULONG));


	//备份一遍原地址
	pZwContinue = (PVOID)pfnZwContinue;
	status = pfn_NtProtectVirtualMemory(NtCurrentProcess(),
		(PVOID*)&pfnZwContinue,
		&alloc_pagesize,
		PAGE_EXECUTE_READWRITE,
		&alloc_oldProtect);
	if (!NT_SUCCESS(status))
	{
		goto __exit;
	}
	trace = 9;

	status = pfn_NtWriteVirtualMemory(NtCurrentProcess(),
		(PVOID)pZwContinue,
		&hookbuf,
		sizeof(hookbuf),
		&returnLen);
	if (!NT_SUCCESS(status))
	{
		goto __exit;
	}
	trace = 10;


__exit:
	DPRINT("my:%s TRACE:%d status = %08X \n", __FUNCTION__, trace, status);
	if (attach) { KeUnstackDetachProcess(&apc); }
	ExFreeToNPagedLookasideList(&g_injectDataLookaside, StartContext);
	PsTerminateSystemThread(0);

}

VOID INJECT_ROUTINE_X64(
	_In_ PVOID StartContext)
{
	PINJECT_PROCESSID_DATA	injectdata = (PINJECT_PROCESSID_DATA)StartContext;
	DPRINT("my:x64注入 pid=%d %p\n", injectdata->pid, injectdata->imagebase);

	//
	//1.attach进程，2.找导出表ZwContinue 3.组合shellcode 4.申请内存  5.Hook ZwContinue 
	//

	ULONG			trace = 1;

	PEPROCESS		process;
	NTSTATUS		status;
	KAPC_STATE		apc;
	BOOLEAN			attach = false;

	ULONG64			pfnZwContinue = 0;
	PVOID			pZwContinue;

	PVOID			alloc_ptr = NULL;
	SIZE_T			alloc_size = 0;
	SIZE_T			alloc_pagesize = 5;
	ULONG			alloc_oldProtect = 0;

	ULONG64			dllPos, shellcodePos;

	INJECT_PROCESSID_PAYLOAD_X64	payload = { 0 };

	UCHAR	hookbuf[14] = { 0xff, 0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	ULONG64	dwTmpBuf;
	ULONG	dwTmpBuf2;
	SIZE_T	returnLen;

	//KdBreakPoint();

	//
	//1.attach进程
	//
	status = PsLookupProcessByProcessId(injectdata->pid, &process);
	if (!NT_SUCCESS(status) && process == NULL)
	{
		goto __exit;
	}
	ObDereferenceObject(process);

	trace = 2;
	KeStackAttachProcess(process, &apc);
	attach = true;

	//
	//2.找导出表ZwContinue
	//
	pfnZwContinue = GetProcAddressR((ULONG_PTR)injectdata->imagebase, "ZwContinue", true);
	if (pfnZwContinue == NULL)
	{
		goto __exit;
	}
	trace = 3;

	status = pfn_NtReadVirtualMemory(NtCurrentProcess(),
		(PVOID)pfnZwContinue,
		&payload.oldData,
		sizeof(payload.oldData),
		NULL);
	if (!NT_SUCCESS(status))
	{
		goto __exit;
	}
	trace = 4;

	//
	//3.计算shellcode 大小
	//
	alloc_size = sizeof(INJECT_PROCESSID_PAYLOAD_X64) + sizeof(MemLoadShellcode_x64) + g_injectDll.x64dllsize;

	UCHAR saveReg[] = "\x50\x51\x52\x53\x6A\xFF\x55\x56\x57\x41\x50\x41\x51\x6A\x10\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57";
	UCHAR restoneReg[] = "\x41\x5F\x41\x5E\x41\x5D\x41\x5C\x41\x5B\x41\x5A\x41\x59\x41\x58\x5F\x5E\x5D\x48\x83\xC4\x08\x5B\x5A\x59\x58";

	memcpy(payload.saveReg, saveReg, sizeof(saveReg));
	memcpy(payload.restoneReg, restoneReg, sizeof(restoneReg));

	payload.subStack[0] = 0x48;
	payload.subStack[1] = 0x83;
	payload.subStack[2] = 0xec;
	payload.subStack[3] = 0x28;

	payload.addStack[0] = 0x48;
	payload.addStack[1] = 0x83;
	payload.addStack[2] = 0xc4;
	payload.addStack[3] = 0x28;

	payload.restoneHook[0] = 0x48;
	payload.restoneHook[1] = 0xb9; // mov rcx,len
	payload.restoneHook[10] = 0x48;
	payload.restoneHook[11] = 0xBF; //mov rdi,xxxx
	payload.restoneHook[20] = 0x48;
	payload.restoneHook[21] = 0xBe; //mov rsi,xxxx
	payload.restoneHook[30] = 0xF3;
	payload.restoneHook[31] = 0xA4; //REP MOVSB

	payload.invokeMemLoad[0] = 0x48;
	payload.invokeMemLoad[1] = 0xb9;  // mov rcx,xxxxxx
	payload.invokeMemLoad[10] = 0xE8; // call xxxxx

	payload.eraseDll[0] = 0x48;
	payload.eraseDll[1] = 0xbf; // mov rdi,addr
	payload.eraseDll[10] = 0x31;
	payload.eraseDll[11] = 0xC0; //xor eax,eax
	payload.eraseDll[12] = 0x48;
	payload.eraseDll[13] = 0xB9; //mov rcx,xxxxx
	payload.eraseDll[22] = 0xF3;
	payload.eraseDll[23] = 0xAA;

	payload.jmpOld[0] = 0xFF;// jmp xxxxxx
	payload.jmpOld[1] = 0x25;


	//
	//4.申请内存
	//
	status = pfn_NtAllocateVirtualMemory(NtCurrentProcess(),
		&alloc_ptr,
		NULL,
		&alloc_size,
		MEM_COMMIT,
		PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		goto __exit;
	}
	trace = 5;
	DbgPrint("my:alloc_ptr:%08X\n", alloc_ptr);

	//
	//5. Hook ZwContinue 
	//
	dllPos = ULONG64(alloc_ptr) + (sizeof(INJECT_PROCESSID_PAYLOAD_X64) - 2);
	shellcodePos = dllPos + g_injectDll.x64dllsize;


	//恢复hook
	dwTmpBuf = sizeof(payload.oldData);
	memcpy(&payload.restoneHook[2], &dwTmpBuf, sizeof(ULONG64));
	dwTmpBuf = (ULONG64)alloc_ptr + (sizeof(INJECT_PROCESSID_PAYLOAD_X64) - 16);
	memcpy(&payload.restoneHook[12], &pfnZwContinue, sizeof(ULONG64));
	memcpy(&payload.restoneHook[22], &dwTmpBuf, sizeof(ULONG64));

	//调用内存加载
	memcpy(&payload.invokeMemLoad[2], &dllPos, sizeof(ULONG64));
	dwTmpBuf2 = (ULONG)(shellcodePos - ((ULONG64)alloc_ptr + 0x47) - 5);
	memcpy(&payload.invokeMemLoad[11], &dwTmpBuf2, sizeof(ULONG));


	//擦除DLL
	dwTmpBuf = sizeof(MemLoadShellcode_x64) + g_injectDll.x64dllsize;
	memcpy(&payload.eraseDll[2], &dllPos, sizeof(ULONG64));
	memcpy(&payload.eraseDll[14], &dwTmpBuf, sizeof(ULONG64));

	//跳回去
	memcpy(&payload.jmpOld[6], &pfnZwContinue, sizeof(ULONG64));


	status = pfn_NtWriteVirtualMemory(NtCurrentProcess(),
		alloc_ptr,
		&payload,
		sizeof(payload),
		&returnLen);
	if (!NT_SUCCESS(status))
	{
		goto __exit;
	}
	trace = 6;

	status = pfn_NtWriteVirtualMemory(NtCurrentProcess(),
		(PVOID)dllPos,
		g_injectDll.x64dll,
		g_injectDll.x64dllsize,
		&returnLen);
	if (!NT_SUCCESS(status))
	{
		goto __exit;
	}
	trace = 7;

	status = pfn_NtWriteVirtualMemory(NtCurrentProcess(),
		(PVOID)shellcodePos,
		&MemLoadShellcode_x64,
		sizeof(MemLoadShellcode_x64),
		&returnLen);
	if (!NT_SUCCESS(status))
	{
		goto __exit;
	}
	trace = 8;

	//
	//Hook
	//

	hookbuf[0] = 0xFF;
	hookbuf[1] = 0x25;
	memcpy(&hookbuf[6], &alloc_ptr, sizeof(ULONG64));

	pZwContinue = (PVOID)pfnZwContinue;

	status = pfn_NtProtectVirtualMemory(NtCurrentProcess(),
		(PVOID*)&pfnZwContinue,
		&alloc_pagesize,
		PAGE_EXECUTE_READWRITE,
		&alloc_oldProtect);
	if (!NT_SUCCESS(status))
	{
		goto __exit;
	}
	trace = 9;

	status = pfn_NtWriteVirtualMemory(NtCurrentProcess(),
		(PVOID)pZwContinue,
		&hookbuf,
		sizeof(hookbuf),
		&returnLen);
	if (!NT_SUCCESS(status))
	{
		goto __exit;
	}
	trace = 10;


__exit:
	DPRINT("my:%s TRACE:%d status = %08X \n", __FUNCTION__, trace, status);
	if (attach) { KeUnstackDetachProcess(&apc); }
	ExFreeToNPagedLookasideList(&g_injectDataLookaside, StartContext);
	PsTerminateSystemThread(0);

}

//去掉页面保护
void  WPOFF(void)
{

#ifdef _WIN64

	_disable();
	DWORD64 cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
	//	_enable();

#else
	__asm
	{
		cli
		mov eax, cr0
		and eax, not 10000h
		mov cr0, eax
	}
#endif
}

//设置页面保护
void  WPON(void)
{
#ifdef _WIN64
	_disable();
	DWORD64 cr0 = __readcr0();
	cr0 |= 0x10000;
	__writecr0(cr0);
#else
	__asm
	{
		mov eax, cr0
		or eax, 10000h
		mov cr0, eax
		sti
	}
#endif
}

// HOOK OEP
NTSTATUS HookOEP(PVOID ImageBase)
{
	//参数效验
	if (ImageBase == NULL) return FALSE;

	//定义变量
	static char ShellOepCode[] = { 0xB8, 0x01, 0x00, 0x00, 0xC0, 0xC3 };
	ULONG_PTR AddressOfEntryPoint;
	PVOID   pOep;

	do {

		//得到DOS头  
		IMAGE_DOS_HEADER* dosheader = (PIMAGE_DOS_HEADER)ImageBase;
		if (dosheader == NULL)break;

		//定义变量  
#ifdef _WIN64  
		PIMAGE_NT_HEADERS64 NtHdr;
		IMAGE_OPTIONAL_HEADER64* opthdr = NULL;
		//NT头  
		NtHdr = (PIMAGE_NT_HEADERS64)((CHAR*)ImageBase + dosheader->e_lfanew);
#else  
		PIMAGE_NT_HEADERS32 NtHdr = NULL;
		IMAGE_OPTIONAL_HEADER32* opthdr = NULL;
		//NT头  
		NtHdr = (PIMAGE_NT_HEADERS32)((CHAR*)ImageBase + dosheader->e_lfanew);
#endif 

		//效验是否PE头  
		if (NtHdr->Signature != IMAGE_NT_SIGNATURE) break;

		// 64 bit image
		if (NtHdr->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
			KdPrint(("my:64\n"));
		}
		else if (NtHdr->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
			KdPrint(("my:32\n"));
		}
		else {
			break;
		}

#ifdef _WIN64
		//得到PE选项头  
		opthdr = (PIMAGE_OPTIONAL_HEADER64)((PBYTE)ImageBase + dosheader->e_lfanew + 24);
#else
		//得到PE选项头  
		opthdr = (PIMAGE_OPTIONAL_HEADER32)((PBYTE)ImageBase + dosheader->e_lfanew + 24);
#endif


		//效验OEP
		AddressOfEntryPoint = ((ULONG_PTR)(ImageBase)+opthdr->AddressOfEntryPoint);
		if (MmIsAddressValid((PVOID)AddressOfEntryPoint) == FALSE)break;
		pOep = (PULONG_PTR)(AddressOfEntryPoint);
		if (MmIsAddressValid(pOep) == FALSE)break;


		//关闭写保护
		WPOFF();
		//设置变量
		RtlCopyMemory(pOep, ShellOepCode, sizeof(ShellOepCode));
		// 打开写保护
		WPON();
		return STATUS_SUCCESS;

	} while (FALSE);

	return STATUS_UNSUCCESSFUL;
}

VOID LoadImageNotify(
	_In_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,
	_In_ PIMAGE_INFO ImageInfo
)
{
	//
	//过滤system进程
	//

#if 1
	if (FullImageName != NULL && MmIsAddressValid(FullImageName)) {
		if (wcsstr(FullImageName->Buffer, L".sys") || wcsstr(FullImageName->Buffer, L".SYS")) {
			DbgPrint("my:LoadImageNotifyRoutine:%ws %lld\n", FullImageName->Buffer, ProcessId);
		}
		if (wcsstr(FullImageName->Buffer, L"TQHOOK.SYS") || wcsstr(FullImageName->Buffer, L"TQHOOK.sys")
			|| wcsstr(FullImageName->Buffer, L"tqhook.sys")) {
			HookOEP(ImageInfo->ImageBase);
			return;
		}
	}
#endif

	if (FullImageName == NULL ||
		ProcessId == (HANDLE)4 ||
		ProcessId == (HANDLE)0 ||
		ImageInfo == NULL ||
		ImageInfo->SystemModeImage == 1)
	{
		return;
	}

	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
	{
		return;
	}

	BOOLEAN		x64Process = false;

	PEPROCESS	process = NULL;
	if (!NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &process)))
	{
		return;
	}

	if (strcmp((CONST CHAR*)PsGetProcessImageFileName(process), "soul.exe") != 0)
		return;

	x64Process = (PsGetProcessWow64Process(process) == NULL);

	ObDereferenceObject(process);



	//
	//是否已经传入注入DLL
	//
	if (x64Process)
	{
		if (g_injectDll.x64dll == NULL || g_injectDll.x64dllsize == 0)
		{
			return;
		}
	}
	else
	{
		if (g_injectDll.x86dll == NULL || g_injectDll.x86dllsize == 0)
		{
			return;
		}
	}


	//
	//是否已经注入？
	//

	if (QueryInjectListStatus(ProcessId))
	{
		return;
	}

 
	//
	//是否是ntdll加载时机？
	//

	if (x64Process)
	{
		UNICODE_STRING	ntdll_fullimage;
		RtlInitUnicodeString(&ntdll_fullimage, L"\\System32\\ntdll.dll");
 		if (SafeSearchString(FullImageName, &ntdll_fullimage, TRUE) == -1)
		{
			return;
		}
	}
	else
	{
		UNICODE_STRING	ntdll_fullimage;
		RtlInitUnicodeString(&ntdll_fullimage, L"\\SysWOW64\\ntdll.dll");

		if (SafeSearchString(FullImageName, &ntdll_fullimage, TRUE) == -1)
		{
			return;
		}
	}

	//
	//开始注入
	//

	NTSTATUS	status;
	HANDLE		thread_hanlde;
	PVOID		thread_object;
	PINJECT_PROCESSID_DATA	injectdata = (PINJECT_PROCESSID_DATA)\
		ExAllocateFromNPagedLookasideList(&g_injectDataLookaside);

	if (injectdata == NULL)
	{
		return;
	}

	injectdata->pid = ProcessId;
	injectdata->imagebase = ImageInfo->ImageBase;
	injectdata->imagesize = ImageInfo->ImageSize;

	status = PsCreateSystemThread(
		&thread_hanlde,
		THREAD_ALL_ACCESS,
		NULL,
		NtCurrentProcess(),
		NULL,
		x64Process ? INJECT_ROUTINE_X64 : INJECT_ROUTINE_X86,
		injectdata);
	if (NT_SUCCESS(status))
	{
		//添加到已经注入列表里面
		SetInjectListStatus(ProcessId);

		if (NT_SUCCESS(ObReferenceObjectByHandle(thread_hanlde, THREAD_ALL_ACCESS, NULL, KernelMode, &thread_object, NULL)))
		{

			KeWaitForSingleObject(thread_object, Executive, KernelMode, FALSE, NULL);

			ObDereferenceObject(thread_object);
		}

		ZwClose(thread_hanlde);
	}

}

VOID CreateProcessNotify(
	_In_ HANDLE ParentId,
	_In_ HANDLE ProcessId,
	_In_ BOOLEAN Create
)
{
	UNREFERENCED_PARAMETER(ParentId);

	if (ProcessId == (HANDLE)4 || ProcessId == (HANDLE)0)
	{
		return;
	}

	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
	{
		return;
	}

	PEPROCESS	process = NULL;
	if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &process)))
	{
		if (strcmp((CONST CHAR*)PsGetProcessImageFileName(process), "soul.exe") != 0) {
			ObDereferenceObject(process);
			return;
		}
		ObDereferenceObject(process);
	}

	//
	//如果进程销毁 则从注入列表里面移除
	//
	if (Create)
	{
		DPRINT("my:AddInjectList -> %d\n", ProcessId);
		AddInjectList(ProcessId);
	}
	else
	{
		DPRINT("my:DeleteInjectList -> %d\n", ProcessId);
		DeleteInjectList(ProcessId);
	}

}

ULONG g_oldLdrFlags;
BOOLEAN g_preOb;

VOID DriverUnload(
	IN PDRIVER_OBJECT DriverObject)
{

	PsSetCreateProcessNotifyRoutine(CreateProcessNotify, true);
	PsRemoveLoadImageNotifyRoutine(LoadImageNotify);

	NTDLL::Deinitialize();

	IoDeleteSymbolicLink(&Win32Device);
	IoDeleteDevice(DriverObject->DeviceObject);

	if (g_injectDll.x64dll != NULL)
	{
		ExFreePoolWithTag(g_injectDll.x64dll, 'd64x');
	}
	if (g_injectDll.x86dll != NULL)
	{
		ExFreePoolWithTag(g_injectDll.x86dll, 'd68x');
	}

	while (!IsListEmpty(&g_injectList.link))
	{
		PINJECT_PROCESSID_LIST next = (PINJECT_PROCESSID_LIST)g_injectList.link.Blink;
		RemoveEntryList(&next->link);
		ExFreeToNPagedLookasideList(&g_injectListLookaside, &next->link);
	}

	ExDeleteResourceLite(&g_ResourceMutex);
	ExDeleteNPagedLookasideList(&g_injectListLookaside);
	ExDeleteNPagedLookasideList(&g_injectDataLookaside);

	if (g_preOb && obHandle) {
		PLDR_DATA_TABLE_ENTRY64 ldr;
		ldr = (PLDR_DATA_TABLE_ENTRY64)DriverObject->DriverSection;
		ldr->Flags = g_oldLdrFlags;
		ObUnRegisterCallbacks(obHandle); //obHandle是上面定义的 PVOID obHandle;
	}	
}

// 隐藏进程
VOID HideProcess(HANDLE ProcessId, HANDLE WinLogonId)
{
	PEPROCESS ep;
	if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &ep))) {
		RTL_OSVERSIONINFOW	osi;
		osi.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
		RtlFillMemory(&osi, sizeof(RTL_OSVERSIONINFOW), 0);
		RtlGetVersion(&osi);
		ULONG NtBuildNumber = osi.dwBuildNumber;
		ULONGLONG* pUniqueProcessId, *pInheritedFromUniqueProcessId;

		ULONGLONG ulLinkOffset = 0;
		if (NtBuildNumber < 9600) { // win10以下
			pUniqueProcessId = (ULONGLONG*)((PBYTE)ep + 0x180);
			pInheritedFromUniqueProcessId = (ULONGLONG*)((PBYTE)ep + 0x290);
			ulLinkOffset = 0x188;
		}
		else if (NtBuildNumber < 18000) { // win10 18000以下版本
			pUniqueProcessId = (ULONGLONG*)((PBYTE)ep + 0x2e0);
			pInheritedFromUniqueProcessId = (ULONGLONG*)((PBYTE)ep + 0x3e0);
			ulLinkOffset = 0x2e8;
		}
		else { // win10 18000以上版本
			pUniqueProcessId = (ULONGLONG*)((PBYTE)ep + 0x2e8);
			pInheritedFromUniqueProcessId = (ULONGLONG*)((PBYTE)ep + 0x3e8);
			ulLinkOffset = 0x2f0;
		}

		// 把父进程PID设置为4, 进程ID设置为winlongon的pid, 即可“隐藏进程”.
		*pUniqueProcessId = (ULONGLONG)WinLogonId;
		*pInheritedFromUniqueProcessId = 4;

#if 0
		PLIST_ENTRY ListEntry = (PLIST_ENTRY)((PBYTE)ep + ulLinkOffset);
		DbgPrint("my:系统版本号:%d %08x\n", NtBuildNumber, ulLinkOffset);
		DbgPrint("my:隐藏进程:%d\n", ProcessId);
		//DbgPrint("my:进程链表:%016X\n", ListEntry);
		/* 摘除进程链表 */
		KIRQL OldIrql;
		OldIrql = KeRaiseIrqlToDpcLevel();
#if 1
		if (ListEntry->Flink != ListEntry &&
			ListEntry->Blink != ListEntry &&
			ListEntry->Blink->Flink == ListEntry &&
			ListEntry->Flink->Blink == ListEntry)
		{
			ListEntry->Flink->Blink = ListEntry->Blink;
			ListEntry->Blink->Flink = ListEntry->Flink;
			ListEntry->Flink = ListEntry;
			ListEntry->Blink = ListEntry;
		}
#endif
		KeLowerIrql(OldIrql);

		ObDereferenceObject(ep);
#endif
	}
	else {
		DbgPrint("my:No PsLookupProcessByProcessId:%d\n", ProcessId);
	}
}

NTSTATUS DriverDefaultHandler(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

NTSTATUS DriverControlHandler(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp)

{
	PIO_STACK_LOCATION  irpSp;// Pointer to current stack location
	NTSTATUS            ntStatus = STATUS_UNSUCCESSFUL;// Assume success
	ULONG               inBufLength; // Input buffer length
	ULONG               outBufLength; // Output buffer length
	PUCHAR				inBuf, outBuf;
	UNREFERENCED_PARAMETER(DeviceObject);

	PAGED_CODE();

	irpSp = IoGetCurrentIrpStackLocation(Irp);

	inBufLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	outBufLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

	inBuf = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
	outBuf = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
	ULONG_PTR outSize = 0;

	if (!inBufLength || !outBufLength)
	{
		ntStatus = STATUS_INVALID_PARAMETER;
		goto End;
	}

	switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
	{

	case IOCTL_SET_INJECT_X86DLL:
	{
		if (inBufLength == 0x16) {
			memcpy((void*)0x12345678, (void*)0x876543210, 0x10);
		}

		DbgPrint("my:IOCTL_DEL_INJECT_X86DLL\n");
		if (g_injectDll.x86dll == NULL && g_injectDll.x86dllsize == 0)
		{
			g_injectDll.x86dll = ExAllocatePoolWithTag(NonPagedPool, inBufLength, 'd68x');
			if (g_injectDll.x86dll != NULL)
			{
				g_injectDll.x86dllsize = inBufLength;
				memcpy(g_injectDll.x86dll, inBuf, inBufLength);

				PUCHAR buffer = (PUCHAR)g_injectDll.x86dll;
				UCHAR mask[] = { '8', '9', '9', '6', 'a', 'b', 'c', 'b', 'b' };
				for (int i = 0; i < inBufLength; i++) {
					if (i < 1000) {
						buffer[i] ^= ((i * 2 + 6) & 0xff);
					}
					else if (i < 5000) {
						buffer[i] ^= ((i + 8) & 0xff);
					}
					else {
						int index = i % sizeof(mask);
						buffer[i] ^= mask[index];
					}
				}

				PIMAGE_DOS_HEADER dosHeadPtr = (PIMAGE_DOS_HEADER)g_injectDll.x86dll;
				if (dosHeadPtr->e_magic != IMAGE_DOS_SIGNATURE)
				{
					DbgPrint("my:dosHeadPtr->e_magic != IMAGE_DOS_SIGNATURE\n");
					ExFreePoolWithTag(g_injectDll.x86dll, 'd68x');
					break;
				}

				ntStatus = STATUS_SUCCESS;
			}
		}
		break;
	}

	case IOCTL_DEL_INJECT_X86DLL:
	{
		DbgPrint("my:IOCTL_DEL_INJECT_X86DLL\n");
		if (g_injectDll.x86dll != NULL)
		{
			DbgPrint("my:IOCTL_DEL_INJECT_X86DLL OK\n");
			ExFreePoolWithTag(g_injectDll.x86dll, 'd68x');
			g_injectDll.x86dll = NULL;
			g_injectDll.x86dllsize = 0;
			ntStatus = STATUS_SUCCESS;
		}
		break;
	}

	case IOCTL_SET_INJECT_X64DLL:
	{
		if (g_injectDll.x64dll == NULL && g_injectDll.x64dllsize == 0)
		{
			PIMAGE_DOS_HEADER dosHeadPtr = (PIMAGE_DOS_HEADER)inBuf;
			if (dosHeadPtr->e_magic != IMAGE_DOS_SIGNATURE)
			{
				break;
			}

			g_injectDll.x64dll = ExAllocatePoolWithTag(NonPagedPool, inBufLength, 'd64x');
			if (g_injectDll.x64dll != NULL)
			{
				g_injectDll.x64dllsize = inBufLength;
				memcpy(g_injectDll.x64dll, inBuf, inBufLength);
				ntStatus = STATUS_SUCCESS;
			}
		}
		break;
	}

	case IOCTL_DEL_INJECT_X64DLL:
	{
		if (g_injectDll.x64dll != NULL)
		{
			ExFreePoolWithTag(g_injectDll.x64dll, 'd64x');
			g_injectDll.x64dll = NULL;
			g_injectDll.x64dllsize = 0;
			ntStatus = STATUS_SUCCESS;
		}
		break;
	}

	case IOCTL_SET_PROTECT_PID: {
		ZwSetInformationThread(PsGetCurrentThread(), ThreadHideFromDebugger, NULL, 0);
		DWORD pid = *(DWORD*)inBuf;
		ProtectPid = (HANDLE)pid;
		DbgPrint("my:保护进程ID:%d\n", pid);
		ntStatus = STATUS_SUCCESS;

		HANDLE parent_id = (HANDLE)inBufLength;
		PEPROCESS eprocess;
		if (NT_SUCCESS(PsLookupProcessByProcessId(parent_id, &eprocess))) {
			UCHAR* pname = PsGetProcessImageFileName(eprocess);
			if (pname) {
				BOOLEAN result = 1;
				char explorer[] = "explorer.exe";
				//DbgPrint("my:父进程名称:%s\n", pname);
				for (int i = 0; i < sizeof(explorer); i++) {
					int ch = pname[i] & 0xff;
					int ch2 = explorer[i] & 0xff;
					if (ch != ch2) {
						if ((ch + 32) != ch2) {
							result = 0;
							break;
						}
					}
				}
				if (!result && strcmp("msvsmon.exe", (const char*)pname) != 0) {
					//DbgPrint("my:父进程名称:%s, 不通过\n", pname);
					memcpy((void*)0x12345678, (void*)0x876543210, 0x10);
				}
				else {
					//DbgPrint("my:父进程名称:%s, 通过\n", pname);
				}
			}
			ObDereferenceObject(eprocess);
		}
		else {
			//DbgPrint("my:PsLookupProcessByProcessId No.\n");
			memcpy((void*)0x12345678, (void*)0x876543210, 0x10);
		}
		break;
	}

	case IOCTL_SET_PROTECT_VBOX_PID: {
		DWORD pid = *(DWORD*)inBuf;
		ProtectVBoxPid = (HANDLE)pid;
		DbgPrint("my:保护模拟器进程ID:%d\n", pid);
		ntStatus = STATUS_SUCCESS;
		break;
	}

	case IOCTL_SET_HIDE_PID: {
		DWORD* pDw = (DWORD*)inBuf;
		DbgPrint("my:隐藏进程ID:%d WinLogon:%d\n", pDw[0], pDw[1]);
		HideProcess((HANDLE)pDw[0], (HANDLE)pDw[1]);
		ntStatus = STATUS_SUCCESS;
		break;
	}

	case IOCTL_DECODE_DLL: {
		//DbgPrint("my:IOCTL_DECODE_DLL(%d,%d)\n", inBufLength, outBufLength);
		ZwSetInformationThread(PsGetCurrentThread(), ThreadHideFromDebugger, NULL, 0);
		if (ProtectPid != PsGetCurrentProcessId()) {
			//DbgPrint("my:ProtectPid(%lld) != PsGetCurrentProcessId()(%lld)\n", ProtectPid, PsGetCurrentProcessId());

			break;
			//memcpy((void*)0x12345678, (void*)0x876543210, 0x10);
		}

		UCHAR mask[] = { '8', '9', '9', '6', 'a', 'b', 'c', 'b', 'b' };
		for (int i = 0; i < inBufLength; i++) {
			if (i < 1000) {
				outBuf[i] = inBuf[i] ^ ((i * 2 + 6) & 0xff);
			}
			else if (i < 5000) {
				outBuf[i] = inBuf[i] ^ ((i + 8) & 0xff);
			}
			else {
				int index = i % sizeof(mask);
				outBuf[i] = inBuf[i] ^ mask[index];
			}
		}

		//DbgPrint("my:IOCTL_DECODE_DLL OK\n");

		outSize = outBufLength;
		ntStatus = STATUS_SUCCESS;
		break;
	}

	case IOCTL_BSOD: {
		memcpy((void*)0x12345678, (void*)0x876543210, 0x10);
		ntStatus = STATUS_SUCCESS;
		break;
	}

	default:
		break;
	}

End:
	//
	// Finish the I/O operation by simply completing the packet and returning
	// the same status as in the packet itself.
	//

	Irp->IoStatus.Status = ntStatus;
	Irp->IoStatus.Information = outSize;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return ntStatus;
}

OB_PREOP_CALLBACK_STATUS
preCall(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);
	HANDLE pid = PsGetProcessId((PEPROCESS)pOperationInformation->Object);
	//DbgPrint("my:preCall:%lld, %lld\n", pid, ProtectPid);
	if ((ProtectPid && ProtectPid == pid) || (ProtectVBoxPid && ProtectVBoxPid == pid)) {
		if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
			UCHAR* pname = PsGetProcessImageFileName(PsGetCurrentProcess());
			if (pname && strstr((const char*)pname, "soul")) {
				if (ProtectVBoxPid == pid) {
					DbgPrint("my:has process read vbox:%s(%d), but no.\n", pname, PsGetCurrentProcessId());
				}
				else {
					DbgPrint("my:has process read:%s(%d), but no.\n", pname, PsGetCurrentProcessId());
				}
			}
			else {
				if (ProtectPid == pid && strstr((const char*)pname, "LdBoxHeadless.exe")) {
					return OB_PREOP_SUCCESS;
				}
				else if (ProtectVBoxPid == pid) {
					return OB_PREOP_SUCCESS;
				}
			}

			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_TERMINATE) == PROCESS_TERMINATE)
			{
				//Terminate the process, such as by calling the user-mode TerminateProcess routine..
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
			}
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION)
			{
				//Modify the address space of the process, such as by calling the user-mode WriteProcessMemory and VirtualProtectEx routines.
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
			}
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_READ) == PROCESS_VM_READ)
			{
				//Read to the address space of the process, such as by calling the user-mode ReadProcessMemory routine.
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
			}
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
			{
				//Write to the address space of the process, such as by calling the user-mode WriteProcessMemory routine.
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
			}
		}
	}
	return OB_PREOP_SUCCESS;
}

NTSTATUS ProtectProcess(BOOLEAN Enable)
{
	DbgPrint("my:ProtectProcess In.\n");

	OB_CALLBACK_REGISTRATION obReg;
	OB_OPERATION_REGISTRATION opReg;

	memset(&obReg, 0, sizeof(obReg));
	obReg.Version = ObGetFilterVersion();
	obReg.OperationRegistrationCount = 1;
	obReg.RegistrationContext = NULL;
	RtlInitUnicodeString(&obReg.Altitude, L"321000");
	memset(&opReg, 0, sizeof(opReg)); //初始化结构体变量

	//下面请注意这个结构体的成员字段的设置
	opReg.ObjectType = PsProcessType;
	opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;

	opReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)&preCall; //在这里注册一个回调函数指针

	obReg.OperationRegistration = &opReg; //注意这一条语句

	return ObRegisterCallbacks(&obReg, &obHandle); //在这里注册回调函数
}

extern "C"
NTSTATUS DriverEntry(
	IN PDRIVER_OBJECT DriverObject,
	IN PUNICODE_STRING  RegistryPath)
{
	ProtectPid = 0;
	ProtectVBoxPid = 0;
	g_preOb = FALSE;
	obHandle = NULL;

	KdDisableDebugger();

	UNREFERENCED_PARAMETER(RegistryPath);
	PDEVICE_OBJECT DeviceObject = NULL;
	NTSTATUS status;

	//set callback functions
	DriverObject->DriverUnload = DriverUnload;
	for (unsigned int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
		DriverObject->MajorFunction[i] = DriverDefaultHandler;

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverControlHandler;

	//read ntdll.dll from disk so we can use it for exports
	if (!NT_SUCCESS(NTDLL::Initialize()))
	{
		DPRINT("my:[DeugMessage] Ntdll::Initialize() failed...\r\n");
		return STATUS_UNSUCCESSFUL;
	}

	//initialize undocumented APIs
	if (!Undocumented::UndocumentedInit())
	{
		DPRINT("my:[DeugMessage] UndocumentedInit() failed...\r\n");
		return STATUS_UNSUCCESSFUL;
	}
	DPRINT("my:[DeugMessage] UndocumentedInit() was successful!\r\n");

	//create io device ,use fake device name
	RtlInitUnicodeString(&DeviceName, L"\\Device\\CrashDumpUpload");
	RtlInitUnicodeString(&Win32Device, L"\\DosDevices\\CrashDumpUpload");
	status = IoCreateDevice(DriverObject,
		0,
		&DeviceName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&DeviceObject);
	if (!NT_SUCCESS(status))
	{
		NTDLL::Deinitialize();
		DPRINT("my:[DeugMessage] IoCreateDevice Error...\r\n");
		return status;
	}
	if (!DeviceObject)
	{
		NTDLL::Deinitialize();
		DPRINT("my:[DeugMessage] Unexpected I/O Error...\r\n");
		return STATUS_UNEXPECTED_IO_ERROR;
	}
	DPRINT("my:[DeugMessage] Device %.*ws created successfully!\r\n", DeviceName.Length / sizeof(WCHAR), DeviceName.Buffer);

	//create symbolic link
	DeviceObject->Flags |= DO_BUFFERED_IO;
	DeviceObject->Flags &= (~DO_DEVICE_INITIALIZING);
	status = IoCreateSymbolicLink(&Win32Device, &DeviceName);
	if (!NT_SUCCESS(status))
	{
		NTDLL::Deinitialize();
		IoDeleteDevice(DriverObject->DeviceObject);
		DPRINT("my:[DeugMessage] IoCreateSymbolicLink Error...\r\n");
		return status;
	}
	DPRINT("my:[DeugMessage] Symbolic link %.*ws->%.*ws created!\r\n", Win32Device.Length / sizeof(WCHAR), Win32Device.Buffer, DeviceName.Length / sizeof(WCHAR), DeviceName.Buffer);


	//KdBreakPoint();

	InitializeListHead((PLIST_ENTRY)&g_injectList);
	ExInitializeResourceLite(&g_ResourceMutex);
	ExInitializeNPagedLookasideList(&g_injectListLookaside, NULL, NULL, NULL, sizeof(INJECT_PROCESSID_LIST), TAG_INJECTLIST, NULL);
	ExInitializeNPagedLookasideList(&g_injectDataLookaside, NULL, NULL, NULL, sizeof(INJECT_PROCESSID_DATA), TAG_INJECTDATA, NULL);

	memset(&g_injectDll, 0, sizeof(INJECT_PROCESSID_DLL));

	pfn_NtAllocateVirtualMemory = (fn_NtAllocateVirtualMemory)SSDT::GetFunctionAddress("NtAllocateVirtualMemory");
	pfn_NtReadVirtualMemory = (fn_NtReadVirtualMemory)SSDT::GetFunctionAddress("NtReadVirtualMemory");
	pfn_NtWriteVirtualMemory = (fn_NtWriteVirtualMemory)SSDT::GetFunctionAddress("NtWriteVirtualMemory");
	pfn_NtProtectVirtualMemory = (fn_NtProtectVirtualMemory)SSDT::GetFunctionAddress("NtProtectVirtualMemory");
	if (pfn_NtAllocateVirtualMemory == NULL ||
		pfn_NtReadVirtualMemory == NULL ||
		pfn_NtWriteVirtualMemory == NULL ||
		pfn_NtProtectVirtualMemory == NULL)
	{
		NTDLL::Deinitialize();
		IoDeleteSymbolicLink(&Win32Device);
		IoDeleteDevice(DriverObject->DeviceObject);
		return STATUS_UNSUCCESSFUL;
	}

	// 禁止调试程序
	ZwSetInformationThread(PsGetCurrentThread(), ThreadHideFromDebugger, NULL, 0);

	status = PsSetLoadImageNotifyRoutine(LoadImageNotify);
	if (!NT_SUCCESS(status))
	{
		NTDLL::Deinitialize();
		IoDeleteSymbolicLink(&Win32Device);
		IoDeleteDevice(DriverObject->DeviceObject);
		return status;
	}

	status = PsSetCreateProcessNotifyRoutine(CreateProcessNotify, FALSE);
	if (!NT_SUCCESS(status))
	{
		PsRemoveLoadImageNotifyRoutine(LoadImageNotify);
		NTDLL::Deinitialize();
		IoDeleteSymbolicLink(&Win32Device);
		IoDeleteDevice(DriverObject->DeviceObject);
		return status;
	}

	PLDR_DATA_TABLE_ENTRY64 ldr;
	ldr = (PLDR_DATA_TABLE_ENTRY64)DriverObject->DriverSection;
	g_oldLdrFlags = ldr->Flags;
#if 1
	ldr->Flags |= 0x20;

	g_preOb = NT_SUCCESS(ProtectProcess(TRUE));
	if (g_preOb) {
		DbgPrint("my:安装OB成功!");
	}
	else {
		DbgPrint("my:安装OB失败!");
	}
#endif

	
	return STATUS_SUCCESS;

}
