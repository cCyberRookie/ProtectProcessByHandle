#include <ntifs.h>


#define PROCESS_VM_READ           (0x0010)  // winnt
#define PROCESS_VM_WRITE          (0x0020)  // winnt


struct _HANDLE_TABLE_ENTRY_INFO
{
	ULONG AuditMask;                                                        //0x0
};

typedef struct _HANDLE_TABLE_ENTRY
{
	union
	{
		VOID* Object;                                                       //0x0
		ULONG ObAttributes;                                                 //0x0
		struct _HANDLE_TABLE_ENTRY_INFO* InfoTable;                         //0x0
		PVOID Value;                                                        //0x0
	};
	union
	{
		ULONG_PTR GrantedAccess : 25;                                               //0x4
		struct
		{
			USHORT GrantedAccessIndex;                                      //0x4
			USHORT CreatorBackTraceIndex;                                   //0x6
		};
		ULONG NextFreeTableEntry;                                           //0x4
	};
}HANDLE_TABLE_ENTRY, * PHANDLE_TABLE_ENTRY;

typedef BOOLEAN(NTAPI* EX_ENUMERATE_HANDLE_ROUTINE)(
	IN PHANDLE_TABLE_ENTRY HandleTableEntry,
	IN HANDLE Handle,
	IN PVOID EnumParameter
	);

BOOLEAN ExEnumHandleTable(
	__in PVOID HandleTable,
	__in EX_ENUMERATE_HANDLE_ROUTINE EnumHandleProcedure,
	__in PVOID EnumParameter,
	__out_opt PHANDLE Handle
);

__int64 __fastcall ExfUnblockPushLock(__int64 a1, __int64 a2);

BOOLEAN NTAPI enumRoutine(
	IN PVOID HandleTable,
	IN PHANDLE_TABLE_ENTRY HandleTableEntry,
	PVOID Unknow,
	IN PVOID eprocess
)
{
	BOOLEAN result = FALSE;
	if (HandleTableEntry)
	{

		ULONG_PTR object_header = (*(PLONG_PTR)(HandleTableEntry) >> 0x10) & 0xFFFFFFFFFFFFFFF0;

		ULONG_PTR object = object_header + 0x30;

		// 若该对象类型为进程，则该对象为该进程的EPROCESS
		if (object == (ULONG_PTR)eprocess)
		{
			//DbgBreakPoint();
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[db]:HandleTableEntry= %llx \r\n", HandleTableEntry);
			HandleTableEntry->GrantedAccess &= ~(PROCESS_VM_READ | PROCESS_VM_WRITE);
			result = TRUE;

		}

	}
	_InterlockedExchangeAdd64(HandleTableEntry, 1);
	if (*(PULONG_PTR)((ULONG_PTR)HandleTable + 0x30)) {
		ExfUnblockPushLock((ULONG_PTR)HandleTable + 0x30, 0);
	}
	return result;
}

VOID ProtectProcessByEprocess(PEPROCESS protected_eprocess)
{
	PEPROCESS eprocess = NULL;

	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)0x464, &eprocess);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,"find process error!\n");
		return;
	}

	//PVOID handle_table = ObReferenceProcessHandleTable(Process);
	PVOID handle_table = *(PVOID*)((LONG_PTR)eprocess + 0x418);
	PVOID Handle = NULL;
	ExEnumHandleTable(handle_table, enumRoutine, protected_eprocess, Handle);
	ObDereferenceObject(eprocess);

}



VOID DriverUnload(PDRIVER_OBJECT pDriver)
{
	return;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg)
{
	PEPROCESS eprocess = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)0x1D24, &eprocess);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "Open process  unsuccessfully!\n");
		return ;
	}
	ObDereferenceObject(eprocess);
	ProtectProcessByEprocess(eprocess);
	pDriver->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}