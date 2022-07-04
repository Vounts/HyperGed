#pragma once
#include "HyperGed.hpp"

namespace util {
	VOID Callbacktest(PVOID args);
	NTSTATUS PowerCallbackRegistration();
	PVOID SvAllocatePageAlingedPhysicalMemory(_In_ SIZE_T NumberOfBytes);
	VOID SvFreePageAlingedPhysicalMemory(_Pre_notnull_ __drv_freesMem(Mem) PVOID BaseAddress);
	PVOID SvAllocateContiguousMemory(_In_ SIZE_T NumberOfBytes);
	VOID SvFreeContiguousMemory(_In_ PVOID BaseAddress);
	NTSTATUS SvExecuteOnEachProcessor(_In_ NTSTATUS(*Callback)(PVOID), _In_opt_ PVOID Context, _Out_opt_ PULONG NumOfProcessorCompleted);
	NTSTATUS SvDevirtualizeProcessor(_In_opt_ PVOID Context);
	BOOLEAN SvIsSimpleSvmHypervisorInstalled(VOID);
	VOID SvPrepareForVirtualization(_Inout_ PVIRTUAL_PROCESSOR_DATA VpData,_In_ PSHARED_VIRTUAL_PROCESSOR_DATA SharedVpData,_In_ const CONTEXT* ContextRecord);
	UINT16 SvGetSegmentAccessRight(_In_ UINT16 SegmentSelector,_In_ ULONG_PTR GdtBase);
	VOID SvBuildNestedPageTables(_Out_ PSHARED_VIRTUAL_PROCESSOR_DATA SharedVpData);
	VOID SvBuildMsrPermissionsMap(_Inout_ PVOID MsrPermissionsMap);
	NTSTATUS SvVirtualizeProcessor(_In_opt_ PVOID Context);
}