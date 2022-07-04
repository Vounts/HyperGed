#include <intrin.h>
#include <ntifs.h>
#include <stdarg.h>
#include "Utils.hpp"


#include "Logging.hpp"
#include "Definitions.hpp"

#define print(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, ULONG_MAX, __VA_ARGS__)


NTSTATUS HyperEntry(PVOID lpBaseAddress, DWORD32 size);
void main();
BOOLEAN SvIsSvmSupported();
NTSTATUS SvVirtualizeProcessor();
VOID SvDevirtualizeAllProcessors(VOID);
EXTERN_C BOOLEAN NTAPI SvHandleVmExit(_Inout_ PVIRTUAL_PROCESSOR_DATA VpData,_Inout_ PGUEST_REGISTERS GuestRegisters);
VOID SvHandleCpuid(_Inout_ PVIRTUAL_PROCESSOR_DATA VpData, _Inout_ PGUEST_CONTEXT GuestContext);
VOID SvHandleMsrAccess(_Inout_ PVIRTUAL_PROCESSOR_DATA VpData,_Inout_ PGUEST_CONTEXT GuestContext);
VOID SvHandleVmrun(_Inout_ PVIRTUAL_PROCESSOR_DATA VpData,_Inout_ PGUEST_CONTEXT GuestContext);
VOID SvInjectGeneralProtectionException(_Inout_ PVIRTUAL_PROCESSOR_DATA VpData); 