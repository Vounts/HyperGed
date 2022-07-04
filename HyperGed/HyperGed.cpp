#include "HyperGed.hpp"




NTSTATUS HyperEntry(PVOID lpBaseAddress, DWORD32 size, PVOID ntos, ULONG ntosize) {
	if (!lpBaseAddress || !size || !ntos || !ntosize)
		return STATUS_UNSUCCESSFUL;

	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

	HANDLE t_Handle = 0;

	PsCreateSystemThread(&t_Handle, THREAD_ALL_ACCESS, 0, 0, 0, (PKSTART_ROUTINE)main, 0);
	
	print("Entry succeeded\n");
	return STATUS_SUCCESS;
}

void main() {
	print("System main thread created\n");

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BOOLEAN needLogReinitialization;

    status = InitializeLogging(k_LogPutLevelDebug | k_LogOptDisableFunctionName, L"\\SystemRoot\\HyperGed.log", &needLogReinitialization);

    print("Logging Status: %llX ", status);

    status = SvVirtualizeProcessor();

    print("Virtualization Status: %llX", status);
    return;
}

BOOLEAN SvIsSvmSupported()
{
	BOOLEAN svmSupported;
	int registers[4];   // EAX, EBX, ECX, and EDX
	ULONG64 vmcr;
	svmSupported = FALSE;
	__cpuid(registers, CPUID_MAX_STANDARD_FN_NUMBER_AND_VENDOR_STRING);
	if ((registers[1] != 'htuA') ||
		(registers[3] != 'itne') ||
		(registers[2] != 'DMAc'))
	{
		goto Exit;
	}

	__cpuid(registers, CPUID_PROCESSOR_AND_PROCESSOR_FEATURE_IDENTIFIERS_EX);
	if ((registers[2] & CPUID_FN8000_0001_ECX_SVM) == 0)
	{
		goto Exit;
	}

	__cpuid(registers, CPUID_SVM_FEATURES);
	if ((registers[3] & CPUID_FN8000_000A_EDX_NP) == 0)
	{
		goto Exit;
	}

	vmcr = __readmsr(SVM_MSR_VM_CR);
	if ((vmcr & SVM_VM_CR_SVMDIS) != 0)
	{
		goto Exit;
	}

	svmSupported = TRUE;

Exit:
	return svmSupported;
}

NTSTATUS SvVirtualizeProcessor() {
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PSHARED_VIRTUAL_PROCESSOR_DATA sharedVpData = nullptr;
	ULONG numOfProcessorsCompleted = 0;

	if (SvIsSvmSupported() == FALSE)
	{
		print("SVM is not fully supported on this processor.\n");
		status = STATUS_HV_FEATURE_UNAVAILABLE;
		goto Exit;
	}

#pragma prefast(push)
#pragma prefast(disable : __WARNING_MEMORY_LEAK, "Ownership is taken on success.")
		sharedVpData = static_cast<PSHARED_VIRTUAL_PROCESSOR_DATA>(
		util::SvAllocatePageAlingedPhysicalMemory(sizeof(SHARED_VIRTUAL_PROCESSOR_DATA)));
#pragma prefast(pop)
	if (sharedVpData == nullptr)
	{
		print("Insufficient memory.\n");
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto Exit;
	}

	sharedVpData->MsrPermissionsMap = util::SvAllocateContiguousMemory(SVM_MSR_PERMISSIONS_MAP_SIZE);
	if (sharedVpData->MsrPermissionsMap == nullptr)
	{
		print("Insufficient memory.\n");
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto Exit;
	}

	util::SvBuildNestedPageTables(sharedVpData);
	util::SvBuildMsrPermissionsMap(sharedVpData->MsrPermissionsMap);

	status = util::SvExecuteOnEachProcessor(util::SvVirtualizeProcessor, sharedVpData, &numOfProcessorsCompleted);


Exit:
	if (!NT_SUCCESS(status))
	{
		if (numOfProcessorsCompleted != 0)
		{
			NT_ASSERT(sharedVpData != nullptr);
			SvDevirtualizeAllProcessors();
		}
		else
		{
			if (sharedVpData != nullptr)
			{
				if (sharedVpData->MsrPermissionsMap != nullptr)
				{
					util::SvFreeContiguousMemory(sharedVpData->MsrPermissionsMap);
				}
				util::SvFreePageAlingedPhysicalMemory(sharedVpData);
			}
		}
	}
	return status;
}

VOID SvDevirtualizeAllProcessors(VOID)
{
	PSHARED_VIRTUAL_PROCESSOR_DATA sharedVpData;

	sharedVpData = nullptr;

	NT_VERIFY(NT_SUCCESS(util::SvExecuteOnEachProcessor(util::SvDevirtualizeProcessor, &sharedVpData, nullptr)));

	if (sharedVpData != nullptr)
	{
		util::SvFreeContiguousMemory(sharedVpData->MsrPermissionsMap);
		util::SvFreePageAlingedPhysicalMemory(sharedVpData);
	}
}

BOOLEAN NTAPI SvHandleVmExit(_Inout_ PVIRTUAL_PROCESSOR_DATA VpData, _Inout_ PGUEST_REGISTERS GuestRegisters)
{
    GUEST_CONTEXT guestContext;
    KIRQL oldIrql;

    guestContext.VpRegs = GuestRegisters;
    guestContext.ExitVm = FALSE;


    __svm_vmload(VpData->HostStackLayout.HostVmcbPa);

    NT_ASSERT(VpData->HostStackLayout.Reserved1 == MAXUINT64);


    oldIrql = KeGetCurrentIrql();
    if (oldIrql < DISPATCH_LEVEL)
    {
        KeRaiseIrqlToDpcLevel();
    }


    GuestRegisters->Rax = VpData->GuestVmcb.StateSaveArea.Rax;


    VpData->HostStackLayout.TrapFrame.Rsp = VpData->GuestVmcb.StateSaveArea.Rsp;
    VpData->HostStackLayout.TrapFrame.Rip = VpData->GuestVmcb.ControlArea.NRip;


    switch (VpData->GuestVmcb.ControlArea.ExitCode)
    {
    case VMEXIT_CPUID:
        SvHandleCpuid(VpData, &guestContext);
        break;
    case VMEXIT_MSR:
        SvHandleMsrAccess(VpData, &guestContext);
        break;
    case VMEXIT_VMRUN:
        SvHandleVmrun(VpData, &guestContext);
        break;

    default:
        SV_DEBUG_BREAK();
#pragma prefast(disable : __WARNING_USE_OTHER_FUNCTION, "Unrecoverble path.")
        KeBugCheck(MANUALLY_INITIATED_CRASH);
    }

 
    if (oldIrql < DISPATCH_LEVEL)
    {
        KeLowerIrql(oldIrql);
    }

   
    if (guestContext.ExitVm != FALSE)
    {
        NT_ASSERT(VpData->GuestVmcb.ControlArea.ExitCode == VMEXIT_CPUID);

     
        guestContext.VpRegs->Rax = reinterpret_cast<UINT64>(VpData) & MAXUINT32;
        guestContext.VpRegs->Rbx = VpData->GuestVmcb.ControlArea.NRip;
        guestContext.VpRegs->Rcx = VpData->GuestVmcb.StateSaveArea.Rsp;
        guestContext.VpRegs->Rdx = reinterpret_cast<UINT64>(VpData) >> 32;

    
        __svm_vmload(MmGetPhysicalAddress(&VpData->GuestVmcb).QuadPart);

        _disable();
        __svm_stgi();

        __writemsr(IA32_MSR_EFER, __readmsr(IA32_MSR_EFER) & ~EFER_SVME);
        __writeeflags(VpData->GuestVmcb.StateSaveArea.Rflags);
        goto Exit;
    }

    VpData->GuestVmcb.StateSaveArea.Rax = guestContext.VpRegs->Rax;

Exit:
    NT_ASSERT(VpData->HostStackLayout.Reserved1 == MAXUINT64);
    return guestContext.ExitVm;
}

VOID SvHandleCpuid(_Inout_ PVIRTUAL_PROCESSOR_DATA VpData, _Inout_ PGUEST_CONTEXT GuestContext)
{
    int registers[4];   // EAX, EBX, ECX, and EDX
    int leaf, subLeaf;
    SEGMENT_ATTRIBUTE attribute;

    leaf = static_cast<int>(GuestContext->VpRegs->Rax);
    subLeaf = static_cast<int>(GuestContext->VpRegs->Rcx);
    __cpuidex(registers, leaf, subLeaf);

    switch (leaf)
    {
    case CPUID_PROCESSOR_AND_PROCESSOR_FEATURE_IDENTIFIERS:

        registers[2] |= CPUID_FN0000_0001_ECX_HYPERVISOR_PRESENT;
        break;
    case CPUID_HV_VENDOR_AND_MAX_FUNCTIONS:
 
        registers[0] = CPUID_HV_MAX;
        registers[1] = 'pmiS';  // "SimpleSvm   "
        registers[2] = 'vSel';
        registers[3] = '   m';
        break;
    case CPUID_HV_INTERFACE:

        registers[0] = '0#vH';  // Hv#0
        registers[1] = registers[2] = registers[3] = 0;
        break;
    case CPUID_UNLOAD_HYPER_GED:
        if (subLeaf == CPUID_UNLOAD_HYPER_GED)
        {
     
            attribute.AsUInt16 = VpData->GuestVmcb.StateSaveArea.SsAttrib;
            if (attribute.Fields.Dpl == DPL_SYSTEM)
            {
                GuestContext->ExitVm = TRUE;
            }
        }
        break;
    default:
        break;
    }


    GuestContext->VpRegs->Rax = registers[0];
    GuestContext->VpRegs->Rbx = registers[1];
    GuestContext->VpRegs->Rcx = registers[2];
    GuestContext->VpRegs->Rdx = registers[3];


    if (KeGetCurrentIrql() <= DISPATCH_LEVEL)
    {
        print("CPUID: %08x-%08x : %08x %08x %08x %08x\n",
            leaf,
            subLeaf,
            registers[0],
            registers[1],
            registers[2],
            registers[3]);
    }

    VpData->GuestVmcb.StateSaveArea.Rip = VpData->GuestVmcb.ControlArea.NRip;
}

VOID
SvHandleMsrAccess(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext
)
{
    ULARGE_INTEGER value;
    UINT32 msr;
    BOOLEAN writeAccess;

    msr = GuestContext->VpRegs->Rcx & MAXUINT32;
    writeAccess = (VpData->GuestVmcb.ControlArea.ExitInfo1 != 0);

    if (msr == IA32_MSR_EFER)
    {

        NT_ASSERT(writeAccess != FALSE);

        value.LowPart = GuestContext->VpRegs->Rax & MAXUINT32;
        value.HighPart = GuestContext->VpRegs->Rdx & MAXUINT32;
        if ((value.QuadPart & EFER_SVME) == 0)
        {
            SvInjectGeneralProtectionException(VpData);
        }

        VpData->GuestVmcb.StateSaveArea.Efer = value.QuadPart;
    }
    else
    {
        NT_ASSERT(((msr > 0x00001fff) && (msr < 0xc0000000)) ||
            ((msr > 0xc0001fff) && (msr < 0xc0010000)) ||
            (msr > 0xc0011fff));

        if (writeAccess != FALSE)
        {
            value.LowPart = GuestContext->VpRegs->Rax & MAXUINT32;
            value.HighPart = GuestContext->VpRegs->Rdx & MAXUINT32;
            __writemsr(msr, value.QuadPart);
        }
        else
        {
            value.QuadPart = __readmsr(msr);
            GuestContext->VpRegs->Rax = value.LowPart;
            GuestContext->VpRegs->Rdx = value.HighPart;
        }
    }
    VpData->GuestVmcb.StateSaveArea.Rip = VpData->GuestVmcb.ControlArea.NRip;
}

VOID
SvHandleVmrun(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext
)
{
    UNREFERENCED_PARAMETER(GuestContext);

    SvInjectGeneralProtectionException(VpData);
}

VOID
SvInjectGeneralProtectionException(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData
)
{
    EVENTINJ event;

    //
    // Inject #GP(vector = 13, type = 3 = exception) with a valid error code.
    // An error code are always zero. See "#GP-General-Protection Exception
    // (Vector 13)" for details about the error code.
    //
    event.AsUInt64 = 0;
    event.Fields.Vector = 13;
    event.Fields.Type = 3;
    event.Fields.ErrorCodeValid = 1;
    event.Fields.Valid = 1;
    VpData->GuestVmcb.ControlArea.EventInj = event.AsUInt64;
}

