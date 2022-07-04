#include "Utils.hpp"

VOID Callbacktest(PVOID args) {
	UNREFERENCED_PARAMETER(args);
	print("called callback");
}

NTSTATUS PowerCallbackRegistration() {
	PCALLBACK_OBJECT cbObject;
	UNICODE_STRING cbObjectName = RTL_CONSTANT_STRING(L"\\Callback\\PowerState");
	OBJECT_ATTRIBUTES cbObjectAtt = RTL_CONSTANT_OBJECT_ATTRIBUTES(&cbObjectName, OBJ_CASE_INSENSITIVE);
	PVOID callbackReg;
	NTSTATUS status;

	callbackReg = nullptr;

	status = ExCreateCallback(&cbObject, &cbObjectAtt, FALSE, TRUE);
	if (!NT_SUCCESS(status)) {
		print("Failed to open power callback!");
		goto Exit;
	}

	callbackReg = ExRegisterCallback(cbObject, (PCALLBACK_FUNCTION)Callbacktest, nullptr);
	ObDereferenceObject(cbObject);
	if (callbackReg == nullptr) {
		print("Failed to create power callback!");
		status = STATUS_UNSUCCESSFUL;
		goto Exit;
	}
Exit:
	if (NT_SUCCESS(status)) {
		NT_ASSERT(callbackReg);
		//g_PowerCallBackReg = callbackReg;
		return STATUS_SUCCESS;
	}
	else {
		if (callbackReg != nullptr) {
			ExUnregisterCallback(callbackReg);
			return STATUS_UNSUCCESSFUL;
		}
	}
	return STATUS_UNSUCCESSFUL;
}

PVOID util::SvAllocatePageAlingedPhysicalMemory(_In_ SIZE_T NumberOfBytes)
{
	PVOID memory;

	NT_ASSERT(NumberOfBytes >= PAGE_SIZE);
#pragma prefast(disable : 28118 __WARNING_ERROR, "FP due to POOL_NX_OPTIN.")
	memory = ExAllocatePoolWithTag(NonPagedPool, NumberOfBytes, 'MVSS');
	if (memory != nullptr)
	{
		NT_ASSERT(PAGE_ALIGN(memory) == memory);
		RtlZeroMemory(memory, NumberOfBytes);
	}
	return memory;
}

VOID util::SvFreePageAlingedPhysicalMemory(_Pre_notnull_ __drv_freesMem(Mem) PVOID BaseAddress) {
	ExFreePoolWithTag(BaseAddress, 'MVSS');
}

PVOID util::SvAllocateContiguousMemory(_In_ SIZE_T NumberOfBytes) {
	PVOID memory;
	PHYSICAL_ADDRESS boundary, lowest, highest;

	boundary.QuadPart = lowest.QuadPart = 0;
	highest.QuadPart = -1;

#pragma prefast(disable : 30030, "No alternative API on Windows 7.")
	memory = MmAllocateContiguousMemorySpecifyCacheNode(NumberOfBytes,
		lowest,
		highest,
		boundary,
		MmCached,
		MM_ANY_NODE_OK);
	if (memory != nullptr)
	{
		RtlZeroMemory(memory, NumberOfBytes);
	}
	return memory;
}

VOID util::SvFreeContiguousMemory(_In_ PVOID BaseAddress)
{
	MmFreeContiguousMemory(BaseAddress);
}

NTSTATUS util::SvExecuteOnEachProcessor(_In_ NTSTATUS(*Callback)(PVOID),_In_opt_ PVOID Context, _Out_opt_ PULONG NumOfProcessorCompleted)
{
    NTSTATUS status;
    ULONG i, numOfProcessors;
    PROCESSOR_NUMBER processorNumber;
    GROUP_AFFINITY affinity, oldAffinity;

    status = STATUS_SUCCESS;
    numOfProcessors = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

    for (i = 0; i < numOfProcessors; i++)
    {
      
        status = KeGetProcessorNumberFromIndex(i, &processorNumber);
        if (!NT_SUCCESS(status))
        {
            goto Exit;
        }

    
        affinity.Group = processorNumber.Group;
        affinity.Mask = 1ULL << processorNumber.Number;
        affinity.Reserved[0] = affinity.Reserved[1] = affinity.Reserved[2] = 0;
        KeSetSystemGroupAffinityThread(&affinity, &oldAffinity);

      
        status = Callback(Context);

      
        KeRevertToUserGroupAffinityThread(&oldAffinity);

        if (!NT_SUCCESS(status))
        {
            goto Exit;
        }
    }

Exit:

    NT_ASSERT(!NT_SUCCESS(status) || (i == numOfProcessors));
    if (ARGUMENT_PRESENT(NumOfProcessorCompleted))
    {
        *NumOfProcessorCompleted = i;
    }
    return status;
}

NTSTATUS util::SvDevirtualizeProcessor(_In_opt_ PVOID Context)
{
    int registers[4];   // EAX, EBX, ECX, and EDX
    UINT64 high, low;
    PVIRTUAL_PROCESSOR_DATA vpData;
    PSHARED_VIRTUAL_PROCESSOR_DATA* sharedVpDataPtr;

    if (!ARGUMENT_PRESENT(Context))
    {
        goto Exit;
    }

    __cpuidex(registers, CPUID_UNLOAD_HYPER_GED, CPUID_UNLOAD_HYPER_GED);
    if (registers[2] != 'SSVM')
    {
        goto Exit;
    }

    print("The processor has been de-virtualized.\n");

   
    high = registers[3];
    low = registers[0] & MAXUINT32;
    vpData = reinterpret_cast<PVIRTUAL_PROCESSOR_DATA>(high << 32 | low);
    NT_ASSERT(vpData->HostStackLayout.Reserved1 == MAXUINT64);

    sharedVpDataPtr = static_cast<PSHARED_VIRTUAL_PROCESSOR_DATA*>(Context);
    *sharedVpDataPtr = vpData->HostStackLayout.SharedVpData;
    util::SvFreePageAlingedPhysicalMemory(vpData);

Exit:
    return STATUS_SUCCESS;
}

NTSTATUS
util::SvVirtualizeProcessor(
    _In_opt_ PVOID Context
)
{
    NTSTATUS status;
    PSHARED_VIRTUAL_PROCESSOR_DATA sharedVpData;
    PVIRTUAL_PROCESSOR_DATA vpData;
    PCONTEXT contextRecord;

    SV_DEBUG_BREAK();

    vpData = nullptr;

    NT_ASSERT(ARGUMENT_PRESENT(Context));
    _Analysis_assume_(ARGUMENT_PRESENT(Context));

    contextRecord = static_cast<PCONTEXT>(ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(*contextRecord),
        'MVSS'));
    if (contextRecord == nullptr)
    {
        print("Insufficient memory.\n");
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    //
    // Allocate per processor data.
    //
#pragma prefast(push)
#pragma prefast(disable : __WARNING_MEMORY_LEAK, "Ownership is taken on success.")
    vpData = static_cast<PVIRTUAL_PROCESSOR_DATA>(util::SvAllocatePageAlingedPhysicalMemory(sizeof(VIRTUAL_PROCESSOR_DATA)));
#pragma prefast(pop)
    if (vpData == nullptr)
    {
        print("Insufficient memory.\n");
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    //
    // Capture the current RIP, RSP, RFLAGS, and segment selectors. This
    // captured state is used as an initial state of the guest mode; therefore
    // when virtualization starts by the later call of SvLaunchVm, a processor
    // resume its execution at this location and state.
    //
    RtlCaptureContext(contextRecord);

    //
    // First time of this execution, the SimpleSvm hypervisor is not installed
    // yet. Therefore, the branch is taken, and virtualization is attempted.
    //
    // At the second execution of here, after SvLaunchVm virtualized the
    // processor, SvIsSimpleSvmHypervisorInstalled returns TRUE, and this
    // function exits with STATUS_SUCCESS.
    //
    if (util::SvIsSimpleSvmHypervisorInstalled() == FALSE)
    {
        print("Attempting to virtualize the processor.\n");
        sharedVpData = static_cast<PSHARED_VIRTUAL_PROCESSOR_DATA>(Context);

        //
        // Enable SVM by setting EFER.SVME. It has already been verified that this
        // bit was writable with SvIsSvmSupported.
        //
        __writemsr(IA32_MSR_EFER, __readmsr(IA32_MSR_EFER) | EFER_SVME);

        //
        // Set up VMCB, the structure describes the guest state and what events
        // within the guest should be intercepted, ie, triggers #VMEXIT.
        //
        util::SvPrepareForVirtualization(vpData, sharedVpData, contextRecord);

        //
        // Switch to the host RSP to run as the host (hypervisor), and then
        // enters loop that executes code as a guest until #VMEXIT happens and
        // handles #VMEXIT as the host.
        //
        // This function should never return to here.
        //
        SvLaunchVm(&vpData->HostStackLayout.GuestVmcbPa);
        SV_DEBUG_BREAK();
        KeBugCheck(MANUALLY_INITIATED_CRASH);
    }

    print("The processor has been virtualized.\n");
    status = STATUS_SUCCESS;

Exit:
    if (contextRecord != nullptr)
    {
        ExFreePoolWithTag(contextRecord, 'MVSS');
    }
    if ((!NT_SUCCESS(status)) && (vpData != nullptr))
    {
 
        util::SvFreePageAlingedPhysicalMemory(vpData);
    }
    return status;
}

BOOLEAN
util::SvIsSimpleSvmHypervisorInstalled(
    VOID
)
{
    int registers[4];   // EAX, EBX, ECX, and EDX
    char vendorId[13];

    //
    // When the SimpleSvm hypervisor is installed, CPUID leaf 40000000h will
    // return "SimpleSvm   " as the vendor name.
    //
    __cpuid(registers, CPUID_HV_VENDOR_AND_MAX_FUNCTIONS);
    RtlCopyMemory(vendorId + 0, &registers[1], sizeof(registers[1]));
    RtlCopyMemory(vendorId + 4, &registers[2], sizeof(registers[2]));
    RtlCopyMemory(vendorId + 8, &registers[3], sizeof(registers[3]));
    vendorId[12] = ANSI_NULL;

    return (strcmp(vendorId, "SimpleSvm   ") == 0);
}


VOID
util::SvPrepareForVirtualization(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _In_ PSHARED_VIRTUAL_PROCESSOR_DATA SharedVpData,
    _In_ const CONTEXT* ContextRecord
)
{
    DESCRIPTOR_TABLE_REGISTER gdtr, idtr;
    PHYSICAL_ADDRESS guestVmcbPa, hostVmcbPa, hostStateAreaPa, pml4BasePa, msrpmPa;

    _sgdt(&gdtr);
    __sidt(&idtr);

    guestVmcbPa = MmGetPhysicalAddress(&VpData->GuestVmcb);
    hostVmcbPa = MmGetPhysicalAddress(&VpData->HostVmcb);
    hostStateAreaPa = MmGetPhysicalAddress(&VpData->HostStateArea);
    pml4BasePa = MmGetPhysicalAddress(&SharedVpData->Pml4Entries);
    msrpmPa = MmGetPhysicalAddress(SharedVpData->MsrPermissionsMap);

  
    VpData->GuestVmcb.ControlArea.InterceptMisc1 |= SVM_INTERCEPT_MISC1_CPUID;
    VpData->GuestVmcb.ControlArea.InterceptMisc2 |= SVM_INTERCEPT_MISC2_VMRUN;

    VpData->GuestVmcb.ControlArea.InterceptMisc1 |= SVM_INTERCEPT_MISC1_MSR_PROT;
    VpData->GuestVmcb.ControlArea.MsrpmBasePa = msrpmPa.QuadPart;

 
    VpData->GuestVmcb.ControlArea.GuestAsid = 1;

    VpData->GuestVmcb.ControlArea.NpEnable |= SVM_NP_ENABLE_NP_ENABLE;
    VpData->GuestVmcb.ControlArea.NCr3 = pml4BasePa.QuadPart;

    VpData->GuestVmcb.StateSaveArea.GdtrBase = gdtr.Base;
    VpData->GuestVmcb.StateSaveArea.GdtrLimit = gdtr.Limit;
    VpData->GuestVmcb.StateSaveArea.IdtrBase = idtr.Base;
    VpData->GuestVmcb.StateSaveArea.IdtrLimit = idtr.Limit;

    VpData->GuestVmcb.StateSaveArea.CsLimit = GetSegmentLimit(ContextRecord->SegCs);
    VpData->GuestVmcb.StateSaveArea.DsLimit = GetSegmentLimit(ContextRecord->SegDs);
    VpData->GuestVmcb.StateSaveArea.EsLimit = GetSegmentLimit(ContextRecord->SegEs);
    VpData->GuestVmcb.StateSaveArea.SsLimit = GetSegmentLimit(ContextRecord->SegSs);
    VpData->GuestVmcb.StateSaveArea.CsSelector = ContextRecord->SegCs;
    VpData->GuestVmcb.StateSaveArea.DsSelector = ContextRecord->SegDs;
    VpData->GuestVmcb.StateSaveArea.EsSelector = ContextRecord->SegEs;
    VpData->GuestVmcb.StateSaveArea.SsSelector = ContextRecord->SegSs;
    VpData->GuestVmcb.StateSaveArea.CsAttrib = SvGetSegmentAccessRight(ContextRecord->SegCs, gdtr.Base);
    VpData->GuestVmcb.StateSaveArea.DsAttrib = SvGetSegmentAccessRight(ContextRecord->SegDs, gdtr.Base);
    VpData->GuestVmcb.StateSaveArea.EsAttrib = SvGetSegmentAccessRight(ContextRecord->SegEs, gdtr.Base);
    VpData->GuestVmcb.StateSaveArea.SsAttrib = SvGetSegmentAccessRight(ContextRecord->SegSs, gdtr.Base);

    VpData->GuestVmcb.StateSaveArea.Efer = __readmsr(IA32_MSR_EFER);
    VpData->GuestVmcb.StateSaveArea.Cr0 = __readcr0();
    VpData->GuestVmcb.StateSaveArea.Cr2 = __readcr2();
    VpData->GuestVmcb.StateSaveArea.Cr3 = __readcr3();
    VpData->GuestVmcb.StateSaveArea.Cr4 = __readcr4();
    VpData->GuestVmcb.StateSaveArea.Rflags = ContextRecord->EFlags;
    VpData->GuestVmcb.StateSaveArea.Rsp = ContextRecord->Rsp;
    VpData->GuestVmcb.StateSaveArea.Rip = ContextRecord->Rip;
    VpData->GuestVmcb.StateSaveArea.GPat = __readmsr(IA32_MSR_PAT);

    __svm_vmsave(guestVmcbPa.QuadPart);

    VpData->HostStackLayout.Reserved1 = MAXUINT64;
    VpData->HostStackLayout.SharedVpData = SharedVpData;
    VpData->HostStackLayout.Self = VpData;
    VpData->HostStackLayout.HostVmcbPa = hostVmcbPa.QuadPart;
    VpData->HostStackLayout.GuestVmcbPa = guestVmcbPa.QuadPart;

    __writemsr(SVM_MSR_VM_HSAVE_PA, hostStateAreaPa.QuadPart);

    __svm_vmsave(hostVmcbPa.QuadPart);
}

UINT16
util::SvGetSegmentAccessRight(
    _In_ UINT16 SegmentSelector,
    _In_ ULONG_PTR GdtBase
)
{
    PSEGMENT_DESCRIPTOR descriptor;
    SEGMENT_ATTRIBUTE attribute;

    //
    // Get a segment descriptor corresponds to the specified segment selector.
    //
    descriptor = reinterpret_cast<PSEGMENT_DESCRIPTOR>(
        GdtBase + (SegmentSelector & ~RPL_MASK));

    //
    // Extract all attribute fields in the segment descriptor to a structure
    // that describes only attributes (as opposed to the segment descriptor
    // consists of multiple other fields).
    //
    attribute.Fields.Type = descriptor->Fields.Type;
    attribute.Fields.System = descriptor->Fields.System;
    attribute.Fields.Dpl = descriptor->Fields.Dpl;
    attribute.Fields.Present = descriptor->Fields.Present;
    attribute.Fields.Avl = descriptor->Fields.Avl;
    attribute.Fields.LongMode = descriptor->Fields.LongMode;
    attribute.Fields.DefaultBit = descriptor->Fields.DefaultBit;
    attribute.Fields.Granularity = descriptor->Fields.Granularity;
    attribute.Fields.Reserved1 = 0;

    return attribute.AsUInt16;
}

VOID
util::SvBuildNestedPageTables(
    _Out_ PSHARED_VIRTUAL_PROCESSOR_DATA SharedVpData
)
{
    ULONG64 pdpBasePa, pdeBasePa, translationPa;

    //
    // Build only one PML4 entry. This entry has subtables that control up to
    // 512GB physical memory. PFN points to a base physical address of the page
    // directory pointer table.
    //
    pdpBasePa = MmGetPhysicalAddress(&SharedVpData->PdpEntries).QuadPart;
    SharedVpData->Pml4Entries[0].Fields.PageFrameNumber = pdpBasePa >> PAGE_SHIFT;

    //
    // The US (User) bit of all nested page table entries to be translated
    // without #VMEXIT, as all guest accesses are treated as user accesses at
    // the nested level. Also, the RW (Write) bit of nested page table entries
    // that corresponds to guest page tables must be 1 since all guest page
    // table accesses are threated as write access. See "Nested versus Guest
    // Page Faults, Fault Ordering" for more details.
    //
    // Nested page tables built here set 1 to those bits for all entries, so
    // that all translation can complete without triggering #VMEXIT. This does
    // not lower security since security checks are done twice independently:
    // based on guest page tables, and nested page tables. See "Nested versus
    // Guest Page Faults, Fault Ordering" for more details.
    //
    SharedVpData->Pml4Entries[0].Fields.Valid = 1;
    SharedVpData->Pml4Entries[0].Fields.Write = 1;
    SharedVpData->Pml4Entries[0].Fields.User = 1;

    //
    // One PML4 entry controls 512 page directory pointer entires.
    //
    for (ULONG64 i = 0; i < 512; i++)
    {
        //
        // PFN points to a base physical address of the page directory table.
        //
        pdeBasePa = MmGetPhysicalAddress(&SharedVpData->PdeEntries[i][0]).QuadPart;
        SharedVpData->PdpEntries[i].Fields.PageFrameNumber = pdeBasePa >> PAGE_SHIFT;
        SharedVpData->PdpEntries[i].Fields.Valid = 1;
        SharedVpData->PdpEntries[i].Fields.Write = 1;
        SharedVpData->PdpEntries[i].Fields.User = 1;

        //
        // One page directory entry controls 512 page directory entries.
        //
        // We do not explicitly configure PAT in the NPT entry. The consequences
        // of this are: 1) pages whose PAT (Page Attribute Table) type is the
        // Write-Combining (WC) memory type could be treated as the
        // Write-Combining Plus (WC+) while it should be WC when the MTRR type is
        // either Write Protect (WP), Writethrough (WT) or Writeback (WB), and
        // 2) pages whose PAT type is Uncacheable Minus (UC-) could be treated
        // as Cache Disabled (CD) while it should be WC, when MTRR type is WC.
        //
        // While those are not desirable, this is acceptable given that 1) only
        // introduces additional cache snooping and associated performance
        // penalty, which would not be significant since WC+ still lets
        // processors combine multiple writes into one and avoid large
        // performance penalty due to frequent writes to memory without caching.
        // 2) might be worse but I have not seen MTRR ranges configured as WC
        // on testing, hence the unintentional UC- will just results in the same
        // effective memory type as what would be with UC.
        //
        // See "Memory Types" (7.4), for details of memory types,
        // "PAT-Register PA-Field Indexing", "Combining Guest and Host PAT Types",
        // and "Combining PAT and MTRR Types" for how the effective memory type
        // is determined based on Guest PAT type, Host PAT type, and the MTRR
        // type.
        //
        // The correct approach may be to look up the guest PTE and copy the
        // caching related bits (PAT, PCD, and PWT) when constructing NTP
        // entries for non RAM regions, so the combined PAT will always be the
        // same as the guest PAT type. This may be done when any issue manifests
        // with the current implementation.
        //
        for (ULONG64 j = 0; j < 512; j++)
        {
            //
            // PFN points to a base physical address of system physical address
            // to be translated from a guest physical address. Set the PS
            // (LargePage) bit to indicate that this is a large page and no
            // subtable exists.
            //
            translationPa = (i * 512) + j;
            SharedVpData->PdeEntries[i][j].Fields.PageFrameNumber = translationPa;
            SharedVpData->PdeEntries[i][j].Fields.Valid = 1;
            SharedVpData->PdeEntries[i][j].Fields.Write = 1;
            SharedVpData->PdeEntries[i][j].Fields.User = 1;
            SharedVpData->PdeEntries[i][j].Fields.LargePage = 1;
        }
    }
}


VOID
util::SvBuildMsrPermissionsMap(
    _Inout_ PVOID MsrPermissionsMap
)
{
    static const UINT32 BITS_PER_MSR = 2;
    static const UINT32 SECOND_MSR_RANGE_BASE = 0xc0000000;
    static const UINT32 SECOND_MSRPM_OFFSET = 0x800 * CHAR_BIT;
    RTL_BITMAP bitmapHeader;
    ULONG offsetFrom2ndBase, offset;

    //
    // Setup and clear all bits, indicating no MSR access should be intercepted.
    //
    RtlInitializeBitMap(&bitmapHeader,
        static_cast<PULONG>(MsrPermissionsMap),
        SVM_MSR_PERMISSIONS_MAP_SIZE * CHAR_BIT
    );
    RtlClearAllBits(&bitmapHeader);

    //
    // Compute an offset from the second MSR permissions map offset (0x800) for
    // IA32_MSR_EFER in bits. Then, add an offset until the second MSR
    // permissions map.
    //
    offsetFrom2ndBase = (IA32_MSR_EFER - SECOND_MSR_RANGE_BASE) * BITS_PER_MSR;
    offset = SECOND_MSRPM_OFFSET + offsetFrom2ndBase;

    //
    // Set the MSB bit indicating write accesses to the MSR should be intercepted.
    //
    RtlSetBits(&bitmapHeader, offset + 1, 1);
}