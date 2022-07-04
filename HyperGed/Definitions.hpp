//Definitions
#pragma once
#include <basetsd.h>

#define POOL_NX_OPTIN   1
//
// x86-64 defined constants.
//
#define IA32_MSR_PAT    0x00000277
#define IA32_MSR_EFER   0xc0000080

#define EFER_SVME       (1UL << 12)

#define RPL_MASK        3
#define DPL_SYSTEM      0

#define CPUID_FN8000_0001_ECX_SVM                   (1UL << 2)
#define CPUID_FN0000_0001_ECX_HYPERVISOR_PRESENT    (1UL << 31)
#define CPUID_FN8000_000A_EDX_NP                    (1UL << 0)

#define CPUID_MAX_STANDARD_FN_NUMBER_AND_VENDOR_STRING          0x00000000
#define CPUID_PROCESSOR_AND_PROCESSOR_FEATURE_IDENTIFIERS       0x00000001
#define CPUID_PROCESSOR_AND_PROCESSOR_FEATURE_IDENTIFIERS_EX    0x80000001
#define CPUID_SVM_FEATURES                                      0x8000000a
//
// The Microsoft Hypervisor interface defined constants.
//
#define CPUID_HV_VENDOR_AND_MAX_FUNCTIONS   0x40000000
#define CPUID_HV_INTERFACE                  0x40000001

//
// HyperGed specific constants.
//
#define CPUID_UNLOAD_HYPER_GED     0x41414141
#define CPUID_HV_MAX                CPUID_HV_INTERFACE

#define SV_DEBUG_BREAK() \
    if (KD_DEBUGGER_NOT_PRESENT) \
    { \
        NOTHING; \
    } \
    else \
    { \
        __debugbreak(); \
    } \
    reinterpret_cast<void*>(0)

//
// A size of two the MSR permissions map.
//
#define SVM_MSR_PERMISSIONS_MAP_SIZE    (PAGE_SIZE * 2)

//
// See "SVM Related MSRs"
//
#define SVM_MSR_VM_CR                   0xc0010114
#define SVM_MSR_VM_HSAVE_PA             0xc0010117

#define SVM_VM_CR_SVMDIS                (1UL << 4)

//
// See "VMCB Layout, Control Area"
//
#define SVM_INTERCEPT_MISC1_CPUID       (1UL << 18)
#define SVM_INTERCEPT_MISC1_MSR_PROT    (1UL << 28)
#define SVM_INTERCEPT_MISC2_VMRUN       (1UL << 0)
#define SVM_NP_ENABLE_NP_ENABLE         (1UL << 0)

typedef struct _VMCB_CONTROL_AREA
{
    UINT16 InterceptCrRead;             // +0x000
    UINT16 InterceptCrWrite;            // +0x002
    UINT16 InterceptDrRead;             // +0x004
    UINT16 InterceptDrWrite;            // +0x006
    UINT32 InterceptException;          // +0x008
    UINT32 InterceptMisc1;              // +0x00c
    UINT32 InterceptMisc2;              // +0x010
    UINT8 Reserved1[0x03c - 0x014];     // +0x014
    UINT16 PauseFilterThreshold;        // +0x03c
    UINT16 PauseFilterCount;            // +0x03e
    UINT64 IopmBasePa;                  // +0x040
    UINT64 MsrpmBasePa;                 // +0x048
    UINT64 TscOffset;                   // +0x050
    UINT32 GuestAsid;                   // +0x058
    UINT32 TlbControl;                  // +0x05c
    UINT64 VIntr;                       // +0x060
    UINT64 InterruptShadow;             // +0x068
    UINT64 ExitCode;                    // +0x070
    UINT64 ExitInfo1;                   // +0x078
    UINT64 ExitInfo2;                   // +0x080
    UINT64 ExitIntInfo;                 // +0x088
    UINT64 NpEnable;                    // +0x090
    UINT64 AvicApicBar;                 // +0x098
    UINT64 GuestPaOfGhcb;               // +0x0a0
    UINT64 EventInj;                    // +0x0a8
    UINT64 NCr3;                        // +0x0b0
    UINT64 LbrVirtualizationEnable;     // +0x0b8
    UINT64 VmcbClean;                   // +0x0c0
    UINT64 NRip;                        // +0x0c8
    UINT8 NumOfBytesFetched;            // +0x0d0
    UINT8 GuestInstructionBytes[15];    // +0x0d1
    UINT64 AvicApicBackingPagePointer;  // +0x0e0
    UINT64 Reserved2;                   // +0x0e8
    UINT64 AvicLogicalTablePointer;     // +0x0f0
    UINT64 AvicPhysicalTablePointer;    // +0x0f8
    UINT64 Reserved3;                   // +0x100
    UINT64 VmcbSaveStatePointer;        // +0x108
    UINT8 Reserved4[0x400 - 0x110];     // +0x110
} VMCB_CONTROL_AREA, * PVMCB_CONTROL_AREA;
static_assert(sizeof(VMCB_CONTROL_AREA) == 0x400,
    "VMCB_CONTROL_AREA Size Mismatch");

//
// See "VMCB Layout, State Save Area"
//
typedef struct _VMCB_STATE_SAVE_AREA
{
    UINT16 EsSelector;                  // +0x000
    UINT16 EsAttrib;                    // +0x002
    UINT32 EsLimit;                     // +0x004
    UINT64 EsBase;                      // +0x008
    UINT16 CsSelector;                  // +0x010
    UINT16 CsAttrib;                    // +0x012
    UINT32 CsLimit;                     // +0x014
    UINT64 CsBase;                      // +0x018
    UINT16 SsSelector;                  // +0x020
    UINT16 SsAttrib;                    // +0x022
    UINT32 SsLimit;                     // +0x024
    UINT64 SsBase;                      // +0x028
    UINT16 DsSelector;                  // +0x030
    UINT16 DsAttrib;                    // +0x032
    UINT32 DsLimit;                     // +0x034
    UINT64 DsBase;                      // +0x038
    UINT16 FsSelector;                  // +0x040
    UINT16 FsAttrib;                    // +0x042
    UINT32 FsLimit;                     // +0x044
    UINT64 FsBase;                      // +0x048
    UINT16 GsSelector;                  // +0x050
    UINT16 GsAttrib;                    // +0x052
    UINT32 GsLimit;                     // +0x054
    UINT64 GsBase;                      // +0x058
    UINT16 GdtrSelector;                // +0x060
    UINT16 GdtrAttrib;                  // +0x062
    UINT32 GdtrLimit;                   // +0x064
    UINT64 GdtrBase;                    // +0x068
    UINT16 LdtrSelector;                // +0x070
    UINT16 LdtrAttrib;                  // +0x072
    UINT32 LdtrLimit;                   // +0x074
    UINT64 LdtrBase;                    // +0x078
    UINT16 IdtrSelector;                // +0x080
    UINT16 IdtrAttrib;                  // +0x082
    UINT32 IdtrLimit;                   // +0x084
    UINT64 IdtrBase;                    // +0x088
    UINT16 TrSelector;                  // +0x090
    UINT16 TrAttrib;                    // +0x092
    UINT32 TrLimit;                     // +0x094
    UINT64 TrBase;                      // +0x098
    UINT8 Reserved1[0x0cb - 0x0a0];     // +0x0a0
    UINT8 Cpl;                          // +0x0cb
    UINT32 Reserved2;                   // +0x0cc
    UINT64 Efer;                        // +0x0d0
    UINT8 Reserved3[0x148 - 0x0d8];     // +0x0d8
    UINT64 Cr4;                         // +0x148
    UINT64 Cr3;                         // +0x150
    UINT64 Cr0;                         // +0x158
    UINT64 Dr7;                         // +0x160
    UINT64 Dr6;                         // +0x168
    UINT64 Rflags;                      // +0x170
    UINT64 Rip;                         // +0x178
    UINT8 Reserved4[0x1d8 - 0x180];     // +0x180
    UINT64 Rsp;                         // +0x1d8
    UINT8 Reserved5[0x1f8 - 0x1e0];     // +0x1e0
    UINT64 Rax;                         // +0x1f8
    UINT64 Star;                        // +0x200
    UINT64 LStar;                       // +0x208
    UINT64 CStar;                       // +0x210
    UINT64 SfMask;                      // +0x218
    UINT64 KernelGsBase;                // +0x220
    UINT64 SysenterCs;                  // +0x228
    UINT64 SysenterEsp;                 // +0x230
    UINT64 SysenterEip;                 // +0x238
    UINT64 Cr2;                         // +0x240
    UINT8 Reserved6[0x268 - 0x248];     // +0x248
    UINT64 GPat;                        // +0x268
    UINT64 DbgCtl;                      // +0x270
    UINT64 BrFrom;                      // +0x278
    UINT64 BrTo;                        // +0x280
    UINT64 LastExcepFrom;               // +0x288
    UINT64 LastExcepTo;                 // +0x290
} VMCB_STATE_SAVE_AREA, * PVMCB_STATE_SAVE_AREA;
static_assert(sizeof(VMCB_STATE_SAVE_AREA) == 0x298,
    "VMCB_STATE_SAVE_AREA Size Mismatch");

//
// An entire VMCB (Virtual machine control block) layout.
//
typedef struct _VMCB
{
    VMCB_CONTROL_AREA ControlArea;
    VMCB_STATE_SAVE_AREA StateSaveArea;
    UINT8 Reserved1[0x1000 - sizeof(VMCB_CONTROL_AREA) - sizeof(VMCB_STATE_SAVE_AREA)];
} VMCB, * PVMCB;
static_assert(sizeof(VMCB) == 0x1000,
    "VMCB Size Mismatch");

//
// See "Event Injection"
//
typedef struct _EVENTINJ
{
    union
    {
        UINT64 AsUInt64;
        struct
        {
            UINT64 Vector : 8;          // [0:7]
            UINT64 Type : 3;            // [8:10]
            UINT64 ErrorCodeValid : 1;  // [11]
            UINT64 Reserved1 : 19;      // [12:30]
            UINT64 Valid : 1;           // [31]
            UINT64 ErrorCode : 32;      // [32:63]
        } Fields;
    };
} EVENTINJ, * PEVENTINJ;
static_assert(sizeof(EVENTINJ) == 8,
    "EVENTINJ Size Mismatch");

//
// See "SVM Intercept Codes"
//
#define VMEXIT_CR0_READ             0x0000
#define VMEXIT_CR1_READ             0x0001
#define VMEXIT_CR2_READ             0x0002
#define VMEXIT_CR3_READ             0x0003
#define VMEXIT_CR4_READ             0x0004
#define VMEXIT_CR5_READ             0x0005
#define VMEXIT_CR6_READ             0x0006
#define VMEXIT_CR7_READ             0x0007
#define VMEXIT_CR8_READ             0x0008
#define VMEXIT_CR9_READ             0x0009
#define VMEXIT_CR10_READ            0x000a
#define VMEXIT_CR11_READ            0x000b
#define VMEXIT_CR12_READ            0x000c
#define VMEXIT_CR13_READ            0x000d
#define VMEXIT_CR14_READ            0x000e
#define VMEXIT_CR15_READ            0x000f
#define VMEXIT_CR0_WRITE            0x0010
#define VMEXIT_CR1_WRITE            0x0011
#define VMEXIT_CR2_WRITE            0x0012
#define VMEXIT_CR3_WRITE            0x0013
#define VMEXIT_CR4_WRITE            0x0014
#define VMEXIT_CR5_WRITE            0x0015
#define VMEXIT_CR6_WRITE            0x0016
#define VMEXIT_CR7_WRITE            0x0017
#define VMEXIT_CR8_WRITE            0x0018
#define VMEXIT_CR9_WRITE            0x0019
#define VMEXIT_CR10_WRITE           0x001a
#define VMEXIT_CR11_WRITE           0x001b
#define VMEXIT_CR12_WRITE           0x001c
#define VMEXIT_CR13_WRITE           0x001d
#define VMEXIT_CR14_WRITE           0x001e
#define VMEXIT_CR15_WRITE           0x001f
#define VMEXIT_DR0_READ             0x0020
#define VMEXIT_DR1_READ             0x0021
#define VMEXIT_DR2_READ             0x0022
#define VMEXIT_DR3_READ             0x0023
#define VMEXIT_DR4_READ             0x0024
#define VMEXIT_DR5_READ             0x0025
#define VMEXIT_DR6_READ             0x0026
#define VMEXIT_DR7_READ             0x0027
#define VMEXIT_DR8_READ             0x0028
#define VMEXIT_DR9_READ             0x0029
#define VMEXIT_DR10_READ            0x002a
#define VMEXIT_DR11_READ            0x002b
#define VMEXIT_DR12_READ            0x002c
#define VMEXIT_DR13_READ            0x002d
#define VMEXIT_DR14_READ            0x002e
#define VMEXIT_DR15_READ            0x002f
#define VMEXIT_DR0_WRITE            0x0030
#define VMEXIT_DR1_WRITE            0x0031
#define VMEXIT_DR2_WRITE            0x0032
#define VMEXIT_DR3_WRITE            0x0033
#define VMEXIT_DR4_WRITE            0x0034
#define VMEXIT_DR5_WRITE            0x0035
#define VMEXIT_DR6_WRITE            0x0036
#define VMEXIT_DR7_WRITE            0x0037
#define VMEXIT_DR8_WRITE            0x0038
#define VMEXIT_DR9_WRITE            0x0039
#define VMEXIT_DR10_WRITE           0x003a
#define VMEXIT_DR11_WRITE           0x003b
#define VMEXIT_DR12_WRITE           0x003c
#define VMEXIT_DR13_WRITE           0x003d
#define VMEXIT_DR14_WRITE           0x003e
#define VMEXIT_DR15_WRITE           0x003f
#define VMEXIT_EXCEPTION_DE         0x0040
#define VMEXIT_EXCEPTION_DB         0x0041
#define VMEXIT_EXCEPTION_NMI        0x0042
#define VMEXIT_EXCEPTION_BP         0x0043
#define VMEXIT_EXCEPTION_OF         0x0044
#define VMEXIT_EXCEPTION_BR         0x0045
#define VMEXIT_EXCEPTION_UD         0x0046
#define VMEXIT_EXCEPTION_NM         0x0047
#define VMEXIT_EXCEPTION_DF         0x0048
#define VMEXIT_EXCEPTION_09         0x0049
#define VMEXIT_EXCEPTION_TS         0x004a
#define VMEXIT_EXCEPTION_NP         0x004b
#define VMEXIT_EXCEPTION_SS         0x004c
#define VMEXIT_EXCEPTION_GP         0x004d
#define VMEXIT_EXCEPTION_PF         0x004e
#define VMEXIT_EXCEPTION_15         0x004f
#define VMEXIT_EXCEPTION_MF         0x0050
#define VMEXIT_EXCEPTION_AC         0x0051
#define VMEXIT_EXCEPTION_MC         0x0052
#define VMEXIT_EXCEPTION_XF         0x0053
#define VMEXIT_EXCEPTION_20         0x0054
#define VMEXIT_EXCEPTION_21         0x0055
#define VMEXIT_EXCEPTION_22         0x0056
#define VMEXIT_EXCEPTION_23         0x0057
#define VMEXIT_EXCEPTION_24         0x0058
#define VMEXIT_EXCEPTION_25         0x0059
#define VMEXIT_EXCEPTION_26         0x005a
#define VMEXIT_EXCEPTION_27         0x005b
#define VMEXIT_EXCEPTION_28         0x005c
#define VMEXIT_EXCEPTION_VC         0x005d
#define VMEXIT_EXCEPTION_SX         0x005e
#define VMEXIT_EXCEPTION_31         0x005f
#define VMEXIT_INTR                 0x0060
#define VMEXIT_NMI                  0x0061
#define VMEXIT_SMI                  0x0062
#define VMEXIT_INIT                 0x0063
#define VMEXIT_VINTR                0x0064
#define VMEXIT_CR0_SEL_WRITE        0x0065
#define VMEXIT_IDTR_READ            0x0066
#define VMEXIT_GDTR_READ            0x0067
#define VMEXIT_LDTR_READ            0x0068
#define VMEXIT_TR_READ              0x0069
#define VMEXIT_IDTR_WRITE           0x006a
#define VMEXIT_GDTR_WRITE           0x006b
#define VMEXIT_LDTR_WRITE           0x006c
#define VMEXIT_TR_WRITE             0x006d
#define VMEXIT_RDTSC                0x006e
#define VMEXIT_RDPMC                0x006f
#define VMEXIT_PUSHF                0x0070
#define VMEXIT_POPF                 0x0071
#define VMEXIT_CPUID                0x0072
#define VMEXIT_RSM                  0x0073
#define VMEXIT_IRET                 0x0074
#define VMEXIT_SWINT                0x0075
#define VMEXIT_INVD                 0x0076
#define VMEXIT_PAUSE                0x0077
#define VMEXIT_HLT                  0x0078
#define VMEXIT_INVLPG               0x0079
#define VMEXIT_INVLPGA              0x007a
#define VMEXIT_IOIO                 0x007b
#define VMEXIT_MSR                  0x007c
#define VMEXIT_TASK_SWITCH          0x007d
#define VMEXIT_FERR_FREEZE          0x007e
#define VMEXIT_SHUTDOWN             0x007f
#define VMEXIT_VMRUN                0x0080
#define VMEXIT_VMMCALL              0x0081
#define VMEXIT_VMLOAD               0x0082
#define VMEXIT_VMSAVE               0x0083
#define VMEXIT_STGI                 0x0084
#define VMEXIT_CLGI                 0x0085
#define VMEXIT_SKINIT               0x0086
#define VMEXIT_RDTSCP               0x0087
#define VMEXIT_ICEBP                0x0088
#define VMEXIT_WBINVD               0x0089
#define VMEXIT_MONITOR              0x008a
#define VMEXIT_MWAIT                0x008b
#define VMEXIT_MWAIT_CONDITIONAL    0x008c
#define VMEXIT_XSETBV               0x008d
#define VMEXIT_EFER_WRITE_TRAP      0x008f
#define VMEXIT_CR0_WRITE_TRAP       0x0090
#define VMEXIT_CR1_WRITE_TRAP       0x0091
#define VMEXIT_CR2_WRITE_TRAP       0x0092
#define VMEXIT_CR3_WRITE_TRAP       0x0093
#define VMEXIT_CR4_WRITE_TRAP       0x0094
#define VMEXIT_CR5_WRITE_TRAP       0x0095
#define VMEXIT_CR6_WRITE_TRAP       0x0096
#define VMEXIT_CR7_WRITE_TRAP       0x0097
#define VMEXIT_CR8_WRITE_TRAP       0x0098
#define VMEXIT_CR9_WRITE_TRAP       0x0099
#define VMEXIT_CR10_WRITE_TRAP      0x009a
#define VMEXIT_CR11_WRITE_TRAP      0x009b
#define VMEXIT_CR12_WRITE_TRAP      0x009c
#define VMEXIT_CR13_WRITE_TRAP      0x009d
#define VMEXIT_CR14_WRITE_TRAP      0x009e
#define VMEXIT_CR15_WRITE_TRAP      0x009f
#define VMEXIT_NPF                  0x0400
#define AVIC_INCOMPLETE_IPI         0x0401
#define AVIC_NOACCEL                0x0402
#define VMEXIT_VMGEXIT              0x0403
#define VMEXIT_INVALID              -1


EXTERN_C
VOID
_sgdt(
    _Out_ PVOID Descriptor
);

_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
DECLSPEC_NORETURN
EXTERN_C
VOID
NTAPI
SvLaunchVm(
    _In_ PVOID HostRsp
);

//
// x86-64 defined structures.
//

//
// See "2-Mbyte PML4E-Long Mode" and "2-Mbyte PDPE-Long Mode".
//
typedef struct _PML4_ENTRY_2MB
{
    union
    {
        UINT64 AsUInt64;
        struct
        {
            UINT64 Valid : 1;               // [0]
            UINT64 Write : 1;               // [1]
            UINT64 User : 1;                // [2]
            UINT64 WriteThrough : 1;        // [3]
            UINT64 CacheDisable : 1;        // [4]
            UINT64 Accessed : 1;            // [5]
            UINT64 Reserved1 : 3;           // [6:8]
            UINT64 Avl : 3;                 // [9:11]
            UINT64 PageFrameNumber : 40;    // [12:51]
            UINT64 Reserved2 : 11;          // [52:62]
            UINT64 NoExecute : 1;           // [63]
        } Fields;
    };
} PML4_ENTRY_2MB, * PPML4_ENTRY_2MB,
PDP_ENTRY_2MB, * PPDP_ENTRY_2MB;
static_assert(sizeof(PML4_ENTRY_2MB) == 8,
    "PML4_ENTRY_1GB Size Mismatch");

//
// See "2-Mbyte PDE-Long Mode".
//
typedef struct _PD_ENTRY_2MB
{
    union
    {
        UINT64 AsUInt64;
        struct
        {
            UINT64 Valid : 1;               // [0]
            UINT64 Write : 1;               // [1]
            UINT64 User : 1;                // [2]
            UINT64 WriteThrough : 1;        // [3]
            UINT64 CacheDisable : 1;        // [4]
            UINT64 Accessed : 1;            // [5]
            UINT64 Dirty : 1;               // [6]
            UINT64 LargePage : 1;           // [7]
            UINT64 Global : 1;              // [8]
            UINT64 Avl : 3;                 // [9:11]
            UINT64 Pat : 1;                 // [12]
            UINT64 Reserved1 : 8;           // [13:20]
            UINT64 PageFrameNumber : 31;    // [21:51]
            UINT64 Reserved2 : 11;          // [52:62]
            UINT64 NoExecute : 1;           // [63]
        } Fields;
    };
} PD_ENTRY_2MB, * PPD_ENTRY_2MB;
static_assert(sizeof(PD_ENTRY_2MB) == 8,
    "PDE_ENTRY_2MB Size Mismatch");

//
// See "GDTR and IDTR Format-Long Mode"
//
#include <pshpack1.h>
typedef struct _DESCRIPTOR_TABLE_REGISTER
{
    UINT16 Limit;
    ULONG_PTR Base;
} DESCRIPTOR_TABLE_REGISTER, * PDESCRIPTOR_TABLE_REGISTER;
static_assert(sizeof(DESCRIPTOR_TABLE_REGISTER) == 10,
    "DESCRIPTOR_TABLE_REGISTER Size Mismatch");
#include <poppack.h>

//
// See "Long-Mode Segment Descriptors" and some of definitions
// (eg, "Code-Segment Descriptor-Long Mode")
//
typedef struct _SEGMENT_DESCRIPTOR
{
    union
    {
        UINT64 AsUInt64;
        struct
        {
            UINT16 LimitLow;        // [0:15]
            UINT16 BaseLow;         // [16:31]
            UINT32 BaseMiddle : 8;  // [32:39]
            UINT32 Type : 4;        // [40:43]
            UINT32 System : 1;      // [44]
            UINT32 Dpl : 2;         // [45:46]
            UINT32 Present : 1;     // [47]
            UINT32 LimitHigh : 4;   // [48:51]
            UINT32 Avl : 1;         // [52]
            UINT32 LongMode : 1;    // [53]
            UINT32 DefaultBit : 1;  // [54]
            UINT32 Granularity : 1; // [55]
            UINT32 BaseHigh : 8;    // [56:63]
        } Fields;
    };
} SEGMENT_DESCRIPTOR, * PSEGMENT_DESCRIPTOR;
static_assert(sizeof(SEGMENT_DESCRIPTOR) == 8,
    "SEGMENT_DESCRIPTOR Size Mismatch");

typedef struct _SEGMENT_ATTRIBUTE
{
    union
    {
        UINT16 AsUInt16;
        struct
        {
            UINT16 Type : 4;        // [0:3]
            UINT16 System : 1;      // [4]
            UINT16 Dpl : 2;         // [5:6]
            UINT16 Present : 1;     // [7]
            UINT16 Avl : 1;         // [8]
            UINT16 LongMode : 1;    // [9]
            UINT16 DefaultBit : 1;  // [10]
            UINT16 Granularity : 1; // [11]
            UINT16 Reserved1 : 4;   // [12:15]
        } Fields;
    };
} SEGMENT_ATTRIBUTE, * PSEGMENT_ATTRIBUTE;
static_assert(sizeof(SEGMENT_ATTRIBUTE) == 2,
    "SEGMENT_ATTRIBUTE Size Mismatch");

//
// SimpleSVM specific structures.
//

typedef struct _SHARED_VIRTUAL_PROCESSOR_DATA
{
    PVOID MsrPermissionsMap;
    DECLSPEC_ALIGN(PAGE_SIZE) PML4_ENTRY_2MB Pml4Entries[1];    // Just for 512 GB
    DECLSPEC_ALIGN(PAGE_SIZE) PDP_ENTRY_2MB PdpEntries[512];
    DECLSPEC_ALIGN(PAGE_SIZE) PD_ENTRY_2MB PdeEntries[512][512];
} SHARED_VIRTUAL_PROCESSOR_DATA, * PSHARED_VIRTUAL_PROCESSOR_DATA;

typedef struct _VIRTUAL_PROCESSOR_DATA
{
    union
    {
        //
        //  Low     HostStackLimit[0]                        StackLimit
        //  ^       ...
        //  ^       HostStackLimit[KERNEL_STACK_SIZE - 2]    StackBase
        //  High    HostStackLimit[KERNEL_STACK_SIZE - 1]    StackBase
        //
        DECLSPEC_ALIGN(PAGE_SIZE) UINT8 HostStackLimit[KERNEL_STACK_SIZE];
        struct
        {
            UINT8 StackContents[KERNEL_STACK_SIZE - (sizeof(PVOID) * 6) - sizeof(KTRAP_FRAME)];
            KTRAP_FRAME TrapFrame;
            UINT64 GuestVmcbPa;     // HostRsp
            UINT64 HostVmcbPa;
            struct _VIRTUAL_PROCESSOR_DATA* Self;
            PSHARED_VIRTUAL_PROCESSOR_DATA SharedVpData;
            UINT64 Padding1;        // To keep HostRsp 16 bytes aligned
            UINT64 Reserved1;
        } HostStackLayout;
    };

    DECLSPEC_ALIGN(PAGE_SIZE) VMCB GuestVmcb;
    DECLSPEC_ALIGN(PAGE_SIZE) VMCB HostVmcb;
    DECLSPEC_ALIGN(PAGE_SIZE) UINT8 HostStateArea[PAGE_SIZE];
} VIRTUAL_PROCESSOR_DATA, * PVIRTUAL_PROCESSOR_DATA;
static_assert(sizeof(VIRTUAL_PROCESSOR_DATA) == KERNEL_STACK_SIZE + PAGE_SIZE * 3,
    "VIRTUAL_PROCESSOR_DATA Size Mismatch");

typedef struct _GUEST_REGISTERS
{
    UINT64 R15;
    UINT64 R14;
    UINT64 R13;
    UINT64 R12;
    UINT64 R11;
    UINT64 R10;
    UINT64 R9;
    UINT64 R8;
    UINT64 Rdi;
    UINT64 Rsi;
    UINT64 Rbp;
    UINT64 Rsp;
    UINT64 Rbx;
    UINT64 Rdx;
    UINT64 Rcx;
    UINT64 Rax;
} GUEST_REGISTERS, * PGUEST_REGISTERS;

typedef struct _GUEST_CONTEXT
{
    PGUEST_REGISTERS VpRegs;
    BOOLEAN ExitVm;
} GUEST_CONTEXT, * PGUEST_CONTEXT;

typedef struct _LOG_BUFFER_INFO
{
    //
    // A pointer to buffer currently used. It is either LogBuffer1 or LogBuffer2.
    //
    volatile PSTR LogBufferHead;

    //
    // A pointer to where the next log should be written.
    //
    volatile PSTR LogBufferTail;

    PSTR LogBuffer1;
    PSTR LogBuffer2;

    //
    // Holds the biggest buffer usage to determine a necessary buffer size.
    //
    SIZE_T LogMaxUsage;

    HANDLE LogFileHandle;
    KSPIN_LOCK SpinLock;
    ERESOURCE Resource;
    BOOLEAN ResourceInitialized;
    volatile BOOLEAN BufferFlushThreadShouldBeAlive;
    volatile BOOLEAN BufferFlushThreadStarted;
    HANDLE BufferFlushThreadHandle;
    WCHAR LogFilePath[200];
} LOG_BUFFER_INFO, * PLOG_BUFFER_INFO;



