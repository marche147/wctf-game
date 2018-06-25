#pragma once

#define STRSAFE_NO_CCH_FUNCTIONS	// I don't like them
#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <iostream>
#include <vector>
#include <algorithm>
#include <numeric>
#include <memory>
#include <string>
#include <thread>
#include <strsafe.h>
#include <Shlwapi.h>
#include <stdint.h>
#include <intrin.h>
#include <bcrypt.h>
#include <ntsecapi.h>
#include <winioctl.h>
#pragma comment(lib, "Secur32.lib")
//#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Bcrypt.lib")

#ifdef _WIN64
typedef uint64_t uintptr_t;
#else
typedef uint32_t uintptr_t;
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif
#define PAGE_ALIGN(x) (((x) + PAGE_SIZE - 1) & (~(PAGE_SIZE - 1)))

static_assert(sizeof(int32_t) == 4, "Wrong size for int32_t");
static_assert(sizeof(uint32_t) == 4, "Wrong size for uint32_t");
static_assert(sizeof(int64_t) == 8, "Wrong size for int64_t");
static_assert(sizeof(uint64_t) == 8, "Wrong size for uint64_t");
#ifdef _WIN64
static_assert(sizeof(uintptr_t) == 8, "Wrong size for uintptr_t");
#else
static_assert(sizeof(uintptr_t) == 4, "Wrong size for uintptr_t");
#endif

#define HALLOC_PTR(x) (HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, x))
#define HALLOC_TYPE(x, t) (reinterpret_cast<t>(HALLOC_PTR(x)))
#define HFREE(p) (HeapFree(GetProcessHeap(), 0, reinterpret_cast<LPVOID>(p)))
#define FATAL(s) do { printf("!! Fatal error at (%s:%d), Message: %s, Win32 Last error %d\n", __FILE__, __LINE__, s, GetLastError()); ::ExitProcess(-1); } while (0)
#define CHECK_NONZERO(x) if(!(x)) { FATAL(#x); }
#define CHECK_ZERO(x) if((x)) { FATAL(#x); }
#define CHECK_ERROR(x) do { DWORD ____tmperr = (x); if(____tmperr != ERROR_SUCCESS) { ::SetLastError(____tmperr); FATAL(#x); } } while (0)
#define CHECK_HRESULT(x) do { HRESULT ____tmphr = (x); if(!SUCCEEDED(____tmphr)) { ::SetLastError(common::Win32FromHResult(____tmphr)); FATAL(#x); } } while(0) 
#define CHECK_NTSTATUS(x) do { NTSTATUS ____tmpstatus = (x); if(!NT_SUCCESS(____tmpstatus)) { ::SetLastError(::RtlNtStatusToDosError(____tmpstatus)); FATAL(#x); } } while(0)
#define MAKEQWORD(lo, hi) ((lo) | (uint64_t)((hi) << 32))

#if defined(_DEBUG)
#define DCHECK(x) if(!(x)) { FATAL(#x); }
#else
#define DCHECK(x) x
#endif

#define EXTERN_C extern "C"

#ifdef _MSC_VER
#define INLINE __forceinline
#define IMPORT __declspec(dllimport)
#elif defined(__GNUC__)
#define INLINE __attribute__((always_inline))
#define IMPORT __attribute__((dllimport))
#else
#error "Unsupported compiler."
#endif

/* NTDLL DEF START */

#define STATUS_PROCESS_CLONED (0x297)

typedef LONG NTSTATUS;

#ifndef NT_SUCCESS
#define NT_SUCCESS(x) (((LONG)(x)) >= 0)
#endif

#pragma comment(lib, "ntdll.lib")
EXTERN_C IMPORT ULONG RtlNtStatusToDosError(NTSTATUS Status);

#define RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED	0x00000001
#define RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES		0x00000002
#define RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE		0x00000004

typedef struct _CLIENT_ID {
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _SECTION_IMAGE_INFORMATION {
	PVOID EntryPoint;
	ULONG StackZeroBits;
	ULONG StackReserved;
	ULONG StackCommit;
	ULONG ImageSubsystem;
	WORD SubSystemVersionLow;
	WORD SubSystemVersionHigh;
	ULONG Unknown1;
	ULONG ImageCharacteristics;
	ULONG ImageMachineType;
	ULONG Unknown2[3];
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;

typedef struct _RTL_USER_PROCESS_INFORMATION {
	ULONG Size;
	HANDLE Process;
	HANDLE Thread;
	CLIENT_ID ClientId;
	SECTION_IMAGE_INFORMATION ImageInformation;
} RTL_USER_PROCESS_INFORMATION, *PRTL_USER_PROCESS_INFORMATION;

EXTERN_C NTSTATUS RtlCloneUserProcess(
	ULONG ProcessFlags,
	PSECURITY_DESCRIPTOR ProcessSecurityDescriptor /* optional */,
	PSECURITY_DESCRIPTOR ThreadSecurityDescriptor /* optional */,
	HANDLE DebugPort /* optional */,
	PRTL_USER_PROCESS_INFORMATION ProcessInformation
);

//typedef struct _UNICODE_STRING
//{
//	USHORT Length;
//	USHORT MaximumLength;
//	_Field_size_bytes_part_(MaximumLength, Length) PWCH Buffer;
//} UNICODE_STRING, *PUNICODE_STRING;

EXTERN_C
VOID
NTAPI
RtlInitUnicodeString(
	_Out_ PUNICODE_STRING DestinationString,
	_In_opt_ PWSTR SourceString
);

// Object attributes

#define OBJ_INHERIT 0x00000002
#define OBJ_PERMANENT 0x00000010
#define OBJ_EXCLUSIVE 0x00000020
#define OBJ_CASE_INSENSITIVE 0x00000040
#define OBJ_OPENIF 0x00000080
#define OBJ_OPENLINK 0x00000100
#define OBJ_KERNEL_HANDLE 0x00000200
#define OBJ_FORCE_ACCESS_CHECK 0x00000400
#define OBJ_IGNORE_IMPERSONATED_DEVICEMAP 0x00000800
#define OBJ_DONT_REPARSE 0x00001000
#define OBJ_VALID_ATTRIBUTES 0x00001ff2

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor; // PSECURITY_DESCRIPTOR;
	PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
    }

EXTERN_C
NTSTATUS
NTAPI
NtCreateLowBoxToken(
	_Out_ PHANDLE TokenHandle,
	_In_ HANDLE ExistingTokenHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ PSID PackageSid,
	_In_ ULONG CapabilityCount,
	_In_reads_opt_(CapabilityCount) PSID_AND_ATTRIBUTES Capabilities,
	_In_ ULONG HandleCount,
	_In_reads_opt_(HandleCount) HANDLE *Handles
);

typedef struct _PROCESS_MITIGATION_POLICY_INFORMATION
{
	PROCESS_MITIGATION_POLICY Policy;
	union
	{
		PROCESS_MITIGATION_ASLR_POLICY ASLRPolicy;
		PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY StrictHandleCheckPolicy;
		PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY SystemCallDisablePolicy;
		PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY ExtensionPointDisablePolicy;
		PROCESS_MITIGATION_DYNAMIC_CODE_POLICY DynamicCodePolicy;
		PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY ControlFlowGuardPolicy;
		PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY SignaturePolicy;
		PROCESS_MITIGATION_FONT_DISABLE_POLICY FontDisablePolicy;
		PROCESS_MITIGATION_IMAGE_LOAD_POLICY ImageLoadPolicy;
		PROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY SystemCallFilterPolicy;
		PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY PayloadRestrictionPolicy;
		PROCESS_MITIGATION_CHILD_PROCESS_POLICY ChildProcessPolicy;
	};
} PROCESS_MITIGATION_POLICY_INFORMATION, *PPROCESS_MITIGATION_POLICY_INFORMATION;

typedef enum _PROCESSINFOCLASS
{
	ProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
	ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
	ProcessIoCounters, // q: IO_COUNTERS
	ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
	ProcessTimes, // q: KERNEL_USER_TIMES
	ProcessBasePriority, // s: KPRIORITY
	ProcessRaisePriority, // s: ULONG
	ProcessDebugPort, // q: HANDLE
	ProcessExceptionPort, // s: PROCESS_EXCEPTION_PORT
	ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
	ProcessLdtInformation, // qs: PROCESS_LDT_INFORMATION // 10
	ProcessLdtSize, // s: PROCESS_LDT_SIZE
	ProcessDefaultHardErrorMode, // qs: ULONG
	ProcessIoPortHandlers, // (kernel-mode only)
	ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
	ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
	ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
	ProcessWx86Information,
	ProcessHandleCount, // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
	ProcessAffinityMask, // s: KAFFINITY
	ProcessPriorityBoost, // qs: ULONG
	ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
	ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
	ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
	ProcessWow64Information, // q: ULONG_PTR
	ProcessImageFileName, // q: UNICODE_STRING
	ProcessLUIDDeviceMapsEnabled, // q: ULONG
	ProcessBreakOnTermination, // qs: ULONG
	ProcessDebugObjectHandle, // q: HANDLE // 30
	ProcessDebugFlags, // qs: ULONG
	ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
	ProcessIoPriority, // qs: IO_PRIORITY_HINT
	ProcessExecuteFlags, // qs: ULONG
	ProcessResourceManagement, // ProcessTlsInformation // PROCESS_TLS_INFORMATION
	ProcessCookie, // q: ULONG
	ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
	ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
	ProcessPagePriority, // q: PAGE_PRIORITY_INFORMATION
	ProcessInstrumentationCallback, // qs: PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
	ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
	ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
	ProcessImageFileNameWin32, // q: UNICODE_STRING
	ProcessImageFileMapping, // q: HANDLE (input)
	ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
	ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
	ProcessGroupInformation, // q: USHORT[]
	ProcessTokenVirtualizationEnabled, // s: ULONG
	ProcessConsoleHostProcess, // q: ULONG_PTR // ProcessOwnerInformation
	ProcessWindowInformation, // q: PROCESS_WINDOW_INFORMATION // 50
	ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
	ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
	ProcessDynamicFunctionTableInformation,
	ProcessHandleCheckingMode,
	ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
	ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
	ProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL
	ProcessHandleTable, // since WINBLUE
	ProcessCheckStackExtentsMode,
	ProcessCommandLineInformation, // q: UNICODE_STRING // 60
	ProcessProtectionInformation, // q: PS_PROTECTION
	ProcessMemoryExhaustion, // PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
	ProcessFaultInformation, // PROCESS_FAULT_INFORMATION
	ProcessTelemetryIdInformation, // PROCESS_TELEMETRY_ID_INFORMATION
	ProcessCommitReleaseInformation, // PROCESS_COMMIT_RELEASE_INFORMATION
	ProcessDefaultCpuSetsInformation,
	ProcessAllowedCpuSetsInformation,
	ProcessSubsystemProcess,
	ProcessJobMemoryInformation, // PROCESS_JOB_MEMORY_INFO
	ProcessInPrivate, // since THRESHOLD2 // 70
	ProcessRaiseUMExceptionOnInvalidHandleClose,
	ProcessIumChallengeResponse,
	ProcessChildProcessInformation, // PROCESS_CHILD_PROCESS_INFORMATION
	ProcessHighGraphicsPriorityInformation,
	ProcessSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
	ProcessEnergyValues, // PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES
	ProcessActivityThrottleState, // PROCESS_ACTIVITY_THROTTLE_STATE
	ProcessActivityThrottlePolicy, // PROCESS_ACTIVITY_THROTTLE_POLICY
	ProcessWin32kSyscallFilterInformation,
	ProcessDisableSystemAllowedCpuSets,
	ProcessWakeInformation, // PROCESS_WAKE_INFORMATION
	ProcessEnergyTrackingState, // PROCESS_ENERGY_TRACKING_STATE
	ProcessManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
	ProcessCaptureTrustletLiveDump,
	ProcessTelemetryCoverage,
	ProcessEnclaveInformation,
	ProcessEnableReadWriteVmLogging, // PROCESS_READWRITEVM_LOGGING_INFORMATION
	ProcessUptimeInformation, // PROCESS_UPTIME_INFORMATION
	ProcessImageSection,
	ProcessDebugAuthInformation, // since REDSTONE4
	ProcessSystemResourceManagement, // PROCESS_SYSTEM_RESOURCE_MANAGEMENT
	ProcessSequenceNumber, // q: ULONGLONG
	MaxProcessInfoClass
} PROCESSINFOCLASS;

EXTERN_C
NTSTATUS
NTAPI
NtSetInformationProcess(
	_In_ HANDLE ProcessHandle,
	_In_ PROCESSINFOCLASS ProcessInformationClass,
	_In_reads_bytes_(ProcessInformationLength) PVOID ProcessInformation,
	_In_ ULONG ProcessInformationLength
);

EXTERN_C
NTSTATUS
NTAPI
NtGetNlsSectionPtr(
	_In_ ULONG SectionType,
	_In_ ULONG SectionData,
	_In_ PVOID ContextData,
	_Out_ PVOID *SectionPointer,
	_Out_ PULONG SectionSize
);

typedef struct _REPARSE_DATA_BUFFER {
	ULONG  ReparseTag;
	USHORT ReparseDataLength;
	USHORT Reserved;
	union {
		struct {
			USHORT SubstituteNameOffset;
			USHORT SubstituteNameLength;
			USHORT PrintNameOffset;
			USHORT PrintNameLength;
			ULONG  Flags;
			WCHAR  PathBuffer[1];
		} SymbolicLinkReparseBuffer;
		struct {
			USHORT SubstituteNameOffset;
			USHORT SubstituteNameLength;
			USHORT PrintNameOffset;
			USHORT PrintNameLength;
			WCHAR  PathBuffer[1];
		} MountPointReparseBuffer;
		struct {
			UCHAR DataBuffer[1];
		} GenericReparseBuffer;
	};
} REPARSE_DATA_BUFFER, *PREPARSE_DATA_BUFFER;

/* NTDLL DEF END */

namespace common {
	DWORD Win32FromHResult(HRESULT hr);
	//std::unique_ptr<std::string> RelativePathToAbsolute(const char* path);
	std::unique_ptr<std::string> Win32ErrToString(DWORD err);
	DWORD fork(void);
	std::unique_ptr<std::string> GetProcessPath(void);
	HANDLE LogonS4U(const wchar_t* user, const wchar_t* realm, NTSTATUS* rets = nullptr);
	bool EnablePrivilege(const char* priv);
	bool SetMountPoint(HANDLE hDirectory, std::string& reparse);
	bool QueryRegValueDword(HKEY hKey, const char* valueName, uint32_t* value);
	
	template<typename T> T getRandom(void) {
		T val = 0;
		CHECK_NTSTATUS(::BCryptGenRandom(NULL, reinterpret_cast<PUCHAR>(&val), sizeof(T), BCRYPT_USE_SYSTEM_PREFERRED_RNG));
		return val;
	}

	INLINE void* halloc(uintptr_t size) {
		return ::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, size);
	}

	INLINE void hfree(void* ptr) {
		::HeapFree(::GetProcessHeap(), 0, ptr);
	}
}