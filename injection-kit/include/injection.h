/*
 * injection.h - Common header for Starburst Arsenal Kit injection techniques
 *
 * This header provides shared type definitions, NT API function pointer
 * typedefs, helper macros, and structure definitions used across all
 * injection technique implementations.
 *
 * Usage:
 *   #include "injection.h"
 *   Resolve NT functions at runtime via GetProcAddress from ntdll.dll.
 *
 * When adapting for Starburst PIC (Stardust framework):
 *   - Replace GetProcAddress/GetModuleHandle with Stardust's
 *     LdrFunction / LdrModule resolution.
 *   - Replace standard C library calls with PIC-safe equivalents.
 *   - NT API typedefs here map directly to what Stardust expects.
 */

#ifndef INJECTION_H
#define INJECTION_H

#include <windows.h>

/* ============================================================
 * NTSTATUS and helper macros
 * ============================================================ */

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

/* ============================================================
 * Section access / protection constants
 * ============================================================ */

#ifndef SECTION_MAP_READ
#define SECTION_MAP_READ    0x0004
#endif

#ifndef SECTION_MAP_WRITE
#define SECTION_MAP_WRITE   0x0002
#endif

#ifndef SECTION_MAP_EXECUTE
#define SECTION_MAP_EXECUTE 0x0008
#endif

#ifndef SECTION_ALL_ACCESS
#define SECTION_ALL_ACCESS  0x000F
#endif

#ifndef SEC_COMMIT
#define SEC_COMMIT 0x08000000
#endif

/* ============================================================
 * Enumeration types used by NT APIs
 * ============================================================ */

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;

/* ============================================================
 * Structures
 * ============================================================ */

/* PS_ATTRIBUTE for NtCreateThreadEx */
typedef struct _PS_ATTRIBUTE {
    ULONG_PTR Attribute;
    SIZE_T    Size;
    union {
        ULONG_PTR Value;
        PVOID     ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T       TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

/* OBJECT_ATTRIBUTES for NtCreateSection and friends */
#ifndef InitializeObjectAttributes
typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PVOID           ObjectName;    /* PUNICODE_STRING */
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);         \
    (p)->RootDirectory = r;                          \
    (p)->Attributes = a;                             \
    (p)->ObjectName = n;                             \
    (p)->SecurityDescriptor = s;                     \
    (p)->SecurityQualityOfService = NULL;             \
}
#endif

#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040L
#endif

/* CLIENT_ID for NtOpenProcess / NtCreateThreadEx */
typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

/* ============================================================
 * NT API Function Pointer Typedefs
 * ============================================================ */

/* --- Process / Thread --- */

typedef NTSTATUS (NTAPI *fnNtCreateThreadEx)(
    PHANDLE                 ThreadHandle,
    ACCESS_MASK             DesiredAccess,
    POBJECT_ATTRIBUTES      ObjectAttributes,
    HANDLE                  ProcessHandle,
    PVOID                   StartRoutine,
    PVOID                   Argument,
    ULONG                   CreateFlags,
    SIZE_T                  ZeroBits,
    SIZE_T                  StackSize,
    SIZE_T                  MaximumStackSize,
    PPS_ATTRIBUTE_LIST      AttributeList
);

typedef NTSTATUS (NTAPI *fnNtOpenProcess)(
    PHANDLE             ProcessHandle,
    ACCESS_MASK         DesiredAccess,
    POBJECT_ATTRIBUTES  ObjectAttributes,
    PCLIENT_ID          ClientId
);

typedef NTSTATUS (NTAPI *fnNtClose)(
    HANDLE Handle
);

typedef NTSTATUS (NTAPI *fnNtResumeThread)(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount
);

typedef NTSTATUS (NTAPI *fnNtSuspendThread)(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount
);

typedef NTSTATUS (NTAPI *fnNtGetContextThread)(
    HANDLE    ThreadHandle,
    PCONTEXT  ThreadContext
);

typedef NTSTATUS (NTAPI *fnNtSetContextThread)(
    HANDLE    ThreadHandle,
    PCONTEXT  ThreadContext
);

typedef NTSTATUS (NTAPI *fnNtQueueApcThread)(
    HANDLE  ThreadHandle,
    PVOID   ApcRoutine,
    PVOID   ApcArgument1,
    PVOID   ApcArgument2,
    PVOID   ApcArgument3
);

/* --- Memory --- */

typedef NTSTATUS (NTAPI *fnNtAllocateVirtualMemory)(
    HANDLE    ProcessHandle,
    PVOID     *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
);

typedef NTSTATUS (NTAPI *fnNtWriteVirtualMemory)(
    HANDLE  ProcessHandle,
    PVOID   BaseAddress,
    PVOID   Buffer,
    SIZE_T  NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS (NTAPI *fnNtProtectVirtualMemory)(
    HANDLE  ProcessHandle,
    PVOID   *BaseAddress,
    PSIZE_T RegionSize,
    ULONG   NewProtect,
    PULONG  OldProtect
);

typedef NTSTATUS (NTAPI *fnNtFreeVirtualMemory)(
    HANDLE  ProcessHandle,
    PVOID   *BaseAddress,
    PSIZE_T RegionSize,
    ULONG   FreeType
);

/* --- Section objects --- */

typedef NTSTATUS (NTAPI *fnNtCreateSection)(
    PHANDLE            SectionHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER     MaximumSize,
    ULONG              SectionPageProtection,
    ULONG              AllocationAttributes,
    HANDLE             FileHandle
);

typedef NTSTATUS (NTAPI *fnNtMapViewOfSection)(
    HANDLE          SectionHandle,
    HANDLE          ProcessHandle,
    PVOID           *BaseAddress,
    ULONG_PTR       ZeroBits,
    SIZE_T          CommitSize,
    PLARGE_INTEGER  SectionOffset,
    PSIZE_T         ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG           AllocationType,
    ULONG           Protect
);

typedef NTSTATUS (NTAPI *fnNtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID  BaseAddress
);

/* ============================================================
 * Helper: resolve an NT function from ntdll.dll
 * ============================================================ */

static inline FARPROC ResolveNtFunction(const char *funcName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return NULL;
    return GetProcAddress(hNtdll, funcName);
}

/* ============================================================
 * Common injection function signature
 *
 * All technique files expose:
 *   BOOL inject(DWORD pid, LPVOID shellcode, SIZE_T shellcode_len);
 *
 * Returns TRUE on success, FALSE on failure.
 * Prints error information to stderr for diagnostic purposes.
 * ============================================================ */

#endif /* INJECTION_H */
