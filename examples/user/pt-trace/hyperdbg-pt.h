/**
 * @file hyperdbg-pt.h
 * @author Masoud Rahimi Jafari (Masoodrahimy1379@gmail.com)
 * @brief Minimal, self-contained mirror of the HyperDbg Intel PT IOCTL
 *        contract so this example builds with nothing but the Win32 SDK
 *        and libipt.
 * @details The layouts here MUST stay byte-for-byte identical to the SDK
 *          definitions in:
 *            - hyperdbg/include/SDK/headers/PtDefinitions.h
 *            - hyperdbg/include/SDK/headers/RequestStructures.h
 *            - hyperdbg/include/SDK/headers/Ioctls.h
 *          (see those headers for the authoritative comments / semantics).
 *
 * @copyright This project is released under the GNU Public License v3.
 */
#pragma once

#include <Windows.h>
#include <winioctl.h>
#include <stdint.h>

//
// Device exposed by the HyperDbg debugger driver.
//
#define HYPERDBG_DEVICE_NAME "\\\\.\\HyperDbgDebuggerDevice"

//
// Status value the driver writes into KernelStatus on success.
//
#define DEBUGGER_OPERATION_WAS_SUCCESSFUL 0xFFFFFFFF

//
// PT limits (from PtDefinitions.h).
//
#define PT_MAX_ADDR_RANGES   4
#define PT_MAX_CPUS_FOR_MMAP 64

//
// IOCTLs (from Ioctls.h).
//
#define IOCTL_PERFORM_HYPERTRACE_PT_OPERATION \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x829, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PERFORM_HYPERTRACE_PT_MMAP \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x82a, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// PT operation selector (from RequestStructures.h).
//
typedef enum _HYPERTRACE_PT_OPERATION_REQUEST_TYPE
{
    HYPERTRACE_PT_OP_ENABLE = 0,
    HYPERTRACE_PT_OP_DISABLE,
    HYPERTRACE_PT_OP_PAUSE,
    HYPERTRACE_PT_OP_RESUME,
    HYPERTRACE_PT_OP_SIZE,
    HYPERTRACE_PT_OP_DUMP,
    HYPERTRACE_PT_OP_FLUSH,
    HYPERTRACE_PT_OP_FILTER,
} HYPERTRACE_PT_OPERATION_REQUEST_TYPE;

#pragma pack(push, 1)

//
// IP filter range (from PtDefinitions.h).
//
typedef struct _PT_ADDR_RANGE
{
    UINT64  Start;
    UINT64  End;
    BOOLEAN IsStopRange;
    UINT8   Pad[7]; /* explicit tail padding to match natural 8-alignment */
} PT_ADDR_RANGE;

//
// Operation packet (from RequestStructures.h). Reserved was repurposed as
// TargetProcessId so the driver can resolve a PID to its CR3 for us.
//
typedef struct _HYPERTRACE_PT_OPERATION_PACKETS
{
    UINT32        PtOperationType;
    UINT32        KernelStatus;

    UINT32        TraceUser;
    UINT32        TraceKernel;
    UINT64        TargetCr3;
    UINT64        BufferSize;
    UINT32        NumAddrRanges;
    UINT32        TargetProcessId;
    PT_ADDR_RANGE AddrRanges[PT_MAX_ADDR_RANGES];

    UINT32        NumCpus;
    UINT32        Reserved2;
    UINT64        BytesPerCpu[PT_MAX_CPUS_FOR_MMAP];
} HYPERTRACE_PT_OPERATION_PACKETS;

//
// One per-CPU mapping descriptor (from PtDefinitions.h).
//
typedef struct _PT_USER_BUFFER_DESC
{
    UINT32 CpuId;
    UINT32 Reserved;
    UINT64 UserVa; /* base of main + overflow mapping in THIS process */
    UINT64 Size;   /* total bytes (main + overflow)                    */
} PT_USER_BUFFER_DESC;

//
// mmap result packet (from RequestStructures.h).
//
typedef struct _HYPERTRACE_PT_MMAP_PACKETS
{
    UINT32              KernelStatus;
    UINT32              NumCpus;
    PT_USER_BUFFER_DESC Cpus[PT_MAX_CPUS_FOR_MMAP];
} HYPERTRACE_PT_MMAP_PACKETS;

#pragma pack(pop)
