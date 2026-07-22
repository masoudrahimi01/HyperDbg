
/**
 * @file GlobalVariables.h
 * @author Sina Karvandi (sina@hyperdbg.org)
 * @brief Definition for global variables
 * @details
 * @version 0.19
 * @date 2026-04-19
 *
 * @copyright This project is released under the GNU Public License v3.
 *
 */
#pragma once

//////////////////////////////////////////////////
//			   Global Variables     			//
//////////////////////////////////////////////////

/**
 * @brief List of callbacks
 *
 */
HYPERTRACE_CALLBACKS g_Callbacks;

/**
 * @brief The flag indicating whether the hypertrace module callbacks is initialized or not
 *
 */
BOOLEAN g_HyperTraceCallbacksInitialized;

/**
 * @brief The flag indicating whether the initialization is being done for hypervisor environment or not
 *
 */
BOOLEAN g_RunningOnHypervisorEnvironment;

/**
 * @brief The flag indicating whether the architectural LBR is supported by the CPU or not
 * if false it means the legacy LBR is supported
 *
 */
BOOLEAN g_ArchBasedLastBranchRecord;

/**
 * @brief The flag indicating whether the hypertrace LBR tracing is initialized or not
 *
 */
BOOLEAN g_LastBranchRecordEnabled;

/**
 * @brief This will be a dynamically allocated array to hold LBR states for each core
 *
 */
LBR_STACK_ENTRY * g_LbrStateList;

/**
 * @brief The global variable to hold the LBR capacity of the current CPU
 *
 */
ULONGLONG g_LbrCapacity;

/**
 * @brief The global variable to hold CPUID leaf 0x28 information (Architectural LBR Enumeration Leaf)
 *
 */
CPUID28_LEAFS g_Cpuid28Leafs;

/**
 * @brief The global variable to hold the current LBR filter options bitmask (for both architectural and legacy LBR)
 *
 */
UINT64 g_LbrFilterOptions;

/**
 * @brief The flag indicating whether the hypertrace Processor Trace is initialized or not
 *
 */
BOOLEAN g_ProcessorTraceEnabled;

/**
 * @brief Dynamically allocated array of per-CPU Intel PT state.
 *        Sized to KeQueryActiveProcessorCount(0) at hypertrace init.
 */
PT_PER_CPU * g_PtStateList;

/**
 * @brief When TRUE, ONLY g_PtFuzzCoreId takes part in Processor Trace: every
 *        per-core PT operation becomes a no-op on any other core, and no PT
 *        buffers are allocated or mapped for them.
 *
 *        The point is memory. PT buffers are physically contiguous, non-paged,
 *        and per core, so a 16 MB ring on a 20-core box costs 320 MB of
 *        contiguous non-paged memory even though a pinned fuzzing target only
 *        ever writes to one core's ring. Restricting PT to the fuzz core makes a
 *        large ring affordable.
 *
 *        Set at hypertrace init (TraceApi.c). Only meaningful while PT is
 *        disabled: flipping it with buffers already allocated would leave the
 *        other cores' buffers allocated but unmanaged, so change it and then
 *        re-enable PT.
 */
BOOLEAN g_PtSingleCoreOnly;

/**
 * @brief The core that PT runs on when g_PtSingleCoreOnly is set. Must match the
 *        core the fuzz target is pinned to (WinAFL pins to core 0 and reads that
 *        core's ring, so this is 0).
 */
UINT32 g_PtFuzzCoreId;

/**
 * @brief Per-CPU MDL + user-mode VA for the PT mmap surface (main
 *        output buffer concatenated with the 4 KB overflow page in a
 *        single contiguous user mapping). Populated by
 *        PtMmapAllCpuBuffersToUser, torn down by
 *        PtUnmapAllCpuBuffersFromUser. The user VAs are only valid in
 *        the address space of the process that called the mmap IOCTL —
 *        see HYPERTRACE_PT_MMAP_PACKETS for the contract.
 */
PT_USER_MAPPING g_PtUserMappings[PT_MAX_CPUS_FOR_MMAP];

/**
 * @brief Set while g_PtUserMappings holds live user mappings; cleared
 *        by PtUnmapAllCpuBuffersFromUser.
 */
BOOLEAN g_PtUserMappingsActive;
