/**
 * @file WinaflHookDefinitions.h
 * @author Masoud Rahimi Jafari (Masoodrahimy1379@gmail.com)
 * @brief Shared WinAFL <-> HyperDbg persistence/coverage contract.
 * @details
 *   This header is the single source of truth for the structures exchanged
 *   between the WinAFL fuzzer (user mode) and the HyperDbg VMM (the
 *   MasoudPrologue / MasoudEpilogue hooks that run in VMX-root). It is shared,
 *   verbatim, by:
 *       - hyperkd          (the kernel side that fills the hooks),
 *       - libhyperdbg      (marshals the mmap + callback),
 *       - the WinAFL build (via a thin plain-C mirror that static_asserts the
 *                           layout matches; see winaflhook.h / winaflhook.cpp).
 *
 *   Two regions are mapped into the fuzzer with hyperdbg_u_*_mmap():
 *       1. one WINAFL_HOOK_SHARED control page (this struct), and
 *       2. one PT *data* buffer that the kernel copies each iteration's Intel
 *          PT bytes into (sliced by the SegmentSize[] table below).
 *
 *   All fields use fixed-width HyperDbg integer types so the layout is
 *   identical on every consumer. Do not reorder fields without bumping
 *   WINAFL_HOOK_ABI_VERSION; the kernel rejects a mismatched version.
 *
 * @version 0.1
 * @date 2026-06-17
 *
 * @copyright This project is released under the GNU Public License v3.
 *
 */
#pragma once

//////////////////////////////////////////////////
//                  Constants                   //
//////////////////////////////////////////////////

//
// ABI version. Bump on any layout change; the kernel validates it at arm time
// and refuses to run against a mismatched fuzzer build.
//
// v2: added register (RCX) input delivery + batched multi-run execution
//     (RcxDelivery / BatchCount / BatchInputs[] and the GO_BATCH command /
//     BATCH_DONE tag / NOTRUN status).
// v3: added the EPT guard-page sanitizer (heap-overflow + use-after-free
//     detection). New SanitizeFlags / SanAllocatorCount / PostStubAddress /
//     SanAllocators[] configuration and the SanFault* result block. A batch run
//     whose input trips a guard page (overflow) or touches a held freed buffer
//     (UAF) is reported to the fuzzer as an ordinary WINAFL_TAG_CRASH, attributed
//     to the offending input index, with the classification in SanFault*.
// v4: added WINAFL_SAN_ALLOCATOR.FlagsReg / ZeroFlag so the pre-hook can force a
//     zero-init flag (HEAP_ZERO_MEMORY) into the allocator. That makes the whole
//     enlarged chunk -- including the guard page in the redzone -- present, so the
//     guard page can actually be protected (otherwise a non-zeroed allocation
//     leaves the redzone un-faulted-in and overflow detection silently fails).
//
#define WINAFL_HOOK_ABI_VERSION 4

//
// Maximum fuzzed-function arguments we snapshot/restore at the prologue.
//
#define WINAFL_HOOK_MAX_ARGS 16

//
// Maximum number of per-iteration PT segments buffered before the fuzzer must
// drain. v1 uses exactly one (single run per round-trip); batching (v1.3) uses
// up to this many before signalling the fuzzer. Bounds the SegmentSize/Status
// tables that live in the control page, so keep it modest.
//
#define WINAFL_HOOK_MAX_SEGMENTS 256

//
// Maximum inputs the fuzzer may hand the kernel in a single batched run
// (WINAFL_CMD_GO_BATCH). Each input is one 8-byte value delivered in RCX. Must
// be <= WINAFL_HOOK_MAX_SEGMENTS, since the per-run SegmentSize/SegmentStatus
// output tables (below) are indexed by batch position.
//
#define WINAFL_HOOK_MAX_BATCH 100

//
// ---- EPT guard-page sanitizer (ABI v3) ----
//
// Maximum allocator functions the fuzzer may register for guard-page
// instrumentation (RtlAllocateHeap/RtlFreeHeap, ExAllocatePool*/ExFreePool*, ...).
//
#define WINAFL_SAN_MAX_ALLOCATORS 8

//
// Sanitizer master flags (WINAFL_HOOK_SHARED.SanitizeFlags). Zero => the whole
// sanitizer is inert (no allocator hooks are registered by the fuzzer, so the VMM
// never sees the extra hits).
//
#define WINAFL_SAN_OVERFLOW 0x1 // guard-page heap-overflow detection
#define WINAFL_SAN_UAF      0x2 // use-after-free detection (hold freed pages)

//
// Guard-page over-allocation, in bytes. The pre-hook adds this to the requested
// size; the post-hook then repositions the caller's buffer so its last byte ends
// exactly on a page boundary with a dedicated no-access guard page immediately
// after it, AND so the buffer's first page is fully owned by this allocation (no
// bleed into the previous heap chunk). The placement is
//     GuardVa = PAGE_UP(RealBase) + PAGE_UP(OrigSize)
//     UserPtr = GuardVa - OrigSize
// whose worst-case span is OrigSize + 3 pages: up to one page of front slack
// (PAGE_UP(RealBase) - RealBase) + up to one page of tail rounding
// (PAGE_UP(OrigSize) - OrigSize) + one guard page. See the guard math in the VMM.
//
#define WINAFL_SAN_REDZONE 0x3000

//
// Synthetic exception vector stamped into WINAFL_HOOK_SHARED.FaultVector for a
// sanitizer-detected crash, so the fuzzer can tell it apart from a real fault.
// The precise overflow-vs-UAF classification is in SanFaultKind.
//
#define WINAFL_SAN_FAULT_VECTOR 0x5A

//////////////////////////////////////////////////
//                    Enums                     //
//////////////////////////////////////////////////

/**
 * @brief Command word: fuzzer -> kernel. Written by the fuzzer, polled in
 *        VMX-root at the park stub.
 */
typedef enum _WINAFL_HOOK_COMMAND
{
    WINAFL_CMD_IDLE = 0, // keep the guest parked (spin in the stub)
    WINAFL_CMD_GO,       // release: run exactly one more iteration
    WINAFL_CMD_STOP,     // tear down: stop hooking, let the target proceed/exit
    WINAFL_CMD_GO_BATCH, // release: run BatchCount iterations back-to-back, each
                         // with RCX = BatchInputs[i], recording SegmentSize[i] /
                         // SegmentStatus[i] per run, then notify BATCH_DONE once.

} WINAFL_HOOK_COMMAND;

/**
 * @brief Status word: kernel -> fuzzer. Written in VMX-root, polled (or
 *        delivered via the Masoud callback) by the fuzzer.
 */
typedef enum _WINAFL_HOOK_STATUS
{
    WINAFL_STATUS_INIT = 0,  // not armed yet
    WINAFL_STATUS_ARMED,     // hooks installed, waiting for the first entry hit
    WINAFL_STATUS_ENTRY,     // first prologue reached; snapshot captured
    WINAFL_STATUS_ITER_DONE, // an iteration returned normally (epilogue ran)
    WINAFL_STATUS_CRASH,     // the target faulted (see Fault* fields)
    WINAFL_STATUS_HANG,      // watchdog fired before the iteration returned
    WINAFL_STATUS_NOTRUN,    // batch: this run never executed (a prior run in the
                             // batch crashed/hung and truncated the remainder)

} WINAFL_HOOK_STATUS;

/**
 * @brief Tag passed to the Masoud callback so the fuzzer knows *why* it was
 *        woken without having to diff the whole control page. The full detail
 *        always lives in WINAFL_HOOK_SHARED.
 */
typedef enum _WINAFL_HOOK_TAG
{
    WINAFL_TAG_ARMED     = 0x5741F1A0, // "WAF1" + nibble
    WINAFL_TAG_ENTRY     = 0x5741F1A1,
    WINAFL_TAG_ITER_DONE = 0x5741F1A2,
    WINAFL_TAG_CRASH     = 0x5741F1A3,
    WINAFL_TAG_HANG      = 0x5741F1A4,
    WINAFL_TAG_BATCH_DONE = 0x5741F1A5, // a GO_BATCH run finished all BatchCount runs

} WINAFL_HOOK_TAG;

/**
 * @brief Which x64 integer-argument register carries the size (for an allocator)
 *        or the pointer (for a free). Only used to read/patch the right register
 *        in the VMX-root pre-hook; the numeric values are private to this ABI.
 */
typedef enum _WINAFL_SAN_REG
{
    WINAFL_SAN_REG_NONE = 0,
    WINAFL_SAN_REG_RCX  = 1,
    WINAFL_SAN_REG_RDX  = 2,
    WINAFL_SAN_REG_R8   = 3,
    WINAFL_SAN_REG_R9   = 4,

} WINAFL_SAN_REG;

/**
 * @brief Role of a hooked allocator function.
 */
typedef enum _WINAFL_SAN_FN_KIND
{
    WINAFL_SAN_FN_NONE  = 0,
    WINAFL_SAN_FN_ALLOC = 1, // pre: enlarge the size register; post (via the return
                             //      stub): capture RAX and reposition the buffer
    WINAFL_SAN_FN_FREE  = 2, // pre: look up the pointer register, hold + protect the
                             //      buffer's pages, and skip the real free

} WINAFL_SAN_FN_KIND;

/**
 * @brief Sanitizer fault classification (WINAFL_HOOK_SHARED.SanFaultKind).
 */
typedef enum _WINAFL_SAN_FAULT
{
    WINAFL_SAN_FAULT_NONE        = 0,
    WINAFL_SAN_FAULT_OVERFLOW    = 1, // access crossed into a guard page
    WINAFL_SAN_FAULT_UAF         = 2, // access to a freed (still-held) buffer
    WINAFL_SAN_FAULT_DOUBLE_FREE = 3, // free() of a buffer already held as freed.
                                      // Detected in the free hook (not via an EPT
                                      // violation), so it never appears as a page
                                      // Kind -- only in SanFaultKind.

} WINAFL_SAN_FAULT;

//////////////////////////////////////////////////
//                  Structures                  //
//////////////////////////////////////////////////

/**
 * @brief One hooked allocator function. The fuzzer resolves the entry VA in the
 *        target and fills the register roles per that function's calling
 *        convention. Examples (Windows x64):
 *          RtlAllocateHeap(Heap, Flags, Size@R8)   -> ALLOC, ArgReg=R8
 *          RtlFreeHeap(Heap, Flags, Base@R8)        -> FREE,  ArgReg=R8, RetIsBool=1
 *          ExAllocatePoolWithTag(Type, Size@RDX)    -> ALLOC, ArgReg=RDX
 *          ExAllocatePool2(Flags, Size@RDX)         -> ALLOC, ArgReg=RDX
 *          ExFreePoolWithTag(P@RCX, Tag)            -> FREE,  ArgReg=RCX
 *          ExFreePool(P@RCX)                         -> FREE,  ArgReg=RCX
 */
typedef struct _WINAFL_SAN_ALLOCATOR
{
    UINT64 Address;   // [F->K] entry VA (0 => unused slot)
    UINT32 Kind;      // [F->K] WINAFL_SAN_FN_KIND
    UINT32 ArgReg;    // [F->K] WINAFL_SAN_REG: size (ALLOC) or pointer (FREE)
    UINT32 RetIsBool; // [F->K] FREE only: 1 => emulate a BOOLEAN(TRUE) return in RAX
    UINT32 FlagsReg;  // [F->K] ALLOC only: WINAFL_SAN_REG holding the alloc flags, or
                      //        WINAFL_SAN_REG_NONE. The pre-hook ORs ZeroFlag into it.
    UINT64 ZeroFlag;  // [F->K] ALLOC only: flag bit(s) to force zero-initialisation
                      //        (e.g. HEAP_ZERO_MEMORY=0x8 in RtlAllocateHeap's RDX).
                      //        Zeroing the ENLARGED size touches the whole chunk so the
                      //        guard page in the redzone is present and can be
                      //        protected; without it a non-zeroed allocation leaves the
                      //        redzone un-faulted-in and overflow detection silently
                      //        fails. 0 => do not touch the flags register.

} WINAFL_SAN_ALLOCATOR;

/**
 * @brief Plain mirror of GUEST_REGS (rax..r15). Same field order and size as
 *        HyperDbg's GUEST_REGS so the kernel can copy between the two with a
 *        single memcpy. Kept type-independent here so non-HyperDbg consumers
 *        (the WinAFL build) can share the exact layout.
 */
typedef struct _WINAFL_HOOK_REGS
{
    UINT64 rax;
    UINT64 rcx;
    UINT64 rdx;
    UINT64 rbx;
    UINT64 rsp;
    UINT64 rbp;
    UINT64 rsi;
    UINT64 rdi;
    UINT64 r8;
    UINT64 r9;
    UINT64 r10;
    UINT64 r11;
    UINT64 r12;
    UINT64 r13;
    UINT64 r14;
    UINT64 r15;

} WINAFL_HOOK_REGS;

/**
 * @brief The single shared control page mapped into the fuzzer.
 *
 * Ownership of each field is annotated as:
 *   [F->K] fuzzer writes / kernel reads (configuration & commands)
 *   [K->F] kernel writes / fuzzer reads (snapshot, status, results)
 *   [both] handshake words touched by both sides (volatile)
 */
typedef struct _WINAFL_HOOK_SHARED
{
    //
    // ABI guard. The kernel checks these at arm time.
    //
    UINT32 Version;    // [F->K] must equal WINAFL_HOOK_ABI_VERSION
    UINT32 StructSize; // [F->K] must equal sizeof(WINAFL_HOOK_SHARED)

    //
    // ---- Configuration (written once at arm) ----
    //
    UINT64 FuzzAddress;     // [F->K] fuzzed function entry VA (target space)
    UINT64 ReturnAddress;   // [K->F] captured at first entry from [rsp]
    UINT64 ParkStubAddress; // [F->K] VA of the spin stub the epilogue parks at
    UINT32 TargetProcessId; // [F->K] target PID (0 => kernel-mode / all procs)
    UINT32 CallConv;        // [F->K] calling convention (see winaflpt CALLCONV_*)
    UINT32 NumArgs;         // [F->K] number of args to snapshot (<= MAX_ARGS)
    UINT32 PtrSize;         // [F->K] 4 (wow64) or 8

    //
    // ---- Handshake (both directions, polled in VMX-root / user) ----
    //
    volatile UINT32 Command;        // [both] WINAFL_HOOK_COMMAND
    volatile UINT32 Status;         // [both] WINAFL_HOOK_STATUS
    volatile UINT64 IterationCount; // [K->F] iterations completed since arm
    UINT32          FirstHitDone;   // [K->K] set after the first prologue snapshot
    UINT32          WatchdogMs;     // [F->K] per-iteration timeout, 0 = disabled

    //
    // ---- Snapshot captured at the first entry (the rewind state) ----
    //
    WINAFL_HOOK_REGS SavedRegs;                   // [K->F] GP regs at entry
    UINT64           SavedRsp;                     // [K->F] rsp at entry
    UINT64           SavedArgs[WINAFL_HOOK_MAX_ARGS]; // [K->F] resolved arguments

    //
    // ---- Optional register/arg overrides applied by the epilogue ----
    // The fuzzer may ask the kernel to start the next iteration with modified
    // registers/args (e.g. register-based input delivery in v1.2). Ignored
    // unless ApplyRegOverrides is non-zero.
    //
    UINT32           ApplyRegOverrides;          // [F->K]
    WINAFL_HOOK_REGS NewRegs;                     // [F->K]
    UINT64           NewArgs[WINAFL_HOOK_MAX_ARGS]; // [F->K]

    //
    // ---- Crash / hang detail (valid when Status is CRASH/HANG) ----
    //
    UINT32           FaultVector;    // [K->F] exception vector
    UINT32           FaultErrorCode; // [K->F] exception error code
    UINT64           FaultRip;       // [K->F] faulting instruction pointer
    UINT64           FaultAddress;   // [K->F] CR2 for #PF, else 0
    WINAFL_HOOK_REGS FaultRegs;      // [K->F] GP regs at the fault

    //
    // ---- PT segment table ----
    // The kernel copies each completed iteration's Intel PT bytes into the
    // separately-mapped PT data buffer (PtDataUserVa) and records the length
    // here. The fuzzer slices the data buffer sequentially: iteration i occupies
    // [ sum(SegmentSize[0..i-1]), sum(SegmentSize[0..i]) ). v1 produces exactly
    // one segment per drain; batching produces up to SegmentCount of them.
    //
    UINT64 PtDataUserVa;    // [K->F] base of the mapped PT data buffer
    UINT64 PtDataCapacity;  // [K->F] total bytes in the PT data buffer
    UINT64 PtDataUsed;      // [K->F] bytes filled so far this drain
    UINT32 SegmentCount;    // [K->F] number of buffered iterations
    UINT32 SegmentOverflow; // [K->F] 1 if a segment was truncated/dropped (full)
    UINT64 SegmentSize[WINAFL_HOOK_MAX_SEGMENTS];   // [K->F] cumulative PT ring write
                                                    //        offset after each run
    UINT32 SegmentStatus[WINAFL_HOOK_MAX_SEGMENTS]; // [K->F] WINAFL_HOOK_STATUS per iter

    //
    // ---- Register (RCX) input delivery + batched execution (ABI v2) ----
    // When RcxDelivery is non-zero the kernel loads RCX (the Windows x64 first
    // integer-argument register) from BatchInputs[] on every run entry (both
    // WINAFL_CMD_GO -- which uses BatchInputs[0] -- and WINAFL_CMD_GO_BATCH --
    // which walks BatchInputs[0..BatchCount)). The rest of the entry snapshot is
    // left untouched, so a normal C fuzz function void f(uint64_t x) receives the
    // input as x. When RcxDelivery is zero the hooks behave exactly as ABI v1
    // (file-based input; no register is written).
    //
    UINT32 RcxDelivery;                      // [F->K] 1 => deliver input via RCX
    UINT32 BatchCount;                       // [F->K] runs in this GO_BATCH (<= MAX_BATCH)
    UINT64 BatchInputs[WINAFL_HOOK_MAX_BATCH]; // [F->K] per-run RCX values

    //
    // ---- EPT guard-page sanitizer (ABI v3) ----
    // Heap-overflow + use-after-free detection via EPT no-access guard pages.
    // Entirely inert when SanitizeFlags == 0 (the fuzzer then registers no
    // allocator hooks, so the VMM never runs any of this code). See the guard math
    // and lifecycle in the VMM (WinaflSan* in hyperkd Debugger.c).
    //
    UINT32               SanitizeFlags;     // [F->K] WINAFL_SAN_* bits; 0 = disabled
    UINT32               SanAllocatorCount; // [F->K] valid entries in SanAllocators[]
    UINT64               PostStubAddress;   // [F->K] return-trampoline stub VA (guest);
                                            //        exec-hooked, used to capture RAX at
                                            //        allocator return without a per-call hook
    WINAFL_SAN_ALLOCATOR SanAllocators[WINAFL_SAN_MAX_ALLOCATORS]; // [F->K]

    //
    // Filled by the EPT-violation classifier when a guard-page / UAF fault is
    // reported to the fuzzer as a crash (the generic Fault* block above is filled
    // too: FaultVector = WINAFL_SAN_FAULT_VECTOR, FaultRip = faulting RIP).
    //
    UINT32 SanFaultKind;       // [K->F] WINAFL_SAN_FAULT
    UINT32 SanFaultInputIndex; // [K->F] batch index blamed for the fault
    UINT64 SanFaultAllocBase;  // [K->F] user pointer of the offending allocation
    UINT64 SanFaultAccessVa;   // [K->F] faulting linear address (0 if unavailable)
    UINT64 SanFaultAllocSize;  // [K->F] original requested size of that allocation

} WINAFL_HOOK_SHARED, *PWINAFL_HOOK_SHARED;

//////////////////////////////////////////////////
//                 IOCTL packets                //
//////////////////////////////////////////////////

/**
 * @brief Arm/disarm request (IOCTL_PERFORM_WINAFL_HOOK_ARM / _DISARM).
 *
 *        The fuzzer allocates the WINAFL_HOOK_SHARED page in its own address
 *        space, fills the configuration fields, then passes the page's user VA
 *        and size here. The kernel pins those pages and resolves a system VA the
 *        VMX-root hooks use. Disarm ignores the address fields.
 */
typedef struct _WINAFL_HOOK_ARM_PACKETS
{
    UINT64 SharedUserVa; // [F->K] user VA of the WINAFL_HOOK_SHARED page
    UINT32 SharedSize;   // [F->K] its size in bytes (>= sizeof(WINAFL_HOOK_SHARED))
    UINT32 KernelStatus; // [K->F] DEBUGGER_* status

} WINAFL_HOOK_ARM_PACKETS, *PWINAFL_HOOK_ARM_PACKETS;

#define SIZEOF_WINAFL_HOOK_ARM_PACKETS sizeof(WINAFL_HOOK_ARM_PACKETS)
