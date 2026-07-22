/**
 * @file Debugger.c
 * @author Sina Karvandi (sina@hyperdbg.org)
 * @brief Implementation of Debugger functions
 * @details
 *
 * @version 0.1
 * @date 2020-04-13
 *
 * @copyright This project is released under the GNU Public License v3.
 *
 */
#include "pch.h"

//
// ===================== WinAFL HyperDbg persistence hooks =====================
//
// MasoudPrologue / MasoudEpilogue implement WinAFL's persistent-mode fuzzing on
// top of HyperDbg. They are called from DebuggerTriggerEvents() for every
// HIDDEN_HOOK_EXEC_CC (!epthook) hit, in VMX-root, with:
//     Context = the hooked guest virtual address,
//     Regs    = the guest GP registers (rax..r15, rsp).
//
// They are COMPLETELY INERT until the fuzzer arms them by publishing a shared
// control page via WinaflHookSetSharedPage(): when g_WinaflHookShared is NULL, or
// the hooked address is not one of ours, MasoudPrologue returns FALSE so ordinary
// !epthook events keep their normal behaviour (their actions run; the epilogue is
// a no-op for non-WinAFL addresses).
//
// v1 fuzzes a USER-mode target, so every register/stack edit below only ever
// changes a user process — a mistake can at worst crash the harness, never the
// kernel. The hook bodies still run in root, so they stay minimal and defensive.
//
// The three addresses we hook (all in the target process, scoped to its PID by
// the event itself) are:
//     FuzzAddress     - the fuzzed function entry  (prologue / rewind landing)
//     ReturnAddress   - captured from [rsp] at the first entry (epilogue point)
//     ParkStubAddress - a tiny guest spin stub we park at between iterations
//

//
// ============================ WinAFL kernel logging ============================
//
// All WinAFL hook + sanitizer diagnostics are compile-gated by the two switches
// below, so production / speed runs carry ZERO logging cost. These hooks run in
// VMX-root on the hot path (every fuzz iteration, every guest allocation) where
// there is no IOCTL backpressure on HyperDbg's log path -- an unbounded LogInfo here
// floods that path and bug-checks the box after a few hundred hits. Flip a switch to
// 1 and rebuild hyperkd ONLY for bring-up (pair with the user-side HOOK_DEBUG_LOGS=1
// so the lines are actually printed). Each compiles to nothing when its switch is 0.
//
//   WINAFL_HOOK_KERNEL_VERBOSE -> WINAFL_KLOG("[winafl] ...")
//       Persistence hooks: arm, per-run entry/return tracing, state dumps. Chatty.
//
//   WINAFL_SAN_KERNEL_VERBOSE  -> WINAFL_SAN_KLOG(cat, "[san] ...")
//       EPT guard-page sanitizer: alloc/free, guard placement, faults. Each line is
//       RATE-LIMITED to the first WINAFL_SAN_LOG_LIMIT lines of its category, so a
//       run emits a bounded burst then goes quiet. (The rate-limiter machinery lives
//       next to the sanitizer state further down; only the knobs live here.)
//
// WINAFL_HOOK_KERNEL_VERBOSE is OFF deliberately. Several of its call sites are on the
// per-iteration path -- "entry hook hit" and "return hook hit" fire from VMX-root on
// EVERY run with no rate limit at all, which at a few hundred execs/second is exactly
// the unbounded flood described above. It also drowns the sanitizer's own lines: a run
// that emitted 34 target relaunches produced only 29 kernel log lines, all of them from
// arm time, because everything from VMX-root was being dropped. Turn it back on only
// for short, low-rate persistence bring-up.
#define WINAFL_HOOK_KERNEL_VERBOSE 0
#define WINAFL_SAN_KERNEL_VERBOSE  1

// Per category, per arm. Kept SMALL on purpose. The budget refreshes at every arm, and
// the user side fsyncs every message to disk (deliberately -- the log has to survive a
// bug check), so each line costs milliseconds. A run that emitted a few hundred lines
// was measured running FIVE SECONDS behind, with messages truncated mid-string: by then
// the kernel ring is backed up and the log is no longer a reliable record of what
// happened, which is exactly when you need it most. Eight lines per category still shows
// the shape of a run; the cumulative g_SanStats in the reset summary carry the totals.
#define WINAFL_SAN_LOG_LIMIT       8

//
// The first argument to these wrappers is a NAMED parameter (`fmt`) on purpose: it
// must reach LogInfo() as a lone string literal and never be folded into __VA_ARGS__.
// LogInfo() itself pastes `format` between two string literals ("... | " fmt "\n"),
// and MSVC's legacy preprocessor hands a nested __VA_ARGS__ over as a single blob --
// expanding to `"..." "text", a, b "\n"` (syntax error: missing ')' before 'string').
// ##__VA_ARGS__ elides the comma when there are no trailing args. The same rule
// applies to WINAFL_SAN_KLOG below.
//
#if WINAFL_HOOK_KERNEL_VERBOSE
#    define WINAFL_KLOG(fmt, ...) LogInfo(fmt, ##__VA_ARGS__)
#else
#    define WINAFL_KLOG(fmt, ...) ((VOID)0)
#endif

//
// Published by the WinAFL arm IOCTL. Points at the non-paged shared control page
// that is also mapped into the fuzzer. NULL => disarmed (hooks inert).
//
PWINAFL_HOOK_SHARED g_WinaflHookShared = NULL;

//
// MDL backing the pinned fuzzer page, kept so WinaflHookDisarm can release it.
//
static PMDL g_WinaflHookMdl = NULL;

//
// Batched-execution state (ABI v2). While a WINAFL_CMD_GO_BATCH is in flight the
// return hook runs the next input in place instead of parking/notifying, until all
// BatchCount runs are done. Single-core (the target is pinned), so plain statics.
//
static BOOLEAN g_WinaflBatchActive = FALSE;
static UINT32  g_WinaflBatchIndex  = 0;

//
// =================== WinAFL EPT guard-page sanitizer state ===================
//
// Heap-overflow + use-after-free detection (ABI v3). Backed by the hyperhv EPT
// guard primitives (VmFuncEptGuardProtectPage / VmFuncEptGuardRestorePage). All of
// this is inert unless the fuzzer arms with SanitizeFlags != 0 and registers
// allocator hooks; MasoudPrologue then routes the extra !epthook hits here.
//
// Lifetime model -- TWO DIFFERENT LIFETIMES, and conflating them corrupts the guest
// heap (this was a real bug; see below):
//
//   * EPT protections (g_SanPages) are PER BATCH. WinaflSanBatchReset() restores
//     every protected page to its original EPT entry at the END of each run/batch
//     (normal finish AND crash) -- so by the time the fuzzer kills the target the
//     physical frames are RWX again and cannot fault an unrelated consumer after the
//     frames are freed. (Restoring EPT/INVEPT is only valid in VMX-root, which is why
//     it is done at these hook boundaries and not from the passive-level disarm.)
//
//   * Reposition records (g_SanAllocs) are PER TARGET PROCESS. They must NOT be
//     dropped at a batch boundary. Guarding hands the caller a REPOSITIONED pointer,
//     and the free hook can only un-shift a pointer it still has a record for. The
//     guest's heap is not reset between batches: a buffer allocated in batch N is
//     routinely freed in batch N+1 (ntdll's own long-lived allocations especially).
//     If the record were gone by then, the free would look FOREIGN and the shifted
//     pointer would reach the real allocator -- which is not a heap block base ->
//     heap corruption -> hangs and a bug check. Only WinaflSanProcessReset(), at the
//     first entry hit of a FRESH target, clears them.
//
//   * A guarded allocation's guard page therefore lives until it is freed or the
//     batch ends, but the knowledge that it is repositioned lives as long as the
//     process that holds the pointer. UAF holds a freed buffer's pages no-access
//     until the batch ends; the buffer itself is never returned to the allocator.
//
#define WINAFL_SAN_PAGE_MASK    ((UINT64)(PAGE_SIZE - 1))
#define WINAFL_SAN_PAGE_DOWN(x) ((UINT64)(x) & ~WINAFL_SAN_PAGE_MASK)
#define WINAFL_SAN_PAGE_UP(x)   WINAFL_SAN_PAGE_DOWN((UINT64)(x) + WINAFL_SAN_PAGE_MASK)

//
// Per-batch capacities. If any is exceeded the sanitizer FAILS OPEN (it stops
// guarding new allocations / pages but never blocks the run), so a pathological
// input can at worst lose detection, never wedge the fuzzer.
//
#define WINAFL_SAN_MAX_ALLOCS     4096                 // tracked allocations per TARGET PROCESS
#define WINAFL_SAN_MAX_PAGES      8192                 // protected phys pages per batch
#define WINAFL_SAN_MAX_PENDING    128                  // in-flight alloc calls (entry->ret)
#define WINAFL_SAN_MAX_GUARD_SIZE (16 * 1024 * 1024)   // don't guard allocs larger than this

//
// ===================== QUARANTINE BOUND (UAF mode) =========================
//
// How many freed buffers may be held back from the allocator at once. Past this,
// frees un-reposition and go through to the real allocator exactly as in
// overflow-only mode.
//
// This bound is NOT a nicety -- without it the box eventually bug-checks, and the
// path is worth spelling out because it is entirely non-obvious:
//
//   holding every freed buffer means the heap can never reuse memory, so every run
//   allocates FRESH virtual pages backed by FRESH physical pages -> each new physical
//   page in a previously-untouched 2MB region forces EptSplitLargePage to take a
//   VMM_EPT_DYNAMIC_SPLIT (a full 512-entry PML1 = 4KB of NON-PAGED POOL) -- and
//   nothing ever gives one back. There is no PoolManagerFreePool for
//   SPLIT_2MB_PAGING_TO_4KB_PAGE anywhere in the tree. At a few hundred execs a
//   second that is a steady, permanent non-paged pool leak, and non-paged pool
//   exhaustion takes the machine down after a couple of minutes.
//
// Bounding the quarantine lets the heap recycle its memory, so the guarded pages keep
// landing in the same handful of 2MB regions that are already split.
//
// The detection cost is small, because guard/held pages are restored at every RUN
// boundary anyway: a buffer held beyond the run that freed it is no longer protected
// and can no longer be detected. Quarantining it past that point leaked memory for no
// benefit at all. (ASAN bounds its quarantine for the same reason; it can evict by
// really freeing the oldest, which we cannot do from VMX-root -- so we simply stop
// quarantining once full.)
//
#define WINAFL_SAN_MAX_QUARANTINE 256

//
// One guarded allocation.
//
typedef struct _WINAFL_SAN_ALLOC_META
{
    UINT64  UserPtr;    // pointer handed to the caller (free lookup key)
    UINT64  RealBase;   // the allocator's real (enlarged) base
    UINT64  OrigSize;   // caller's requested size (bytes)
    UINT64  GuardVa;    // guard page VA (== page-aligned end of the user buffer)
    UINT64  HeapHandle; // allocator's 1st arg (RCX) -- the heap this block belongs to.
                        // Quarantine eviction may only hand a block back to the SAME
                        // heap, so this is what makes eviction safe.
    UINT32  InputIndex; // owning batch run index (the input blamed on a fault)
    BOOLEAN Freed;      // TRUE once a free() has held it
} WINAFL_SAN_ALLOC_META;

//
// One EPT-protected guest-physical page (the reverse map used by the classifier,
// and the restore list). Kind says how to classify a fault landing here.
//
typedef struct _WINAFL_SAN_PAGE_META
{
    UINT64 Gpa;           // page-aligned guest-physical address
    UINT64 OriginalEntry; // PML1 entry to restore at batch end
    UINT32 AllocIndex;    // index into g_SanAllocs
    UINT32 Kind;          // WINAFL_SAN_FAULT_OVERFLOW | WINAFL_SAN_FAULT_UAF
} WINAFL_SAN_PAGE_META;

//
// One in-flight allocation call: captured at the allocator entry, consumed at the
// return-trampoline (post) stub.
//
// Records are keyed by RetSlot -- the STACK ADDRESS whose return slot we overwrote
// with the post stub -- and NOT by stack order. A plain LIFO is wrong here: the
// hooked allocator is ntdll's, so EVERY thread of the target process that is
// scheduled on the pinned core runs through it, and their calls interleave
// arbitrarily. Popping "the last pushed" would then pair a return with another
// thread's OrigSize/RealRA and send the guest to a wild address. The stack slot is
// unique per (thread, frame) and is exactly what the return consumed, so matching on
// it is exact for interleaved and recursive calls alike.
//
typedef struct _WINAFL_SAN_PENDING
{
    UINT64 OrigSize;   // caller's requested size captured at entry
    UINT64 RealRA;     // the caller's real return address (restored at the post stub)
    UINT64 RetSlot;    // guest stack address we planted the stub in (the match key)
    UINT64 HeapHandle; // allocator's 1st arg (RCX), carried into the alloc record
} WINAFL_SAN_PENDING;

static WINAFL_SAN_ALLOC_META g_SanAllocs[WINAFL_SAN_MAX_ALLOCS];
static UINT32                g_SanAllocCount   = 0;
static WINAFL_SAN_PAGE_META  g_SanPages[WINAFL_SAN_MAX_PAGES];
static UINT32                g_SanPageCount    = 0;
static WINAFL_SAN_PENDING    g_SanPending[WINAFL_SAN_MAX_PENDING];
static UINT32                g_SanPendingTop   = 0;

//
// Buffers currently withheld from the allocator (UAF quarantine). Per TARGET PROCESS,
// like g_SanAllocs -- a withheld buffer is withheld until the process dies, so this is
// only cleared by WinaflSanProcessReset. See WINAFL_SAN_MAX_QUARANTINE.
//
static UINT32                g_SanQuarantineCount = 0;

//
// ===================== WHAT WE ARE ALLOWED TO GUARD =========================
//
// Guarding is restricted to allocations made BY THE FUZZED CODE ITSELF: on the fuzz
// thread, between the fuzz-entry hook and the return hook. Everything else runs
// untouched.
//
// This is a correctness requirement, not an optimisation. We hook ntdll's
// RtlAllocateHeap, so without this scope EVERY allocation in the target -- the loader's,
// the CRT's, every worker thread's -- gets handed a REPOSITIONED pointer. Only
// alloc and free are hooked: the moment any of that memory reaches an unhooked heap
// API (RtlReAllocateHeap, RtlSizeHeap, RtlValidateHeap), that API reads a chunk header
// at UserPtr-N which is not a chunk header, and the process dies. Measured: the target
// died and relaunched 8 times in 7 seconds, and each death orphaned no-access guard
// pages that then bug-checked the box.
//
// The fuzzed function's own allocations are the ones a fuzzer cares about anyway.
//
static BOOLEAN g_WinaflInFuzzRun     = FALSE; // between fuzz-entry and return
static UINT64  g_WinaflFuzzThreadId  = 0;     // the thread that runs the fuzz function

//
// ========================= CIRCUIT BREAKER =========================
//
// Every way this sanitizer can go wrong ends the same way: it wedges or kills the
// target, the target dies holding no-access pages, Windows recycles those frames, and
// the box bug-checks. The failure is also self-reinforcing -- a target that dies in
// 200ms relaunches five times a second, each relaunch orphaning more pages.
//
// So the sanitizer counts its own anomalies (unrecoverable post stubs, emergency
// heals) and, past a small threshold, STOPS GUARDING for the rest of the session:
// no new allocation is repositioned or protected. It does NOT stop intercepting
// free() -- pointers already handed out are still shifted and must still be
// un-shifted -- and it never blocks a run. The job degrades into an ordinary fuzzing
// session that happens not to detect anything, which is a far better outcome than
// taking the machine down.
//
#define WINAFL_SAN_MAX_ANOMALIES 8

static BOOLEAN g_SanDisabled  = FALSE;
static UINT32  g_SanAnomalies = 0;

//
// ===================== Sanitizer logging categories ==========================
//
// The sanitizer switch (WINAFL_SAN_KERNEL_VERBOSE) and per-category rate limit
// (WINAFL_SAN_LOG_LIMIT) live with the other logging knobs at the top of the file.
// The g_SanStats counters keep accumulating past that limit and are dumped by the
// per-batch reset summary, so a long run still reports totals after the burst.
//
typedef enum _WINAFL_SAN_LOG_CAT
{
    SAN_LOG_ARM = 0,   // one-shot arm-time configuration dump
    SAN_LOG_ALLOC,     // allocator entry (pre stage)
    SAN_LOG_POST,      // return trampoline (post stage) + guard placement
    SAN_LOG_FREE,      // free entry (hold / pass-through / double-free)
    SAN_LOG_PROTECT,   // EPT protect of one page (incl. failures)
    SAN_LOG_RESET,     // per-batch restore + summary
    SAN_LOG_FAULT,     // classified guard/UAF fault
    SAN_LOG_FOREIGN,   // EPT violation NOT owned by us (passed through)
    SAN_LOG_ERROR,     // give-up / fail-open paths worth seeing every time
    SAN_LOG_CAT_MAX
} WINAFL_SAN_LOG_CAT;

//
// Cumulative counters (never reset by the log limiter; cleared only at arm time).
//
typedef struct _WINAFL_SAN_STATS
{
    UINT64 AllocHooked;       // allocator entries we rerouted
    UINT64 AllocPassed;       // allocator entries we let run untouched
    UINT64 AllocSkippedScope; // allocator entries outside the fuzzed run (not ours to guard)
    UINT64 PostGuarded;    // allocations that got a guard page
    UINT64 PostUnguarded;  // allocations that fell open (no guard)
    UINT64 PostOrphan;     // post-stub hits with an empty pending stack (unrecoverable)
    UINT64 PostSlotMiss;   // post-stub hits whose stack-slot key missed (fell back to LIFO)
    UINT64 XlateFail;      // VA->PA translation failures
    UINT64 ProtectFail;    // VmFuncEptGuardProtectPage failures
    UINT64 FreeHeld;       // frees intercepted + held (UAF mode)
    UINT64 FreePassed;     // frees passed through to the real allocator
    UINT64 FreeForeign;    // frees of pointers we do not track
    UINT64 DoubleFree;         // double-free detections
    UINT64 QuarantineEvicted;  // quarantined buffers handed back to keep detection alive
    UINT64 Faults;         // classified guard/UAF faults
    UINT64 ForeignFaults;  // EPT violations we did not own
} WINAFL_SAN_STATS;

static WINAFL_SAN_STATS g_SanStats = {0};

#if WINAFL_SAN_KERNEL_VERBOSE
static volatile LONG g_SanLogCount[SAN_LOG_CAT_MAX] = {0};

//
// `fmt` is a named parameter for the same reason as WINAFL_KLOG (see the logging
// block at the top of the file): it must reach LogInfo() as a lone string literal,
// never folded into __VA_ARGS__. The (cat) counter rate-limits each category to
// WINAFL_SAN_LOG_LIMIT lines; ##__VA_ARGS__ elides the comma when there are no args.
//
#    define WINAFL_SAN_KLOG(cat, fmt, ...)                                           \
        do                                                                           \
        {                                                                            \
            if (InterlockedIncrement(&g_SanLogCount[(cat)]) <= WINAFL_SAN_LOG_LIMIT) \
                LogInfo(fmt, ##__VA_ARGS__);                                         \
        } while (0)

//
// Reset the per-category log budget (called at arm) so each fuzzing session gets a
// fresh burst of diagnostics instead of staying silent after the first run.
//
static VOID
WinaflSanLogReset(VOID)
{
    UINT32 i;
    for (i = 0; i < SAN_LOG_CAT_MAX; i++)
        g_SanLogCount[i] = 0;
    RtlZeroMemory(&g_SanStats, sizeof(g_SanStats));
}
#else
#    define WINAFL_SAN_KLOG(cat, fmt, ...) ((VOID)0)
static VOID
WinaflSanLogReset(VOID)
{
    RtlZeroMemory(&g_SanStats, sizeof(g_SanStats));
}
#endif

//
// Forward declarations for the sanitizer routines used by the run/park hooks that
// are defined earlier in this file. WinaflSanBatchReset restores every guarded page
// and clears the metadata; it is safe (a no-op) when nothing is protected, so the
// run/park boundaries can call it unconditionally.
//
static VOID    WinaflSanBatchReset(UINT32 CoreId);
static VOID    WinaflSanProcessReset(UINT32 CoreId);
BOOLEAN        WinaflSanHandleEptViolation(UINT32 CoreId, UINT64 ViolationQualification, UINT64 GuestPhysicalAddr);

VOID
WinaflHookSetSharedPage(PWINAFL_HOOK_SHARED Shared)
{
    g_WinaflHookShared = Shared;
}

//
// Register (RCX) input delivery: when armed with RcxDelivery, load the run's
// 8-byte input value into RCX -- the Windows x64 first integer-argument register
// -- just before entering the fuzzed function, so a normal C function
// void f(uint64_t x) receives the input as x. The rest of the entry snapshot is
// left as captured. Bounds-checked against the input table. No-op when
// RcxDelivery is off (classic file-based input).
//
static VOID
WinaflHookLoadInput(PWINAFL_HOOK_SHARED Shared, GUEST_REGS * Regs, UINT32 Index)
{
    if (Shared->RcxDelivery && Index < WINAFL_HOOK_MAX_BATCH)
    {
        Regs->rcx = Shared->BatchInputs[Index];
    }
}

//
// Arm the hooks: pin the fuzzer's WINAFL_HOOK_SHARED page into a system VA that
// is valid from VMX-root in any process context, validate its ABI, and publish
// it. Runs at PASSIVE_LEVEL in the fuzzer's context (the IOCTL caller), which is
// required by MmProbeAndLockPages.
//
NTSTATUS
WinaflHookArm(UINT64 SharedUserVa, UINT32 SharedSize)
{
    PMDL                Mdl;
    PVOID               SystemVa;
    PWINAFL_HOOK_SHARED Shared;

    if (g_WinaflHookShared != NULL || g_WinaflHookMdl != NULL)
    {
        //
        // Already armed; require an explicit disarm first.
        //
        return STATUS_DEVICE_ALREADY_ATTACHED;
    }

    if (SharedUserVa == (UINT64)NULL || SharedSize < sizeof(WINAFL_HOOK_SHARED))
    {
        return STATUS_INVALID_PARAMETER;
    }

    Mdl = IoAllocateMdl((PVOID)SharedUserVa, SharedSize, FALSE, FALSE, NULL);
    if (Mdl == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try
    {
        //
        // Lock the user pages (write access: the kernel updates Status/snapshot).
        //
        MmProbeAndLockPages(Mdl, UserMode, IoModifyAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        IoFreeMdl(Mdl);
        return STATUS_ACCESS_VIOLATION;
    }

    //
    // Resolve a non-paged system VA for the locked pages. MdlMappingNoExecute is
    // correct for a pure data page and satisfies modern WDK requirements.
    //
    SystemVa = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
    if (SystemVa == NULL)
    {
        MmUnlockPages(Mdl);
        IoFreeMdl(Mdl);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Validate the ABI before trusting any field the hooks will read.
    //
    Shared = (PWINAFL_HOOK_SHARED)SystemVa;
    if (Shared->Version != WINAFL_HOOK_ABI_VERSION ||
        Shared->StructSize != sizeof(WINAFL_HOOK_SHARED))
    {
        MmUnlockPages(Mdl);
        IoFreeMdl(Mdl);
        return STATUS_REVISION_MISMATCH;
    }

    Shared->Status = WINAFL_STATUS_ARMED;

    //
    // Fresh session: clear any stale batch state left by a previous run that was
    // torn down mid-batch (crash/hang truncation). Every GO/GO_BATCH re-inits this
    // anyway, but reset defensively so a stray return hook can't misbehave.
    //
    g_WinaflBatchActive = FALSE;
    g_WinaflBatchIndex  = 0;

    WINAFL_KLOG("[winafl] armed: shared=0x%llx fuzz=0x%llx park=0x%llx pid=%u rcx=%u",
                (UINT64)Shared, Shared->FuzzAddress, Shared->ParkStubAddress,
                Shared->TargetProcessId, Shared->RcxDelivery);

    //
    // Sanitizer: give this session a fresh log budget and dump the resolved
    // configuration so a bring-up log always starts with the exact hook set.
    //
    // DO NOT clear g_SanPages/g_SanAllocs here. Arming runs at PASSIVE_LEVEL, where
    // restoring EPT entries (INVEPT) is illegal, so if a previous target was torn
    // down mid-batch its pages are still no-access. Those entries are the ONLY
    // record of how to put them back; the first VMX-root touchpoint of the new
    // target (WinaflHookOnEntry -> WinaflSanBatchReset) uses them to heal the
    // orphaned frames. Zeroing the counters here would strand them permanently.
    //
    WinaflSanLogReset();

    //
    // Start all-core (default). The pinned core is only known once the target hits
    // the fuzz entry, so WinaflHookOnEntry narrows the scope to that core. Any hooks
    // registered before then (the fuzz-entry hook) are in the target's private image,
    // so all-core installs of them are harmless (no other process maps those pages).
    //
    VmFuncEptHookSetForceSingleCore(-1);

    if (g_SanPageCount != 0)
    {
        WINAFL_SAN_KLOG(SAN_LOG_ARM,
                        "[san] arm: %u page(s) still protected from a previous target -- they will be "
                        "restored at the first VMX-root hook of this run",
                        g_SanPageCount);
    }

    if (Shared->SanitizeFlags != 0)
    {
        UINT32 i;
        WINAFL_SAN_KLOG(SAN_LOG_ARM,
                        "[san] armed: flags=0x%x (overflow=%u uaf=%u) redzone=0x%x poststub=0x%llx allocators=%u",
                        Shared->SanitizeFlags,
                        (Shared->SanitizeFlags & WINAFL_SAN_OVERFLOW) ? 1 : 0,
                        (Shared->SanitizeFlags & WINAFL_SAN_UAF) ? 1 : 0,
                        WINAFL_SAN_REDZONE,
                        Shared->PostStubAddress,
                        Shared->SanAllocatorCount);

        for (i = 0; i < Shared->SanAllocatorCount && i < WINAFL_SAN_MAX_ALLOCATORS; i++)
        {
            WINAFL_SAN_KLOG(SAN_LOG_ARM,
                            "[san]   allocator[%u]: addr=0x%llx kind=%u (1=alloc 2=free) argreg=%u "
                            "retbool=%u flagsreg=%u zeroflag=0x%llx",
                            i,
                            Shared->SanAllocators[i].Address,
                            Shared->SanAllocators[i].Kind,
                            Shared->SanAllocators[i].ArgReg,
                            Shared->SanAllocators[i].RetIsBool,
                            Shared->SanAllocators[i].FlagsReg,
                            Shared->SanAllocators[i].ZeroFlag);
        }

        //
        // The guard page can only be protected if it has a physical frame behind it,
        // and heap memory is demand-zero. Without a forced zero flag on an allocator,
        // its redzone is never written, so VA->PA of the guard page returns 0 and
        // every overflow in that allocator's buffers is missed. This is the single
        // most common reason for "the sanitizer never fires", so say it at arm time
        // rather than leaving it to be inferred from a pile of XLATE-FAIL lines.
        //
        if (Shared->SanitizeFlags & WINAFL_SAN_OVERFLOW)
        {
            for (i = 0; i < Shared->SanAllocatorCount && i < WINAFL_SAN_MAX_ALLOCATORS; i++)
            {
                if (Shared->SanAllocators[i].Kind == WINAFL_SAN_FN_ALLOC &&
                    Shared->SanAllocators[i].ZeroFlag == 0)
                {
                    WINAFL_SAN_KLOG(SAN_LOG_ARM,
                                    "[san] *** WARNING: allocator[%u] (0x%llx) has no zero flag -- its redzone "
                                    "stays demand-zero, so guard pages will fail to translate and overflows "
                                    "will be MISSED ***",
                                    i, Shared->SanAllocators[i].Address);
                }
            }
        }

        //
        // Loud warning for the configuration that corrupts the guest heap: we hand
        // the caller a REPOSITIONED pointer when overflow guarding is on, but only
        // intercept free() when UAF is on. With UAF off, the app's free() reaches
        // the real allocator holding a pointer that is not a heap block base.
        //
        if ((Shared->SanitizeFlags & WINAFL_SAN_OVERFLOW) && !(Shared->SanitizeFlags & WINAFL_SAN_UAF))
        {
            WINAFL_SAN_KLOG(SAN_LOG_ARM,
                            "[san] *** WARNING: overflow-only mode repositions allocations but does NOT "
                            "intercept free() -- the real allocator will receive shifted pointers ***");
        }
    }

    //
    // Publish last: once g_WinaflHookShared is non-NULL the hooks are live.
    //
    g_WinaflHookMdl    = Mdl;
    g_WinaflHookShared = Shared;

    return STATUS_SUCCESS;
}

//
// Disarm the hooks and release the pinned page. The hooks read g_WinaflHookShared
// first thing and treat NULL as "inert", so clearing it before unlocking makes
// teardown safe (the v1 target runs single-threaded on its pinned core and is
// parked or dead by the time the fuzzer disarms).
//
VOID
WinaflHookDisarm()
{
    PMDL Mdl = g_WinaflHookMdl;

    g_WinaflHookShared = NULL;
    g_WinaflHookMdl    = NULL;

    //
    // Release the single-core exec-hook scoping so any later (non-WinAFL) hooks
    // install on all cores again.
    //
    VmFuncEptHookSetForceSingleCore(-1);

    if (Mdl != NULL)
    {
        MmUnlockPages(Mdl);
        IoFreeMdl(Mdl);
    }
}

//
// Wake the fuzzer with a WINAFL_HOOK_TAG. The per-iteration detail already lives
// in the shared page; the tag only says *why* we woke it. This is the same
// immediate-buffer path ScriptEngineFunctionMasoudCallback uses, so it is safe
// from the VMX-root event-trigger context.
//
static VOID
WinaflHookNotify(UINT64 Tag)
{
    LogCallbackSendBuffer(OPERATION_MASOUD_CALLBACK, &Tag, sizeof(Tag), TRUE);
}

//
// Dump the guest GP registers + the top of the guest stack at a hook transition.
// Used during bring-up to confirm the per-iteration rewind keeps the stack
// consistent: RSP and the saved return address at [rsp] must be IDENTICAL on
// every iteration -- any drift here is the "stack corruption" we are watching
// for. The stack is read through the CR3-aware safe mapper so a bad RSP cannot
// fault us in VMX-root.
//
static VOID
WinaflHookLogState(const char * Where, GUEST_REGS * Regs)
{
#if WINAFL_HOOK_KERNEL_VERBOSE
    UINT64  Stack[6] = {0};
    BOOLEAN StackOk  = MemoryMapperReadMemorySafeOnTargetProcess(Regs->rsp, Stack, sizeof(Stack));

    LogInfo("[winafl] %s regs: rsp=0x%llx rbp=0x%llx rax=0x%llx rcx=0x%llx rdx=0x%llx r8=0x%llx r9=0x%llx",
            Where, Regs->rsp, Regs->rbp, Regs->rax, Regs->rcx, Regs->rdx, Regs->r8, Regs->r9);

    if (StackOk)
        LogInfo("[winafl] %s stack@rsp: [0]=0x%llx [1]=0x%llx [2]=0x%llx [3]=0x%llx [4]=0x%llx [5]=0x%llx",
                Where, Stack[0], Stack[1], Stack[2], Stack[3], Stack[4], Stack[5]);
    else
        LogInfo("[winafl] %s stack@rsp=0x%llx: <unreadable>", Where, Regs->rsp);
#else
    UNREFERENCED_PARAMETER(Where);
    UNREFERENCED_PARAMETER(Regs);
#endif
}

//
// Capture the state we rewind to every iteration. For a file-based v1 harness the
// arguments do not change between runs, so the GP registers + RSP + the return
// address (read from [rsp]) fully reconstitute the call. (Callconv-aware argument
// capture into SavedArgs[] is deferred to v1.2's register/memory input delivery.)
//
static VOID
WinaflHookSnapshotEntry(PWINAFL_HOOK_SHARED Shared, GUEST_REGS * Regs)
{
    UINT64 ReturnAddress = 0;

    //
    // GUEST_REGS and WINAFL_HOOK_REGS share an identical layout (rax..r15), so a
    // straight copy captures every GP register, including rsp.
    //
    RtlCopyMemory(&Shared->SavedRegs, Regs, sizeof(WINAFL_HOOK_REGS));
    Shared->SavedRsp = Regs->rsp;

    //
    // The return address is the top of the guest stack at entry. Read it through
    // the safe, CR3-aware mapper so a bad stack pointer cannot fault us in root.
    //
    if (MemoryMapperReadMemorySafeOnTargetProcess(Regs->rsp, &ReturnAddress, sizeof(ReturnAddress)))
    {
        Shared->ReturnAddress = ReturnAddress;
    }
}

//
// Park the guest: reset RSP to the saved entry value and point RIP at the spin
// stub. The stub is stackless, so SavedRsp simply keeps RSP on the real stack.
//
// The redirect is honoured by HyperDbg's !epthook machinery: the EPT-hook
// breakpoint handler (EptCheckAndHandleBreakpoint in hyperhv/.../Ept.c) calls
// HvSuppressRipIncrement() before triggering our event and never re-writes
// GUEST_RIP afterwards, so our VmFuncSetRip() is the last writer and takes
// effect on VM-entry. The subsequent MTF only re-arms the hooked page.
//
static VOID
WinaflHookPark(PWINAFL_HOOK_SHARED Shared)
{
    //
    // Parking always ends a run, whatever got us here (normal finish, crash report,
    // orphaned post stub). Clearing the guard scope here means no path can leave it
    // set while the guest is not executing fuzzed code.
    //
    g_WinaflInFuzzRun = FALSE;

    SetGuestRSP(Shared->SavedRsp);
    VmFuncSetRip(Shared->ParkStubAddress);
}

//
// Hit on the fuzzed function entry.
//
static BOOLEAN
WinaflHookOnEntry(UINT32 CoreId, PWINAFL_HOOK_SHARED Shared, GUEST_REGS * Regs)
{
    if (!Shared->FirstHitDone)
    {
        //
        // First ever entry: capture the rewind snapshot + the return address,
        // tell the fuzzer (so it can install the return-address hook AND drop
        // this entry hook), and park until it releases us. We must NOT run the
        // function before the return hook is installed, or we would miss the
        // epilogue.
        //
        // Also clear any sanitizer guard pages left over from a previous (possibly
        // torn-down) target: restoring them here, at the first VMX-root touchpoint
        // of the fresh process, heals orphaned no-access frames before they can be
        // reused. (A no-op when nothing is protected.)
        //
        // This is the ONE place the reposition records are dropped too: the target is
        // brand new, so no guest pointer from the previous one can still be live. Every
        // other boundary uses WinaflSanBatchReset, which keeps them (see the lifetime
        // model above) -- dropping them mid-process is what lets a shifted pointer reach
        // the real allocator and corrupt the guest heap.
        //
        WinaflSanProcessReset(CoreId);

        //
        // We are now running on the target's PINNED core (the target's affinity
        // restricts it to one core, so the fuzz-entry #BP always fires here). If the
        // sanitizer is armed, scope every subsequently-registered exec hook -- the
        // return hook and, crucially, the ntdll allocator hooks -- to THIS core only.
        // The allocators live in shared ntdll, so hooking them on all cores would
        // trap every process's heap call system-wide (2 VM-exits each) and make the
        // whole box unresponsive. Hooking only the pinned core catches all of the
        // target's calls while leaving every other core (and process) untouched.
        //
        if (Shared->SanitizeFlags != 0)
            VmFuncEptHookSetForceSingleCore((INT32)CoreId);

        WinaflHookSnapshotEntry(Shared, Regs);
        Shared->FirstHitDone = 1;
        Shared->Status       = WINAFL_STATUS_ENTRY;
        WINAFL_KLOG("[winafl] ENTRY (first hit): snapshot captured, return=0x%llx park=0x%llx",
                    Shared->ReturnAddress, Shared->ParkStubAddress);
        WinaflHookLogState("ENTRY", Regs);
        WinaflHookNotify(WINAFL_TAG_ENTRY);
        WinaflHookPark(Shared);
        return TRUE; // handled in kernel: skip user-mode actions + epilogue
    }

    //
    // One-hook-at-a-time design: after the first hit the fuzzer removes this
    // entry breakpoint (it shares a physical page with the return address, and
    // two hidden-CC breakpoints on one page was crashing the dry run). Every
    // later iteration is released from the park stub, which restores the snapshot
    // and jumps here directly -- so we should never re-enter via a breakpoint. If
    // we do, the entry CC was left in place: log loudly, restore the snapshot,
    // and let it run so the guest is not wedged.
    //
    WINAFL_KLOG("[winafl] WARNING: unexpected later ENTRY breakpoint (entry CC should have been removed)");
    RtlCopyMemory(Regs, &Shared->SavedRegs, sizeof(WINAFL_HOOK_REGS));
    SetGuestRSP(Shared->SavedRsp);
    WinaflHookLogState("ENTRY(late)", Regs);
    return TRUE;
}

//
// Hit on the captured return address: the iteration finished. Returning FALSE
// asks the dispatcher to run the (empty) event actions and then call
// MasoudEpilogue, where we rewind + park.
//
static BOOLEAN
WinaflHookOnReturn(UINT32 CoreId, PWINAFL_HOOK_SHARED Shared, GUEST_REGS * Regs)
{
    //
    // The fuzzed function has returned: stop treating this thread's allocations as
    // guardable until the next run is released. (Re-set below for a batch re-entry.)
    //
    g_WinaflInFuzzRun = FALSE;

    //
    // ---- Batched run (WINAFL_CMD_GO_BATCH) ----
    // Run BatchCount inputs back-to-back. PT stays enabled across the whole batch
    // (the ring accumulates every run), and at each return boundary we record the
    // CUMULATIVE PT write offset for the run that just finished. If more runs
    // remain we DO NOT pause/park: restore the entry snapshot, load the next RCX
    // input, and jump straight back to the fuzz entry. Only after the last run do
    // we pause PT, park, and notify the fuzzer once (BATCH_DONE).
    //
    if (g_WinaflBatchActive)
    {
        UINT32 i = g_WinaflBatchIndex;

        //
        // PAUSE tracing on THIS core BEFORE reading the offset. Disabling TraceEn
        // flushes PT's internally-buffered packets out to the ToPA output buffer, so
        // the offset then reflects ALL of this run's packets. Reading it while
        // tracing is still live returns a stale offset (the run's last packets are
        // not yet in the buffer), which truncated each segment and bled bytes into
        // the next one -- causing the decoder's "can't sync" errors and the low
        // stability. It also means the inter-run gap (return hook, snapshot restore,
        // VM transitions) is not traced into the next run's segment. Pause/resume
        // preserve the ring offset (HyperTracePtResumeCurrentCore does not rewind
        // MASK_PTRS), so the cumulative-offset model still holds.
        //
        HyperTracePtPauseCurrentCore();

        if (i < WINAFL_HOOK_MAX_BATCH)
        {
            Shared->SegmentSize[i]   = HyperTracePtSizeCurrentCore();
            Shared->SegmentStatus[i] = WINAFL_STATUS_ITER_DONE;
        }

        g_WinaflBatchIndex   = ++i;
        Shared->SegmentCount = i;              // publish progress (crash/hang truncation reads this)
        Shared->IterationCount++;

        if (i < Shared->BatchCount)
        {
            //
            // More runs remain: restore the snapshot, load the next input, RESUME
            // tracing, then re-enter the fuzz entry. Resuming AFTER the register/RSP
            // restore means only the run's own instructions are traced. The return
            // hook is a #BP epthook, so EptCheckAndHandleBreakpoint already
            // suppressed the RIP increment -- our VmFuncSetRip is the last writer.
            //
            //
            // Release this run's guard pages before starting the next one. Protections
            // are restored PER RUN, not per batch, on purpose: a target that dies while
            // pages are still no-access orphans those frames, and Windows then hands
            // them to another process -- which is what bug-checks the box. Per-run
            // restore keeps that window one iteration wide instead of a whole batch
            // (~100x smaller). A bug in persistent fuzzing manifests within the run that
            // triggered it, so nothing detectable is lost.
            //
            WinaflSanBatchReset(CoreId);

            RtlCopyMemory(Regs, &Shared->SavedRegs, sizeof(WINAFL_HOOK_REGS));
            SetGuestRSP(Shared->SavedRsp);
            WinaflHookLoadInput(Shared, Regs, i);
            HyperTracePtResumeCurrentCore();
            g_WinaflInFuzzRun = TRUE; // next run starts here: its allocations are guardable
            VmFuncSetRip(Shared->FuzzAddress);
            return TRUE; // handled in kernel: skip the (empty) action + epilogue
        }

        //
        // Last run of the batch: PT is already paused above; just park the guest and
        // wake the fuzzer once. End-of-batch: restore all sanitizer guard pages (held
        // freed buffers are released here) so the target's frames are RWX again.
        //
        g_WinaflBatchActive = FALSE;
        WinaflSanBatchReset(CoreId);
        Shared->Status      = WINAFL_STATUS_ITER_DONE;
        WINAFL_KLOG("[winafl] BATCH done: %u runs (PT paused, parking)", Shared->BatchCount);
        WinaflHookPark(Shared);
        WinaflHookNotify(WINAFL_TAG_BATCH_DONE);
        return TRUE; // handled in kernel
    }

    //
    // ---- Single run (WINAFL_CMD_GO) ----
    // The iteration has returned: stop tracing immediately, on THIS (pinned) core,
    // before we rewind + park. Current-core RTIT_CTL toggle only (no DPC/log), so
    // it is valid here in VMX-root. Bracketing PT in the hooks -- not from a
    // user-mode IOCTL after the async ITER_DONE notification -- captures exactly
    // this iteration with no resume/pause race clipping the start or trailing end.
    //
    HyperTracePtPauseCurrentCore();

    Shared->IterationCount++;
    Shared->Status = WINAFL_STATUS_ITER_DONE;
    //
    // End of a single run (a batch of one for sanitizer purposes): release any guard
    // pages / held freed buffers from this run.
    //
    WinaflSanBatchReset(CoreId);
    WINAFL_KLOG("[winafl] RETURN breakpoint: iteration %lld returned (PT paused)", Shared->IterationCount);
    WinaflHookLogState("RETURN", Regs);
    return FALSE; // run the (empty) event action, then MasoudEpilogue rewinds + parks
}

//
// Park poll via CPUID (replaces the old epthook-on-a-spin-stub park). The parked
// guest runs a delay loop and executes CPUID, which forces a VM-exit; we get here
// from the CPUID dispatch (DebuggerTriggerEvents' CPUID case). The delay loop means
// ONE VM-exit per ~1M iterations instead of an epthook #BP every couple of
// instructions -- far less overhead while waiting for GO.
//
// Returns TRUE iff this was our park CPUID AND we released/teared-down the guest
// (RIP redirected); the caller then short-circuits so HvHandleCpuid does NOT also
// advance RIP. Returns FALSE for "not our CPUID" or "still idle" so the caller lets
// normal CPUID emulation run (advancing RIP -> the guest loops back through the
// delay and polls again).
//
static BOOLEAN
WinaflHookOnParkCpuid(PROCESSOR_DEBUGGING_STATE * DbgState)
{
    PWINAFL_HOOK_SHARED Shared = g_WinaflHookShared;
    UINT64              Rip;

    if (Shared == NULL)
        return FALSE;

    //
    // Is this CPUID our park stub? The stub is a tiny, isolated VirtualAllocEx page
    // ([delay loop][cpuid][jmp]); any CPUID with RIP inside it is a park poll. Other
    // CPUIDs in the target (CRT, etc.) have RIP elsewhere -> not ours.
    //
    Rip = VmFuncGetRip();
    if (Rip < Shared->ParkStubAddress || Rip >= Shared->ParkStubAddress + 0x40)
        return FALSE;

    if (Shared->Command == WINAFL_CMD_GO || Shared->Command == WINAFL_CMD_GO_BATCH)
    {
        BOOLEAN Batch = (Shared->Command == WINAFL_CMD_GO_BATCH);

        //
        // Release into the next run: restore the snapshotted GP registers + RSP (RSP
        // must go through SetGuestRSP -- it is VMCS state), optionally load the input
        // into RCX, resume PT on this pinned core, and jump straight to the fuzz
        // entry. The caller short-circuits the event so HvHandleCpuid does not
        // advance RIP over our redirect.
        //
        // GO_BATCH additionally arms the return-hook batch loop: it runs BatchInputs
        // [0..BatchCount) back-to-back before parking + notifying BATCH_DONE.
        //
        Shared->Command = WINAFL_CMD_IDLE;
        RtlCopyMemory(DbgState->Regs, &Shared->SavedRegs, sizeof(WINAFL_HOOK_REGS));
        SetGuestRSP(Shared->SavedRsp);

        //
        // Start each run/batch with a clean sanitizer slate (idempotent; the batch
        // end already restored, so this only matters if a prior batch was cut short).
        //
        WinaflSanBatchReset(DbgState->CoreId);

        if (Batch)
        {
            //
            // Defence in depth: never let a bad BatchCount index past the segment
            // tables (the user side already clamps, but this runs in VMX-root).
            //
            if (Shared->BatchCount > WINAFL_HOOK_MAX_BATCH)
                Shared->BatchCount = WINAFL_HOOK_MAX_BATCH;

            g_WinaflBatchActive  = TRUE;
            g_WinaflBatchIndex   = 0;
            Shared->SegmentCount = 0;
        }
        else
        {
            g_WinaflBatchActive = FALSE;
        }

        WinaflHookLoadInput(Shared, DbgState->Regs, 0); // run 0 uses BatchInputs[0]

        WINAFL_KLOG("[winafl] park(cpuid): %s -> resume at fuzz=0x%llx (iter=%lld)",
                    Batch ? "GO_BATCH" : "GO", Shared->FuzzAddress, Shared->IterationCount);
        HyperTracePtResumeCurrentCore();

        //
        // The run starts here, on THIS thread: from now until the return hook, this
        // thread's allocations are the fuzzed code's own and may be guarded.
        //
        g_WinaflFuzzThreadId = (UINT64)PsGetCurrentThreadId();
        g_WinaflInFuzzRun    = TRUE;

        VmFuncSetRip(Shared->FuzzAddress);
        //
        // CRITICAL: suppress the VM-exit framework's default RIP increment. Unlike
        // the EPT-hook (#BP) path -- where EptCheckAndHandleBreakpoint already calls
        // HvSuppressRipIncrement -- the CPUID exit leaves IncrementRip=TRUE, so
        // without this the framework would advance our redirected RIP by the CPUID
        // length (FuzzAddress -> FuzzAddress+2), landing mid-instruction and running
        // garbage. ShortCircuitingEvent (below) only skips HvHandleCpuid's
        // emulation/reg-clobber; it does NOT stop the framework increment.
        //
        VmFuncSuppressRipIncrement(DbgState->CoreId);
        DbgState->ShortCircuitingEvent = TRUE;
        return TRUE;
    }

    if (Shared->Command == WINAFL_CMD_STOP)
    {
        //
        // Tear down: restore the snapshot, resume normally from the fuzz entry, and
        // disarm so the hooks become inert again.
        //
        Shared->Command = WINAFL_CMD_IDLE;
        RtlCopyMemory(DbgState->Regs, &Shared->SavedRegs, sizeof(WINAFL_HOOK_REGS));
        SetGuestRSP(Shared->SavedRsp);
        WINAFL_KLOG("[winafl] park(cpuid): STOP -> disarm, resume at fuzz=0x%llx", Shared->FuzzAddress);
        VmFuncSetRip(Shared->FuzzAddress);
        VmFuncSuppressRipIncrement(DbgState->CoreId); // see GO branch
        g_WinaflHookShared = NULL;
        DbgState->ShortCircuitingEvent = TRUE;
        return TRUE;
    }

    //
    // WINAFL_CMD_IDLE: keep spinning -- but DO NOT let the event's script action
    // (masoud_callback(0)) run. Returning FALSE here would fall through to
    // DebuggerPerformActions, which fires a VMX-root kernel->user notification on
    // EVERY park poll (thousands/sec while we wait for GO). That flood (a) is the
    // same VMX-root message-flood pattern that bug-checked the box before, and
    // (b) races/displaces the real ITER_DONE notification in the message buffer,
    // so the user-mode wait times out even though the kernel finished the iteration.
    //
    // Instead short-circuit the event (ShortCircuitingEvent + return TRUE -> the
    // caller `continue`s, skipping both the script action AND HvHandleCpuid) but do
    // NOT call VmFuncSuppressRipIncrement: the VM-exit framework's default
    // IncrementRip then advances RIP past the CPUID (2 bytes), so the stub's delay
    // loop simply continues and polls again on the next pass. Skipping HvHandleCpuid
    // is safe -- the park stub issues CPUID purely as a vmexit trigger and never
    // reads the result registers.
    //
    DbgState->ShortCircuitingEvent = TRUE;
    return TRUE;
}

//
// ==================== WinAFL EPT guard-page sanitizer =======================
//
// The routines below implement heap-overflow + use-after-free detection. They are
// only reached when the fuzzer arms with SanitizeFlags != 0 and registers the
// allocator + return-stub !epthooks; MasoudPrologue routes those hits here.
//

//
// Map a WINAFL_SAN_REG to the matching field in the guest GP register block, so we
// can read/patch a call's size or pointer argument by its calling-convention slot.
//
static UINT64 *
WinaflSanRegPtr(GUEST_REGS * Regs, UINT32 Reg)
{
    switch (Reg)
    {
    case WINAFL_SAN_REG_RCX:
        return &Regs->rcx;
    case WINAFL_SAN_REG_RDX:
        return &Regs->rdx;
    case WINAFL_SAN_REG_R8:
        return &Regs->r8;
    case WINAFL_SAN_REG_R9:
        return &Regs->r9;
    default:
        return NULL;
    }
}

//
// Find a registered allocator/free function by its entry VA (NULL if none / off).
//
static WINAFL_SAN_ALLOCATOR *
WinaflSanFindAllocatorByAddr(PWINAFL_HOOK_SHARED Shared, UINT64 Va)
{
    UINT32 i;

    if (Shared->SanitizeFlags == 0)
        return NULL;

    for (i = 0; i < Shared->SanAllocatorCount && i < WINAFL_SAN_MAX_ALLOCATORS; i++)
    {
        if (Shared->SanAllocators[i].Kind != WINAFL_SAN_FN_NONE &&
            Shared->SanAllocators[i].Address == Va)
        {
            return &Shared->SanAllocators[i];
        }
    }

    return NULL;
}

//
// Look up a guarded allocation by the pointer we handed the caller (-1 if none).
//
// NEWEST FIRST. Records now live for the whole target process, so the heap can hand
// the same address out again after a real free; the youngest record is the live one.
// Scanning forwards would find a stale, already-freed record and misreport the next
// legitimate free of that address as a double free. It is also the faster order:
// allocate-then-free-soon is the common shape, so the match is usually a few entries
// from the end.
//
static int
WinaflSanFindAllocByUserPtr(UINT64 UserPtr)
{
    UINT32 i;

    for (i = g_SanAllocCount; i > 0; i--)
    {
        if (g_SanAllocs[i - 1].UserPtr == UserPtr)
            return (int)(i - 1);
    }

    return -1;
}

//
// Pick the buffer to hand back to the allocator when the quarantine is full.
//
// OLDEST FIRST (FIFO): the whole point of a quarantine is to keep recently-freed
// memory poisoned for as long as possible, so the buffer freed longest ago is the one
// whose detection value has already expired.
//
// A candidate must be (a) still tracked, (b) already freed/quarantined -- never a live
// allocation the guest still holds a pointer to -- and (c) from the SAME heap as the
// call that is about to run, since that call is what will free it. ExcludeIdx keeps the
// record being quarantined right now out of the running.
//
static int
WinaflSanFindEvictionCandidate(UINT64 HeapHandle, int ExcludeIdx)
{
    UINT32 i;

    for (i = 0; i < g_SanAllocCount; i++)
    {
        if ((int)i == ExcludeIdx)
            continue;
        if (g_SanAllocs[i].UserPtr == 0)
            continue; // tombstoned: already back with the allocator
        if (!g_SanAllocs[i].Freed)
            continue; // live allocation -- freeing it would be a use-after-free WE caused
        if (g_SanAllocs[i].HeapHandle != HeapHandle)
            continue; // different heap: freeing it here would corrupt both

        return (int)i;
    }

    return -1;
}

//
// Index returned by WinaflSanPeekSlot when the table is exhausted.
//
#define WINAFL_SAN_NO_SLOT 0xFFFFFFFFu

//
// The record slot the next tracked allocation WOULD use, without committing to it
// (the caller only commits if the guard actually goes down). Prefers a fresh append
// and otherwise recycles a tombstoned record -- one whose chunk the heap has already
// taken back, so no guest pointer can still refer to it. Without recycling, a target
// that allocates for hours would exhaust the table and silently stop detecting.
//
static UINT32
WinaflSanPeekSlot(VOID)
{
    UINT32 i;

    if (g_SanAllocCount < WINAFL_SAN_MAX_ALLOCS)
        return g_SanAllocCount;

    for (i = 0; i < g_SanAllocCount; i++)
    {
        if (g_SanAllocs[i].UserPtr == 0)
            return i;
    }

    return WINAFL_SAN_NO_SLOT;
}

//
// Retire (tombstone) every stale record covering memory the allocator has just handed
// out again, i.e. a chunk we previously un-repositioned and really freed. Keeping a
// stale but still-keyed record would let a free of the NEW allocation match the OLD
// one and be misreported as a double free -- and, once records outlive a batch, those
// stale records accumulate for the life of the process.
//
// Matching is by CONTAINMENT, not just an equal base: the heap is free to split or
// coalesce what it reclaimed, so the reused chunk often comes back under a different
// base that still covers the old buffer. Any address inside the newly-returned chunk
// provably belongs to this allocation now, so an older record keyed there is dead.
//
// Only records already marked Freed are retired. A record that is still live cannot
// legitimately overlap a fresh allocation, and tombstoning one would strand the
// guest's repositioned pointer with no way to un-shift it at free time.
//
static VOID
WinaflSanRetireStaleRecords(UINT64 RealBase, UINT64 ChunkSize)
{
    UINT64 End = RealBase + ChunkSize;
    UINT32 i;

    for (i = 0; i < g_SanAllocCount; i++)
    {
        if (g_SanAllocs[i].UserPtr == 0 || !g_SanAllocs[i].Freed)
            continue;

        if (g_SanAllocs[i].RealBase == RealBase ||
            (g_SanAllocs[i].UserPtr >= RealBase && g_SanAllocs[i].UserPtr < End))
        {
            g_SanAllocs[i].UserPtr = 0; // tombstone: no future lookup matches it
        }
    }
}

//
// Force one guest-virtual page to no-access via EPT, recording the reverse map
// (GPA -> alloc + kind) used by the classifier and the restore list. Physical
// pages of a multi-page range are non-contiguous, so callers protect page by page.
// Returns FALSE (fail open) if the page is not present or a table is full.
//
static BOOLEAN
WinaflSanProtectPage(UINT32 CoreId, UINT64 Va, UINT32 AllocIndex, UINT32 Kind)
{
    UINT64 Gpa  = (UINT64)VirtualAddressToPhysicalAddressOnTargetProcess((PVOID)WINAFL_SAN_PAGE_DOWN(Va));
    UINT64 Orig = 0;
    UINT32 i;

    if (Gpa == 0)
    {
        g_SanStats.XlateFail++;
        //
        // PROTECT, not ERROR. This is a routine fail-open that fires often, and in the
        // ERROR category it ate that budget (69 of 72 lines in one run) and starved the
        // rare, loud events that share it -- post-stub ORPHAN especially. Losing the one
        // line that explains a fabricated crash to a flood of routine ones made a real
        // bug undiagnosable.
        //
        WINAFL_SAN_KLOG(SAN_LOG_PROTECT,
                        "[san] protect XLATE-FAIL: va=0x%llx (page 0x%llx) kind=%u idx=%u -- page not present, failing open",
                        Va, WINAFL_SAN_PAGE_DOWN(Va), Kind, AllocIndex);
        return FALSE; // page not present -> cannot guard
    }

    Gpa = WINAFL_SAN_PAGE_DOWN(Gpa);

    //
    // Already protecting this physical page? Just (re)tag it -- e.g. a free() of a
    // buffer re-tags its data pages OVERFLOW->UAF.
    //
    for (i = 0; i < g_SanPageCount; i++)
    {
        if (g_SanPages[i].Gpa == Gpa)
        {
            WINAFL_SAN_KLOG(SAN_LOG_PROTECT,
                            "[san] protect RETAG: va=0x%llx gpa=0x%llx kind %u->%u idx %u->%u",
                            Va, Gpa, g_SanPages[i].Kind, Kind, g_SanPages[i].AllocIndex, AllocIndex);
            g_SanPages[i].AllocIndex = AllocIndex;
            g_SanPages[i].Kind       = Kind;
            VmFuncEptGuardProtectPage(CoreId, Gpa, &Orig);
            return TRUE;
        }
    }

    if (g_SanPageCount >= WINAFL_SAN_MAX_PAGES)
    {
        WINAFL_SAN_KLOG(SAN_LOG_ERROR,
                        "[san] protect TABLE-FULL: va=0x%llx gpa=0x%llx (%u pages) -- failing open",
                        Va, Gpa, g_SanPageCount);
        return FALSE; // table full -> fail open
    }

    if (!VmFuncEptGuardProtectPage(CoreId, Gpa, &Orig))
    {
        g_SanStats.ProtectFail++;
        WINAFL_SAN_KLOG(SAN_LOG_ERROR,
                        "[san] protect EPT-FAIL: va=0x%llx gpa=0x%llx kind=%u (split/pml1 failure) -- failing open",
                        Va, Gpa, Kind);
        return FALSE;
    }

    g_SanPages[g_SanPageCount].Gpa           = Gpa;
    g_SanPages[g_SanPageCount].OriginalEntry = Orig;
    g_SanPages[g_SanPageCount].AllocIndex    = AllocIndex;
    g_SanPages[g_SanPageCount].Kind          = Kind;
    g_SanPageCount++;

    WINAFL_SAN_KLOG(SAN_LOG_PROTECT,
                    "[san] protect OK: va=0x%llx gpa=0x%llx kind=%u idx=%u orig=0x%llx (pages=%u)",
                    Va, Gpa, Kind, AllocIndex, Orig, g_SanPageCount);
    return TRUE;
}

//
// Protect every page in [StartVa, EndVa) (used to hold a freed buffer's data pages).
//
static VOID
WinaflSanProtectRange(UINT32 CoreId, UINT64 StartVa, UINT64 EndVa, UINT32 AllocIndex, UINT32 Kind)
{
    UINT64 Va;

    for (Va = WINAFL_SAN_PAGE_DOWN(StartVa); Va < EndVa; Va += PAGE_SIZE)
        WinaflSanProtectPage(CoreId, Va, AllocIndex, Kind);
}

//
// Restore + drop just ONE allocation's protected pages (identified by its index in
// g_SanAllocs). Used when a repositioned allocation must be handed back to the real
// allocator mid-batch (overflow-only free): its guard page has to become RWX and
// leave g_SanPages before the frame returns to the heap, or the heap's reuse of it
// would fault into our classifier. Swap-with-last removal is safe -- nothing indexes
// g_SanPages by position (the classifier scans by GPA, the reset walks all entries).
// VMX-root only.
//
static VOID
WinaflSanUnprotectAlloc(UINT32 CoreId, UINT32 AllocIndex)
{
    UINT32 i = 0;

    while (i < g_SanPageCount)
    {
        if (g_SanPages[i].AllocIndex == AllocIndex)
        {
            VmFuncEptGuardRestorePage(CoreId, g_SanPages[i].Gpa, g_SanPages[i].OriginalEntry);
            g_SanPages[i] = g_SanPages[g_SanPageCount - 1]; // swap-with-last
            g_SanPageCount--;
            // do NOT advance i: re-check the entry we just swapped in
        }
        else
        {
            i++;
        }
    }
}

//
// Restore every guarded page to its original EPT entry and drop the per-BATCH
// metadata. Called at every run/batch boundary (start, normal end, crash) so the
// target's physical frames are RWX again before it is ever torn down. Safe to call
// when nothing is protected. VMX-root only (it touches EPT + INVEPT).
//
// It deliberately does NOT clear g_SanAllocs / g_SanPending -- see the lifetime model
// at the top of the sanitizer section. Those describe pointers the GUEST still holds
// (repositioned buffers) and allocator calls still in flight on other threads; both
// outlive a batch, and forgetting them hands shifted pointers to the real allocator.
// WinaflSanProcessReset() clears them, once, for a fresh target.
//
static VOID
WinaflSanBatchReset(UINT32 CoreId)
{
    UINT32 i;

    for (i = 0; i < g_SanPageCount; i++)
        VmFuncEptGuardRestorePage(CoreId, g_SanPages[i].Gpa, g_SanPages[i].OriginalEntry);

    //
    // Only log a reset that actually did something, so the (frequent) no-op resets
    // at run boundaries stay silent. Includes the cumulative counters so a long run
    // still reports totals after the per-line log budget is spent.
    //
    if (g_SanPageCount != 0)
    {
        WINAFL_SAN_KLOG(SAN_LOG_RESET,
                        "[san] reset: restored %u pages (kept %u allocs, %u pending) | totals: "
                        "alloc(hook=%llu pass=%llu scope=%llu) post(guard=%llu open=%llu orphan=%llu slotmiss=%llu) "
                        "fail(xlate=%llu ept=%llu) free(held=%llu pass=%llu foreign=%llu dbl=%llu) "
                        "quarantine(now=%u evicted=%llu) faults(ours=%llu foreign=%llu)",
                        g_SanPageCount, g_SanAllocCount, g_SanPendingTop,
                        g_SanStats.AllocHooked, g_SanStats.AllocPassed, g_SanStats.AllocSkippedScope,
                        g_SanStats.PostGuarded, g_SanStats.PostUnguarded, g_SanStats.PostOrphan,
                        g_SanStats.PostSlotMiss,
                        g_SanStats.XlateFail, g_SanStats.ProtectFail,
                        g_SanStats.FreeHeld, g_SanStats.FreePassed, g_SanStats.FreeForeign,
                        g_SanStats.DoubleFree,
                        g_SanQuarantineCount, g_SanStats.QuarantineEvicted,
                        g_SanStats.Faults, g_SanStats.ForeignFaults);
    }

    g_SanPageCount = 0;
}

//
// Record one sanitizer malfunction and trip the circuit breaker once they add up.
// See the WINAFL_SAN_MAX_ANOMALIES block for why this exists.
//
static VOID
WinaflSanCountAnomaly(const char * What)
{
    if (g_SanDisabled)
        return;

    if (++g_SanAnomalies >= WINAFL_SAN_MAX_ANOMALIES)
    {
        g_SanDisabled = TRUE;
        WINAFL_SAN_KLOG(SAN_LOG_ERROR,
                        "[san] *** DISABLING the sanitizer: %u anomalies (last: %s). No further allocation "
                        "will be guarded this session. free() interception continues for pointers already "
                        "handed out. Fuzzing continues WITHOUT detection -- this is deliberate, it stops a "
                        "malfunctioning sanitizer from killing the target in a loop and bug-checking the box. ***",
                        g_SanAnomalies, What);
    }
    else
    {
        WINAFL_SAN_KLOG(SAN_LOG_ERROR,
                        "[san] anomaly %u/%u (%s) -- sanitizer disables itself at %u",
                        g_SanAnomalies, WINAFL_SAN_MAX_ANOMALIES, What, WINAFL_SAN_MAX_ANOMALIES);
    }
}

//
// Emergency: drop EVERY protection we hold, right now, and say why.
//
// Used from the EPT-violation classifier when continuing to hold guard pages would
// hurt something other than the fuzz target -- an orphaned page from a dead target now
// owned by another process, or a violation we cannot account for. Restoring the saved
// PML1 entries puts those frames back exactly as Windows expects them, so whatever
// faulted just re-executes and succeeds.
//
// The allocation records are deliberately KEPT: the guest may still hold repositioned
// pointers, and the free hook must be able to un-shift them. Only detection stops.
// VMX-root only.
//
static VOID
WinaflSanHealOrphanedPages(UINT32 CoreId, const char * Why, UINT64 GuestPhysicalAddr)
{
    UINT32 Healed = g_SanPageCount;
    UINT32 i;

    for (i = 0; i < g_SanPageCount; i++)
        VmFuncEptGuardRestorePage(CoreId, g_SanPages[i].Gpa, g_SanPages[i].OriginalEntry);

    g_SanPageCount = 0;

    WinaflSanCountAnomaly("emergency heal");

    WINAFL_SAN_KLOG(SAN_LOG_FOREIGN,
                    "[san] HEAL: %s -- gpa=0x%llx pid=%llu rip=0x%llx. Restored all %u protected page(s) "
                    "and retrying the access; NOT reported as a fuzzing crash. Detection is off until the "
                    "next allocation is guarded.",
                    Why, GuestPhysicalAddr, (UINT64)PsGetCurrentProcessId(), VmFuncGetRip(), Healed);
}

//
// Full reset for a FRESH target process: restore the EPT protections (which may be
// left over from a previous target that was torn down mid-batch) AND forget every
// reposition record. Only valid when no guest can still be holding a repositioned
// pointer -- i.e. at the first entry hit of a newly launched target, whose heap is
// brand new. VMX-root only.
//
static VOID
WinaflSanProcessReset(UINT32 CoreId)
{
    WinaflSanBatchReset(CoreId);

    if (g_SanAllocCount != 0 || g_SanPendingTop != 0)
    {
        WINAFL_SAN_KLOG(SAN_LOG_RESET,
                        "[san] process reset: dropped %u alloc record(s), %u pending, %u quarantined "
                        "(new target)",
                        g_SanAllocCount, g_SanPendingTop, g_SanQuarantineCount);
    }

    g_SanAllocCount      = 0;
    g_SanPendingTop      = 0;
    g_SanQuarantineCount = 0; // the old process's withheld memory died with it
}

//
// Report a guard-page / UAF detection to the fuzzer as a crash, attributed to the
// currently-executing input (g_WinaflBatchIndex -- the same index the user side
// blames as inputs[SegmentCount], since SegmentCount is not bumped for a run that
// faults). Fills the generic Fault* block + the SanFault* detail, stops tracing,
// ends the batch, restores the guard pages, parks the guest, and notifies CRASH.
//
static VOID
WinaflSanReport(UINT32 CoreId, PWINAFL_HOOK_SHARED Shared, GUEST_REGS * Regs, UINT32 Kind,
                UINT32 AllocIndex, UINT64 AllocBase, UINT64 AllocSize, UINT64 AccessVa)
{
    UINT32 Index = g_WinaflBatchIndex;
    UNREFERENCED_PARAMETER(AllocIndex);

    Shared->SanFaultKind       = Kind;
    Shared->SanFaultInputIndex = Index;
    Shared->SanFaultAllocBase  = AllocBase;
    Shared->SanFaultAllocSize  = AllocSize;
    Shared->SanFaultAccessVa   = AccessVa;

    Shared->FaultVector    = WINAFL_SAN_FAULT_VECTOR;
    Shared->FaultErrorCode = Kind;
    Shared->FaultRip       = VmFuncGetRip();
    Shared->FaultAddress   = AccessVa;
    if (Regs != NULL)
        RtlCopyMemory(&Shared->FaultRegs, Regs, sizeof(WINAFL_HOOK_REGS));

    if (Index < WINAFL_HOOK_MAX_SEGMENTS)
        Shared->SegmentStatus[Index] = WINAFL_STATUS_CRASH;
    Shared->Status = WINAFL_STATUS_CRASH;

    g_SanStats.Faults++;
    WINAFL_SAN_KLOG(SAN_LOG_FAULT,
                    "[san] FAULT kind=%u (1=overflow 2=uaf 3=double-free) input=%u "
                    "alloc=0x%llx size=0x%llx access=0x%llx rip=0x%llx idx=%u",
                    Kind, Index, AllocBase, AllocSize, AccessVa, Shared->FaultRip, AllocIndex);

    //
    // Stop PT on this pinned core, end any batch, restore the guard pages (so the
    // frames are RWX before the fuzzer kills the target), and park the guest in the
    // spin stub -- it harmlessly loops there until the kill lands.
    //
    HyperTracePtPauseCurrentCore();
    g_WinaflBatchActive = FALSE;
    WinaflSanBatchReset(CoreId);
    WinaflHookPark(Shared);
    WinaflHookNotify(WINAFL_TAG_CRASH);
}

//
// Allocator ENTRY (pre stage): enlarge the requested size by one alignment page +
// one guard page, and reroute the return through the post stub so we can capture
// RAX. Runs the real allocator afterwards (RIP is not redirected). Returns TRUE so
// the empty event action + epilogue are skipped (avoids a per-alloc notify flood).
//
static BOOLEAN
WinaflSanOnAllocEntry(PWINAFL_HOOK_SHARED Shared, GUEST_REGS * Regs, WINAFL_SAN_ALLOCATOR * Fn)
{
    UINT64 * SizeReg = WinaflSanRegPtr(Regs, Fn->ArgReg);
    UINT64   Size;
    UINT64   ReturnAddress = 0;
    UINT64   Stub;

    if ((Shared->SanitizeFlags & (WINAFL_SAN_OVERFLOW | WINAFL_SAN_UAF)) == 0 || SizeReg == NULL)
    {
        g_SanStats.AllocPassed++;
        return TRUE; // nothing to do -> let the call run untouched
    }

    //
    // Only the fuzzed code's own allocations may be repositioned (see the scope note
    // next to g_WinaflInFuzzRun). Anything else -- the loader, the CRT, other threads,
    // anything outside a run -- gets the real allocator, untouched. Handing those a
    // shifted pointer kills the target as soon as it reaches an unhooked heap API.
    //
    if (g_SanDisabled || !g_WinaflInFuzzRun ||
        (UINT64)PsGetCurrentThreadId() != g_WinaflFuzzThreadId)
    {
        g_SanStats.AllocSkippedScope++;
        return TRUE;
    }

    Size = *SizeReg;

    //
    // Skip zero / oversized requests (their returns pass through the post stub with
    // no pending record, which is handled harmlessly).
    //
    if (Size == 0 || Size > WINAFL_SAN_MAX_GUARD_SIZE)
    {
        g_SanStats.AllocPassed++;
        WINAFL_SAN_KLOG(SAN_LOG_ALLOC, "[san] alloc SKIP (size=0x%llx out of range)", Size);
        return TRUE;
    }

    if (g_SanPendingTop >= WINAFL_SAN_MAX_PENDING || Shared->PostStubAddress == 0)
    {
        g_SanStats.AllocPassed++;
        WINAFL_SAN_KLOG(SAN_LOG_ERROR,
                        "[san] alloc SKIP: pending=%u/%u stub=0x%llx -- cannot track return",
                        g_SanPendingTop, WINAFL_SAN_MAX_PENDING, Shared->PostStubAddress);
        return TRUE; // no room to track the return / no stub -> run normally
    }

    //
    // Capture and reroute the return address: read [rsp], push the pending record,
    // then overwrite [rsp] with the post stub so the allocator returns into it.
    //
    if (!MemoryMapperReadMemorySafeOnTargetProcess(Regs->rsp, &ReturnAddress, sizeof(ReturnAddress)))
    {
        g_SanStats.AllocPassed++;
        WINAFL_SAN_KLOG(SAN_LOG_ERROR,
                        "[san] alloc SKIP: cannot read return slot at rsp=0x%llx", Regs->rsp);
        return TRUE; // can't read the stack -> don't risk it
    }

    g_SanPending[g_SanPendingTop].OrigSize   = Size;
    g_SanPending[g_SanPendingTop].RealRA     = ReturnAddress;
    g_SanPending[g_SanPendingTop].RetSlot    = Regs->rsp; // match key at the post stub
    g_SanPending[g_SanPendingTop].HeapHandle = Regs->rcx; // heap this block comes from
    g_SanPendingTop++;

    *SizeReg = Size + WINAFL_SAN_REDZONE;

    //
    // Force zero-initialisation (e.g. HEAP_ZERO_MEMORY) so the allocator writes the
    // WHOLE enlarged chunk -- including the guard page in the redzone -- which faults
    // those pages in. Without this the redzone stays committed-but-not-present, so
    // VA->PA of the guard page returns 0 at the post stub and overflow detection
    // silently falls open. No-op when the allocator has no zero flag configured.
    //
    if (Fn->ZeroFlag != 0)
    {
        UINT64 * FlagsReg = WinaflSanRegPtr(Regs, Fn->FlagsReg);
        if (FlagsReg != NULL)
            *FlagsReg |= Fn->ZeroFlag;
    }

    Stub = Shared->PostStubAddress;
    if (!MemoryMapperWriteMemorySafeOnTargetProcess(Regs->rsp, &Stub, sizeof(Stub)))
    {
        //
        // Could not reroute the return: undo the pending push and the size bump so
        // the call runs exactly as the app intended (fail open, no half state).
        //
        g_SanPendingTop--;
        *SizeReg = Size;
        g_SanStats.AllocPassed++;
        WINAFL_SAN_KLOG(SAN_LOG_ERROR,
                        "[san] alloc SKIP: cannot write return slot at rsp=0x%llx -- rolled back", Regs->rsp);
        return TRUE;
    }

    g_SanStats.AllocHooked++;
    WINAFL_SAN_KLOG(SAN_LOG_ALLOC,
                    "[san] alloc: size=0x%llx -> 0x%llx (reg=%u) slot=0x%llx realRA=0x%llx stub=0x%llx pending=%u",
                    Size, Size + WINAFL_SAN_REDZONE, Fn->ArgReg, Regs->rsp, ReturnAddress, Stub, g_SanPendingTop);
    return TRUE;
}

//
// free() ENTRY (pre stage): if the pointer is one of our guarded allocations, hold
// it (mark its data pages no-access for UAF) and SKIP the real free by emulating a
// near-return to the caller -- so the memory is never returned to the allocator.
// A second free of an already-held buffer is reported as a UAF-class crash.
//
static BOOLEAN
WinaflSanOnFreeEntry(PWINAFL_HOOK_SHARED Shared, UINT32 CoreId, GUEST_REGS * Regs, WINAFL_SAN_ALLOCATOR * Fn)
{
    UINT64 * PtrReg = WinaflSanRegPtr(Regs, Fn->ArgReg);
    UINT64   UserPtr;
    UINT64   ReturnAddress = 0;
    int      Idx;

    //
    // IMPORTANT: the lookup is NOT gated on the UAF flag. Whenever we guard an
    // allocation we hand the caller a REPOSITIONED pointer, so we must intercept
    // every free of a tracked pointer regardless of UAF -- otherwise the real
    // allocator receives a shifted pointer that is not a heap block base and
    // corrupts the heap (the hang) and later faults on the reused guard frame (the
    // bug check). Repositioning and free-interception are coupled to the SAME set.
    //
    if (PtrReg == NULL)
        return TRUE; // misconfigured register -> run the real free

    UserPtr = *PtrReg;
    if (UserPtr == 0)
        return TRUE; // free(NULL) -> run normally

    Idx = WinaflSanFindAllocByUserPtr(UserPtr);
    if (Idx < 0)
    {
        //
        // Not tracked -> ordinary free. We only ever reposition allocations we also
        // track, so an untracked pointer was never shifted by us: it is safe to pass
        // straight through to the real allocator.
        //
        g_SanStats.FreeForeign++;
        WINAFL_SAN_KLOG(SAN_LOG_FREE,
                        "[san] free FOREIGN: ptr=0x%llx not tracked (allocs=%u) -> real free",
                        UserPtr, g_SanAllocCount);
        return TRUE;
    }

    if (g_SanAllocs[Idx].Freed)
    {
        //
        // Double free: freeing memory we are already holding as freed. Reported as
        // its own class (not plain UAF) so the fuzzer can name the bug precisely.
        // Report + park (WinaflSanReport rewinds/parks the guest); the #BP path
        // already suppressed the RIP increment.
        //
        g_SanStats.DoubleFree++;

        //
        // Reporting parks the guest, so it is only valid on the thread running the
        // fuzzed function -- parking any other thread rewrites ITS RSP/RIP to the fuzz
        // thread's park stub. A tracked pointer freed twice from another thread is not
        // this input's bug; swallow the second free (the buffer is already held, so the
        // real allocator must not see the shifted pointer either way) and carry on.
        //
        if ((UINT64)PsGetCurrentThreadId() != g_WinaflFuzzThreadId)
        {
            WINAFL_SAN_KLOG(SAN_LOG_FREE,
                            "[san] free DOUBLE-FREE on a non-fuzz thread: ptr=0x%llx idx=%d -- swallowed, "
                            "not reported (parking the wrong thread would be fatal)",
                            UserPtr, Idx);
            goto SkipRealFree;
        }

        WINAFL_SAN_KLOG(SAN_LOG_FREE,
                        "[san] free DOUBLE-FREE: ptr=0x%llx idx=%d (first freed by input %u)",
                        UserPtr, Idx, g_SanAllocs[Idx].InputIndex);
        WinaflSanReport(CoreId, Shared, Regs, WINAFL_SAN_FAULT_DOUBLE_FREE, (UINT32)Idx,
                        g_SanAllocs[Idx].UserPtr, g_SanAllocs[Idx].OrigSize, UserPtr);
        return TRUE;
    }

    //
    // ---- Quarantine full: EVICT the oldest instead of giving up on detection ----
    //
    // Simply passing this free through once the quarantine filled was a bug: UAF
    // detection silently switched itself off after WINAFL_SAN_MAX_QUARANTINE frees
    // and never came back for the life of the process. At one alloc/free per run
    // that is a couple of seconds of coverage, which is exactly the reported
    // "sometimes it catches the use-after-free, sometimes it doesn't".
    //
    // Evict instead. The guest is ALREADY inside RtlFreeHeap with a valid heap
    // handle, valid flags, at the right IRQL, in the right process -- so point that
    // call at the OLDEST quarantined buffer instead of the one it asked to free. The
    // heap gets its memory back (which is what keeps the EPT split count bounded --
    // see WINAFL_SAN_MAX_QUARANTINE), the caller's buffer is quarantined in its
    // place, and the net quarantine size is unchanged. No RIP redirect: the real
    // free runs, just on a different block.
    //
    // Only a buffer allocated from the SAME heap handle may be evicted. That is what
    // makes this safe rather than clever: freeing a block into the wrong heap
    // corrupts both. The handle is captured from RCX at alloc entry, and RCX is the
    // heap for RtlAllocateHeap(Heap,Flags,Size) and RtlFreeHeap(Heap,Flags,Base)
    // alike. For the pool-style Ex* allocators RCX is a pool type at alloc and a
    // pointer at free, so they never match and eviction simply never happens --
    // those fall through to the un-reposition path below, as before.
    //
    if ((Shared->SanitizeFlags & WINAFL_SAN_UAF) != 0 &&
        g_SanQuarantineCount >= WINAFL_SAN_MAX_QUARANTINE)
    {
        int Evict = WinaflSanFindEvictionCandidate(Regs->rcx, Idx);

        if (Evict >= 0)
        {
            UINT64 EvictReal = g_SanAllocs[Evict].RealBase;

            //
            // Drop the evicted buffer's protections BEFORE the heap can hand its
            // pages out again, and tombstone it so no later lookup matches it.
            //
            WinaflSanUnprotectAlloc(CoreId, (UINT32)Evict);
            g_SanAllocs[Evict].UserPtr = 0;
            g_SanQuarantineCount--;

            //
            // Redirect this call at the evicted block, then quarantine the caller's
            // buffer in its place.
            //
            *PtrReg = EvictReal;

            g_SanAllocs[Idx].Freed      = TRUE;
            g_SanAllocs[Idx].InputIndex = g_WinaflBatchIndex;
            WinaflSanProtectRange(CoreId, g_SanAllocs[Idx].UserPtr, g_SanAllocs[Idx].GuardVa,
                                  (UINT32)Idx, WINAFL_SAN_FAULT_UAF);
            g_SanQuarantineCount++;

            g_SanStats.QuarantineEvicted++;
            WINAFL_SAN_KLOG(SAN_LOG_FREE,
                            "[san] free EVICT: holding ptr=0x%llx idx=%d, freeing evicted idx=%d "
                            "(real=0x%llx) through this call instead (quarantine=%u)",
                            UserPtr, Idx, Evict, EvictReal, g_SanQuarantineCount);
            return TRUE; // real free runs, on the evicted block
        }

        //
        // Nothing evictable from this heap -- fall through and pass this one through
        // un-repositioned, as before.
        //
    }

    if ((Shared->SanitizeFlags & WINAFL_SAN_UAF) == 0 ||
        g_SanQuarantineCount >= WINAFL_SAN_MAX_QUARANTINE)
    {
        //
        // ---- Overflow-only, or quarantine full with nothing evictable:
        // ---- un-reposition and let the REAL free run ----
        // We repositioned this allocation for the guard page but are not holding
        // freed buffers. Undo it: restore + drop this allocation's guard page (so the
        // frame can safely return to the heap), rewrite the pointer register back to
        // the real block base, and fall through to the real allocator. No RIP redirect
        // -- the real free executes normally.
        //
        // We MARK the record freed but DO NOT tombstone it (UserPtr stays set), so a
        // second free of the same pointer is caught as a double free below instead of
        // being passed through to the real allocator as a shifted pointer (which would
        // corrupt the heap and hang). If the heap later reuses this chunk, the post
        // stub retires this record by RealBase, so there is no stale-record ambiguity.
        //
        UINT64 Real = g_SanAllocs[Idx].RealBase;

        WinaflSanUnprotectAlloc(CoreId, (UINT32)Idx);
        *PtrReg                     = Real;  // hand the real block base to the allocator
        g_SanAllocs[Idx].Freed      = TRUE;  // keyed record kept for double-free detection
        g_SanAllocs[Idx].InputIndex = g_WinaflBatchIndex;

        g_SanStats.FreePassed++;
        WINAFL_SAN_KLOG(SAN_LOG_FREE,
                        "[san] free UNREPOSITION: user=0x%llx -> real=0x%llx idx=%d (guard restored) -> real free",
                        UserPtr, Real, Idx);
        return TRUE;
    }

    //
    // ---- UAF on: first free -> HOLD the buffer ----
    // Protect its data pages [UserPtr, GuardVa) as UAF (page-aligned start means
    // these pages are exclusively ours -- no bleed). The guard page beyond GuardVa is
    // already no-access from the alloc when overflow is also on. Then SKIP the real
    // free by emulating a near-return, so the memory is never returned to the
    // allocator.
    //
    g_SanAllocs[Idx].Freed      = TRUE;
    g_SanAllocs[Idx].InputIndex = g_WinaflBatchIndex;
    WinaflSanProtectRange(CoreId, g_SanAllocs[Idx].UserPtr, g_SanAllocs[Idx].GuardVa,
                          (UINT32)Idx, WINAFL_SAN_FAULT_UAF);

    //
    // This buffer is now withheld from the allocator for the life of the process, so
    // it counts against the quarantine bound (see WINAFL_SAN_MAX_QUARANTINE).
    //
    g_SanQuarantineCount++;
    if (g_SanQuarantineCount == WINAFL_SAN_MAX_QUARANTINE)
    {
        WINAFL_SAN_KLOG(SAN_LOG_FREE,
                        "[san] quarantine FULL at %u buffers (~%u KB withheld) -- further frees go "
                        "through to the allocator so the heap can recycle memory. Holding more would "
                        "leak a permanent 4KB non-paged EPT split per fresh physical page.",
                        g_SanQuarantineCount,
                        (UINT32)((g_SanQuarantineCount * (WINAFL_SAN_REDZONE + 0x1000)) / 1024));
    }

    //
    // Skip the real free: emulate a near-return (pop the return address, jump to it).
    // RAX = TRUE for RtlFreeHeap-style BOOLEAN returns. RSP is VMCS state, so it is
    // updated via SetGuestRSP; the mirror (Regs->rsp) is kept in step defensively.
    //
    // Also reached by the swallowed non-fuzz-thread double free above: that buffer is
    // already held and already protected, and all that is left to do is keep the real
    // allocator from ever seeing the shifted pointer.
    //
SkipRealFree:
    if (!MemoryMapperReadMemorySafeOnTargetProcess(Regs->rsp, &ReturnAddress, sizeof(ReturnAddress)))
        return TRUE; // can't emulate the return -> fall back to the real free

    Regs->rsp += sizeof(UINT64);
    SetGuestRSP(Regs->rsp);
    if (Fn->RetIsBool)
        Regs->rax = 1;
    VmFuncSetRip(ReturnAddress);

    g_SanStats.FreeHeld++;
    WINAFL_SAN_KLOG(SAN_LOG_FREE,
                    "[san] free HELD: ptr=0x%llx idx=%d size=0x%llx pages[0x%llx..0x%llx) "
                    "skipped real free, ret->0x%llx",
                    UserPtr, Idx, g_SanAllocs[Idx].OrigSize,
                    WINAFL_SAN_PAGE_DOWN(g_SanAllocs[Idx].UserPtr), g_SanAllocs[Idx].GuardVa,
                    ReturnAddress);
    return TRUE;
}

//
// Return-trampoline (post stage): the allocator has returned into the post stub.
// Capture RAX (the real base), place the caller's buffer so its last byte ends on a
// page boundary with the guard page right after, protect that guard page, record
// the allocation, hand the repositioned pointer back in RAX, and return to the real
// caller. Fails open (returns the real base, no guard) if the guard page cannot be
// protected (e.g. not present) or a table is full.
//
static BOOLEAN
WinaflSanOnPostStub(PWINAFL_HOOK_SHARED Shared, UINT32 CoreId, GUEST_REGS * Regs)
{
    WINAFL_SAN_PENDING Pending = {0};
    UINT64             RetSlot;
    UINT64             RealBase;
    UINT64             GuardVa;
    UINT64             UserPtr;
    UINT32             Slot;
    UINT32             p;
    BOOLEAN            Found     = FALSE;
    BOOLEAN            WantGuard = FALSE;
    BOOLEAN            Track     = FALSE;

    //
    // Find OUR pending record by the stack slot this return consumed. The allocator
    // reached us with `ret`, which popped the slot we planted the stub in, so that
    // slot is exactly RSP-8 now. Matching on it (rather than popping a LIFO) is what
    // keeps interleaved allocator calls from other threads of the target -- all of
    // which run through this same shared-ntdll hook -- from stealing each other's
    // size and return address. Newest first: a recursive allocator reuses stack
    // depth, so the most recent record for a slot is the right one.
    //
    RetSlot = Regs->rsp - sizeof(UINT64);

    for (p = g_SanPendingTop; p > 0; p--)
    {
        if (g_SanPending[p - 1].RetSlot == RetSlot)
        {
            Pending                = g_SanPending[p - 1];
            g_SanPending[p - 1]    = g_SanPending[g_SanPendingTop - 1]; // swap-with-last
            g_SanPendingTop--;
            Found = TRUE;
            break;
        }
    }

    if (!Found && g_SanPendingTop != 0)
    {
        //
        // Slot match failed but we DO have in-flight records. Fall back to the most
        // recent one (the original LIFO behaviour) instead of giving up.
        //
        // This matters enormously: the only thing we cannot reconstruct here is the
        // caller's real return address, and without it the sole option is to park --
        // which silently hangs the run, times out, gets the target killed, and orphans
        // guard pages. A slightly wrong pairing is recoverable; a park is not. So the
        // slot key is treated as an OPTIMISATION for correct pairing under thread
        // interleaving, never as a reason to abandon the guest.
        //
        // If this fires often, the RSP mirror at the post stub does not line up with
        // the alloc entry's (`rsp-8`) the way it is assumed to, and the slot key is
        // simply wrong for this allocator -- the counter below is how you find that out.
        //
        Pending = g_SanPending[--g_SanPendingTop];
        Found   = TRUE;

        g_SanStats.PostSlotMiss++;
        WINAFL_SAN_KLOG(SAN_LOG_ERROR,
                        "[san] post SLOT-MISS: no record for slot=0x%llx (rsp=0x%llx); fell back to the "
                        "newest pending (size=0x%llx ra=0x%llx, %u left). Pairing may be wrong but the "
                        "guest continues.",
                        RetSlot, Regs->rsp, Pending.OrigSize, Pending.RealRA, g_SanPendingTop);
    }

    if (!Found)
    {
        //
        // Genuinely nothing in flight: the caller's real return address is gone and
        // cannot be reconstructed, so parking is all that is left. Notify a crash so
        // the fuzzer kills and relaunches immediately instead of waiting out a per-run
        // timeout -- a silent park here is what turns into a hang, a dead target, and
        // orphaned guard pages.
        //
        g_SanStats.PostOrphan++;
        WINAFL_SAN_KLOG(SAN_LOG_ERROR,
                        "[san] post ORPHAN: empty pending stack at slot=0x%llx (rax=0x%llx rsp=0x%llx) -- "
                        "parking + reporting so the target is relaunched rather than left hanging",
                        RetSlot, Regs->rax, Regs->rsp);
        WinaflSanCountAnomaly("post-stub with empty pending stack");
        WinaflSanBatchReset(CoreId);
        WinaflHookPark(Shared);
        WinaflHookNotify(WINAFL_TAG_CRASH);
        return TRUE;
    }

    RealBase = Regs->rax;

    if (RealBase == 0)
    {
        WINAFL_SAN_KLOG(SAN_LOG_POST,
                        "[san] post: allocation FAILED (size=0x%llx) -> returning NULL to 0x%llx",
                        Pending.OrigSize, Pending.RealRA);
        VmFuncSetRip(Pending.RealRA); // allocation failed -> return NULL unchanged
        return TRUE;
    }

    //
    // Guard placement. GuardVa = PAGE_UP(RealBase) + PAGE_UP(OrigSize) makes BOTH
    // ends clean: the buffer's last byte lands on a page boundary (guard page right
    // after -> byte-precise overflow) AND its first page starts at PAGE_UP(RealBase)
    // >= RealBase, so every page we ever protect is exclusively inside THIS
    // allocation (no bleed into the previous heap chunk). The 3-page redzone
    // (WINAFL_SAN_REDZONE) guarantees this fits.
    //
    GuardVa = WINAFL_SAN_PAGE_UP(RealBase) + WINAFL_SAN_PAGE_UP(Pending.OrigSize);
    UserPtr = GuardVa - Pending.OrigSize;

    WantGuard = (Shared->SanitizeFlags & WINAFL_SAN_OVERFLOW) != 0;

    //
    // Reserve the record slot BEFORE protecting: the guard page's reverse map stores
    // this index, so it has to be final by then. Nothing is committed until Track --
    // a failed guard must leave the table exactly as it was.
    //
    Slot = WinaflSanPeekSlot();

    if (Slot != WINAFL_SAN_NO_SLOT)
    {
        if (WantGuard)
        {
            //
            // Overflow on: protect the trailing guard page now. Only track (and
            // therefore reposition) the allocation if the guard actually went down;
            // otherwise fall fully open so we never hand out a shifted pointer we
            // cannot police.
            //
            Track = WinaflSanProtectPage(CoreId, GuardVa, Slot, WINAFL_SAN_FAULT_OVERFLOW);
        }
        else if (Shared->SanitizeFlags & WINAFL_SAN_UAF)
        {
            //
            // UAF-only: reposition + track with NO trailing guard page (the buffer's
            // data pages are protected at free time). Same placement math, so the
            // held pages never overlap a neighbouring chunk.
            //
            Track = TRUE;
        }
    }

    if (Track)
    {
        //
        // If the heap just reused memory we previously real-freed (overflow-only
        // un-reposition), retire those stale records so a later free of THIS new
        // allocation cannot match one and be misreported as a double free.
        //
        WinaflSanRetireStaleRecords(RealBase, Pending.OrigSize + WINAFL_SAN_REDZONE);

        g_SanAllocs[Slot].UserPtr    = UserPtr;
        g_SanAllocs[Slot].RealBase   = RealBase;
        g_SanAllocs[Slot].OrigSize   = Pending.OrigSize;
        g_SanAllocs[Slot].GuardVa    = GuardVa;
        g_SanAllocs[Slot].HeapHandle = Pending.HeapHandle;
        g_SanAllocs[Slot].InputIndex = g_WinaflBatchIndex;
        g_SanAllocs[Slot].Freed      = FALSE;

        if (Slot == g_SanAllocCount)
            g_SanAllocCount++; // fresh append (a recycled slot is already counted)

        Regs->rax = UserPtr; // hand the repositioned pointer to the caller

        g_SanStats.PostGuarded++;
        WINAFL_SAN_KLOG(SAN_LOG_POST,
                        "[san] post %s: real=0x%llx size=0x%llx -> user=0x%llx last=0x%llx "
                        "guard=0x%llx idx=%u ra=0x%llx",
                        WantGuard ? "GUARDED" : "TRACKED(uaf)",
                        RealBase, Pending.OrigSize, UserPtr, UserPtr + Pending.OrigSize - 1,
                        GuardVa, Slot, Pending.RealRA);
    }
    else
    {
        //
        // Not tracked: the caller gets the real (over-sized) base UNCHANGED, so a
        // later free of it is an ordinary free with nothing shifted. Happens when the
        // overflow guard could not be placed (page not present / tables full) or
        // neither detector wants this allocation.
        //
        g_SanStats.PostUnguarded++;
        WINAFL_SAN_KLOG(SAN_LOG_POST,
                        "[san] post UNTRACKED: real=0x%llx size=0x%llx (no guard placed) -- returned as-is",
                        RealBase, Pending.OrigSize);
    }

    VmFuncSetRip(Pending.RealRA);
    return TRUE;
}

//
// EPT-violation classifier (called from AttachingCheckUnhandledEptViolation, in
// VMX-root on the faulting core). If the faulting physical page is one we forced to
// no-access, classify it (guard page => overflow, held freed page => UAF), report a
// crash for the current input, and return TRUE (handled). Otherwise return FALSE so
// the normal HyperDbg path runs.
//
BOOLEAN
WinaflSanHandleEptViolation(UINT32 CoreId, UINT64 ViolationQualification, UINT64 GuestPhysicalAddr)
{
    PWINAFL_HOOK_SHARED Shared = g_WinaflHookShared;
    UINT64              Gpa    = WINAFL_SAN_PAGE_DOWN(GuestPhysicalAddr);
    UINT32              i;

    UNREFERENCED_PARAMETER(ViolationQualification);

    if (Shared == NULL || Shared->SanitizeFlags == 0 || g_SanPageCount == 0)
        return FALSE; // sanitizer not active -> not ours

    for (i = 0; i < g_SanPageCount; i++)
    {
        if (g_SanPages[i].Gpa == Gpa)
        {
            UINT32 AllocIndex;
            UINT64 Base;
            UINT64 Size;

            //
            // ---- Is this REALLY the fuzzed code faulting? ----
            // Reporting means parking the guest: rewriting RSP and RIP to the target's
            // user-mode park stub. That is only meaningful for the one thread running
            // the fuzzed function. Doing it to anything else corrupts whatever was
            // actually executing, and if that is a kernel thread it bug-checks the box
            // immediately. So ALL THREE of these must hold, and each guards a real case:
            //
            //   * right process -- a dead target leaves no-access frames behind (nothing
            //     runs in VMX-root to restore them), Windows recycles them, and the next
            //     process to touch one lands here with a matching GPA.
            //
            //   * USER MODE -- this is the subtle one, and it needs no target death at
            //     all. A guard page is a physical frame; the kernel touches guest frames
            //     from inside the target's process context routinely (working-set
            //     trimming, zeroing, paging I/O). PsGetCurrentProcessId() MATCHES for
            //     those, so a process check alone lets a kernel thread through -- and
            //     parking a kernel thread on a user-mode stub is an instant bug check.
            //     A kernel RIP is the reliable tell.
            //
            //   * right thread -- another user thread of the target touching the buffer
            //     is not this input's crash, and parking it would restore the FUZZ
            //     thread's RSP onto the wrong stack.
            //
            // Anything else: heal and retry. The saved PML1 entry is that frame's
            // correct present/RWX mapping, so restoring is always safe.
            //
            {
                UINT64  FaultRip   = VmFuncGetRip();
                BOOLEAN RightProc  = ((UINT64)PsGetCurrentProcessId() == (UINT64)Shared->TargetProcessId);
                BOOLEAN UserMode   = (FaultRip < 0xFFFF800000000000ull);
                BOOLEAN RightThrd  = ((UINT64)PsGetCurrentThreadId() == g_WinaflFuzzThreadId);

                if (!RightProc || !UserMode || !RightThrd)
                {
                    WinaflSanHealOrphanedPages(CoreId,
                                               !RightProc ? "guard page hit by a FOREIGN PROCESS" :
                                               !UserMode  ? "guard page hit from KERNEL MODE (frame touched by the OS)" :
                                                            "guard page hit by a non-fuzz thread",
                                               GuestPhysicalAddr);
                    VmFuncSuppressRipIncrement(CoreId);
                    return TRUE;
                }
            }

            AllocIndex = g_SanPages[i].AllocIndex;
            Base       = (AllocIndex < g_SanAllocCount) ? g_SanAllocs[AllocIndex].UserPtr : 0;
            Size       = (AllocIndex < g_SanAllocCount) ? g_SanAllocs[AllocIndex].OrigSize : 0;

            //
            // FaultRegs is left unfilled here (NULL): during an EPT violation this
            // path is not reached through DebuggerTriggerEvents, so the per-core
            // saved GUEST_REGS would be stale. FaultRip (below) is read live.
            //
            // AccessVa carries the faulting guest-PHYSICAL address here (the guest
            // linear address is in the VMCS but not exported to hyperkd). The offending
            // allocation is already identified exactly by Base/Size, and FaultRip says
            // which instruction did it, so this is enough to triage.
            //
            WinaflSanReport(CoreId, Shared, NULL, g_SanPages[i].Kind, AllocIndex, Base, Size, GuestPhysicalAddr);

            //
            // EPT violations do not advance RIP for us; suppress the framework's
            // default increment so our park redirect (in WinaflSanReport) stands.
            //
            VmFuncSuppressRipIncrement(CoreId);
            return TRUE;
        }
    }

    //
    // An EPT violation whose GPA we do not recognise, while we are still holding
    // protections. Left alone this returns FALSE into HyperDbg's LogError +
    // DbgBreakPoint(), which on a box with no kernel debugger attached is a bug check.
    //
    // We are almost certainly the cause: nothing else in this configuration denies
    // access to guest frames. Bug-checking the user's machine to report our own stale
    // bookkeeping is the worst possible outcome, so drop every protection we hold and
    // let the instruction retry. Detection stops for this batch; the box survives.
    //
    g_SanStats.ForeignFaults++;
    WinaflSanHealOrphanedPages(CoreId, "unrecognised EPT violation while guards were live", GuestPhysicalAddr);
    VmFuncSuppressRipIncrement(CoreId);
    return TRUE;
}

BOOLEAN
MasoudPrologue(UINT32       CoreId,
               PVOID        Context,
               GUEST_REGS * Regs)
{
    PWINAFL_HOOK_SHARED    Shared = g_WinaflHookShared;
    UINT64                 Va     = (UINT64)Context;
    WINAFL_SAN_ALLOCATOR * Fn;

#if WINAFL_HOOK_KERNEL_VERBOSE
    //
    // Trace the first calls so we can confirm the hook fires at all and at which
    // address (capped so the park-stub spin can never flood the log). If NO
    // "[winafl] prologue" line appears, the !epthook never triggered MasoudPrologue.
    //
    {
        static volatile LONG WinaflDbgCount = 0;
        if (InterlockedIncrement(&WinaflDbgCount) <= 64)
            LogInfo("[winafl] prologue: ctx=0x%llx armed=%d fuzz=0x%llx ret=0x%llx park=0x%llx first=%d",
                    Va,
                    (Shared != NULL) ? 1 : 0,
                    (Shared != NULL) ? Shared->FuzzAddress : 0ull,
                    (Shared != NULL) ? Shared->ReturnAddress : 0ull,
                    (Shared != NULL) ? Shared->ParkStubAddress : 0ull,
                    (Shared != NULL) ? Shared->FirstHitDone : 0);
    }
#endif

    //
    // Disarmed, or this hook is not one of ours: return FALSE so the ordinary
    // !epthook path (its actions, then the no-op epilogue) is preserved.
    //
    if (Shared == NULL)
    {
        return FALSE;
    }

    //
    // ---- Sanitizer routing (only when armed with SanitizeFlags) ----
    // The allocator/free entries and the return-trampoline stub are separate
    // !epthooks; route their hits to the guard-page sanitizer. All of these return
    // TRUE so the empty event action + epilogue are skipped.
    //
    if (Shared->SanitizeFlags != 0)
    {
        if (Va == Shared->PostStubAddress)
            return WinaflSanOnPostStub(Shared, CoreId, Regs);

        Fn = WinaflSanFindAllocatorByAddr(Shared, Va);
        if (Fn != NULL)
        {
            if (Fn->Kind == WINAFL_SAN_FN_ALLOC)
                return WinaflSanOnAllocEntry(Shared, Regs, Fn);
            if (Fn->Kind == WINAFL_SAN_FN_FREE)
                return WinaflSanOnFreeEntry(Shared, CoreId, Regs, Fn);
        }
    }

    if (Va == Shared->FuzzAddress)
    {
        WINAFL_KLOG("[winafl] entry hook hit (first=%d)", Shared->FirstHitDone);
        return WinaflHookOnEntry(CoreId, Shared, Regs);
    }

    if (Shared->FirstHitDone && Va == Shared->ReturnAddress)
    {
        WINAFL_KLOG("[winafl] return hook hit (iter=%lld)", Shared->IterationCount);
        return WinaflHookOnReturn(CoreId, Shared, Regs);
    }

    //
    // NOTE: the park is no longer an epthook. The parked guest polls for GO via a
    // CPUID delay loop, handled in WinaflHookOnParkCpuid (called from the CPUID
    // dispatch), so there is no park branch here anymore.
    //
    return FALSE;
}

VOID
MasoudEpilogue(UINT32       CoreId,
               PVOID        Context,
               GUEST_REGS * Regs)
{
    PWINAFL_HOOK_SHARED Shared = g_WinaflHookShared;
    UNREFERENCED_PARAMETER(Regs);
    UNREFERENCED_PARAMETER(CoreId);

    //
    // Only the return-address hook reaches here (the entry/park branches return
    // TRUE and skip the epilogue). Rewind to the entry, park until the fuzzer
    // hands us the next input, and notify it the iteration is done.
    //
    if (Shared != NULL && (UINT64)Context == Shared->ReturnAddress)
    {
        WINAFL_KLOG("[winafl] epilogue: rewind to park=0x%llx (rsp<-0x%llx), notify ITER_DONE",
                    Shared->ParkStubAddress, Shared->SavedRsp);
        WinaflHookPark(Shared);
        WinaflHookNotify(WINAFL_TAG_ITER_DONE);
    }
}

/**
 * @brief A wrapper for GetRegValue() in script-engine
 *
 * @return BOOLEAN Value of register
 */
UINT64
DebuggerGetRegValueWrapper(PGUEST_REGS GuestRegs, UINT32 /* REGS_ENUM */ RegId)
{
    return GetRegValue(GuestRegs, RegId);
}

/**
 * @brief Debugger get the last error
 *
 * @return UINT32 Error value
 */
UINT32
DebuggerGetLastError()
{
    return g_LastError;
}

/**
 * @brief Debugger set the last error
 * @param LastError The value of last error
 *
 * @return VOID
 */
VOID
DebuggerSetLastError(UINT32 LastError)
{
    g_LastError = LastError;
}

/**
 * @brief Initialize script engine global variables and per-core stack buffers
 *
 * @return BOOLEAN Shows whether the initialization process was successful
 * or not
 */
BOOLEAN
DebuggerInitializeScriptEngine()
{
    ULONG                       ProcessorsCount      = KeQueryActiveProcessorCount(0);
    PROCESSOR_DEBUGGING_STATE * CurrentDebuggerState = NULL;

    //
    // Initialize script engines global variables holder
    //
    if (!g_ScriptGlobalVariables)
    {
        g_ScriptGlobalVariables = PlatformMemAllocateNonPagedPool(MAX_VAR_COUNT * sizeof(UINT64));
    }

    if (!g_ScriptGlobalVariables)
    {
        //
        // Out of resource, initialization of script engine's global variable holders failed
        //
        return FALSE;
    }

    //
    // Zero the global variables memory
    //
    RtlZeroMemory(g_ScriptGlobalVariables, MAX_VAR_COUNT * sizeof(UINT64));

    //
    // Initialize the local and temp variables
    //
    for (SIZE_T i = 0; i < ProcessorsCount; i++)
    {
        CurrentDebuggerState = &g_DbgState[i];

        if (!CurrentDebuggerState->ScriptEngineCoreSpecificStackBuffer)
        {
            CurrentDebuggerState->ScriptEngineCoreSpecificStackBuffer = PlatformMemAllocateNonPagedPool(MAX_STACK_BUFFER_COUNT * sizeof(UINT64));
        }

        if (!CurrentDebuggerState->ScriptEngineCoreSpecificStackBuffer)
        {
            //
            // Out of resource, initialization of script engine's stack buffer holders failed
            //
            return FALSE;
        }

        //
        // Zero stack buffer memory
        //
        RtlZeroMemory(CurrentDebuggerState->ScriptEngineCoreSpecificStackBuffer, MAX_STACK_BUFFER_COUNT * sizeof(UINT64));
    }

    return TRUE;
}

/**
 * @brief Initialize trap flag state and breakpoint related structures
 *
 * @return BOOLEAN Shows whether the initialization process was successful
 * or not
 */
BOOLEAN
DebuggerInitializeTrapsAndBreakpoints()
{
    //
    // Zero the TRAP FLAG state memory
    //
    RtlZeroMemory(&g_TrapFlagState, sizeof(DEBUGGER_TRAP_FLAG_STATE));

    //
    // Request pages for breakpoint detail
    //
    PoolManagerRequestAllocation(sizeof(DEBUGGEE_BP_DESCRIPTOR),
                                 MAXIMUM_BREAKPOINTS_WITHOUT_CONTINUE,
                                 BREAKPOINT_DEFINITION_STRUCTURE);

    //
    // Initialize list of breakpoints and breakpoint id
    //
    g_MaximumBreakpointId = 0;
    InitializeListHead(&g_BreakpointsListHead);

    return TRUE;
}

/**
 * @brief Initialize VMM operations (events and related operations)
 *
 * @return BOOLEAN Shows whether the initialization process was successful
 * or not
 */
BOOLEAN
DebuggerInitializeVmmOperations()
{
    //
    // Initialize lists relating to the debugger events store
    //
    InitializeListHead(&g_Events->EptHookExecCcEventsHead);
    InitializeListHead(&g_Events->HiddenHookReadAndWriteAndExecuteEventsHead);
    InitializeListHead(&g_Events->HiddenHookReadAndWriteEventsHead);
    InitializeListHead(&g_Events->HiddenHookReadAndExecuteEventsHead);
    InitializeListHead(&g_Events->HiddenHookWriteAndExecuteEventsHead);
    InitializeListHead(&g_Events->HiddenHookReadEventsHead);
    InitializeListHead(&g_Events->HiddenHookWriteEventsHead);
    InitializeListHead(&g_Events->HiddenHookExecuteEventsHead);
    InitializeListHead(&g_Events->EptHook2sExecDetourEventsHead);
    InitializeListHead(&g_Events->SyscallHooksEferSyscallEventsHead);
    InitializeListHead(&g_Events->SyscallHooksEferSysretEventsHead);
    InitializeListHead(&g_Events->CpuidInstructionExecutionEventsHead);
    InitializeListHead(&g_Events->RdmsrInstructionExecutionEventsHead);
    InitializeListHead(&g_Events->WrmsrInstructionExecutionEventsHead);
    InitializeListHead(&g_Events->ExceptionOccurredEventsHead);
    InitializeListHead(&g_Events->TscInstructionExecutionEventsHead);
    InitializeListHead(&g_Events->PmcInstructionExecutionEventsHead);
    InitializeListHead(&g_Events->InInstructionExecutionEventsHead);
    InitializeListHead(&g_Events->OutInstructionExecutionEventsHead);
    InitializeListHead(&g_Events->DebugRegistersAccessedEventsHead);
    InitializeListHead(&g_Events->ExternalInterruptOccurredEventsHead);
    InitializeListHead(&g_Events->VmcallInstructionExecutionEventsHead);
    InitializeListHead(&g_Events->TrapExecutionModeChangedEventsHead);
    InitializeListHead(&g_Events->TrapExecutionInstructionTraceEventsHead);
    InitializeListHead(&g_Events->ControlRegister3ModifiedEventsHead);
    InitializeListHead(&g_Events->ControlRegisterModifiedEventsHead);
    InitializeListHead(&g_Events->XsetbvInstructionExecutionEventsHead);

    //
    // Initialize NMI broadcasting mechanism
    //
    VmFuncVmxBroadcastInitialize();

    //
    // Set initial state of triggering events for VMCALLs
    //
    VmFuncSetTriggerEventForVmcalls(FALSE);

    //
    // Set initial state of triggering events for CPUIDs
    //
    VmFuncSetTriggerEventForCpuids(FALSE);

    //
    // Pre-allocate pools for possible EPT hooks
    //
    ConfigureEptHookReservePreallocatedPoolsForEptHooks(MAXIMUM_NUMBER_OF_INITIAL_PREALLOCATED_EPT_HOOKS);

    if (!PoolManagerCheckAndPerformAllocationAndDeallocation())
    {
        LogWarning("Warning, cannot allocate the pre-allocated pools for EPT hooks");

        //
        // BTW, won't fail the starting phase because of this
        //
    }

    //
    // Enabled Debugger VMX Events
    //
    g_EnableDebuggerVmxEvents = TRUE;

    return TRUE;
}

/**
 * @brief Initialize Debugger Structures and Routines
 *
 * @return BOOLEAN Shows whether the initialization process was successful
 * or not
 */
BOOLEAN
DebuggerInitialize()
{
    ULONG ProcessorsCount = KeQueryActiveProcessorCount(0);

    //
    // Also allocate the debugging state
    //
    if (!GlobalDebuggingStateAllocateZeroedMemory())
    {
        return FALSE;
    }

    //
    // Allocate buffer for saving events
    //
    if (GlobalEventsAllocateZeroedMemory() == FALSE)
    {
        return FALSE;
    }

    //
    // Set the core's IDs
    //
    for (UINT32 i = 0; i < ProcessorsCount; i++)
    {
        g_DbgState[i].CoreId = i;
    }

    //
    // Initialize Pool Manager
    //
    if (!PoolManagerInitialize())
    {
        LogError("Err, could not initialize pool manager");
        return FALSE;
    }

    //
    // Initialize script engine global variables and per-core stack buffers
    //
    if (!DebuggerInitializeScriptEngine())
    {
        return FALSE;
    }

    //
    // Initialize trap flag state and breakpoint related structures
    //
    if (!DebuggerInitializeTrapsAndBreakpoints())
    {
        return FALSE;
    }

    //
    // Initialize attaching mechanism,
    // we'll use the functionalities of the attaching in reading modules
    // of user mode applications (other than attaching mechanism itself)
    //
    if (!AttachingInitialize())
    {
        return FALSE;
    }

    return TRUE;
}

/**
 * @brief Uninitialize Debugger VMM Operations (Events and other related operations)
 *
 * @return VOID
 */
VOID
DebuggerUninitializeVmmOperations()
{
    //
    //  *** Disable, terminate and clear all the events ***
    //

    //
    // Because we want to delete all the objects and buffers (pools)
    // after we finished termination, the debugger might still use
    // the buffers for events and action, for solving this problem
    // we first disable the tag(s) and this way the debugger no longer
    // use that event and this way we can safely remove and deallocate
    // the buffers later after termination
    //

    //
    // Disable triggering events
    //
    g_EnableDebuggerVmxEvents = FALSE;

    //
    // Clear all events (Check if the kernel debugger is enable
    // and whether the instant event mechanism is working or not)
    //
    if (g_KernelDebuggerState && EnableInstantEventMechanism)
    {
        DebuggerClearAllEvents(FALSE, TRUE);
    }
    else
    {
        DebuggerClearAllEvents(FALSE, FALSE);
    }

    //
    // Uninitialize kernel debugger
    //
    KdUninitializeKernelDebugger();

    //
    // Uninitialize user debugger
    //
    UdUninitializeUserDebugger();

    //
    // Uninitialize NMI broadcasting mechanism
    //
    VmFuncVmxBroadcastUninitialize();
}

/**
 * @brief Uninitialize Debugger Structures and Routines
 *
 * @return VOID
 */
VOID
DebuggerUninitialize()
{
    ULONG                       ProcessorsCount;
    PROCESSOR_DEBUGGING_STATE * CurrentDebuggerState = NULL;

    ProcessorsCount = KeQueryActiveProcessorCount(0);

    //
    // Free the Pool manager
    //
    PoolManagerUninitialize();

    //
    // Free g_Events
    //
    GlobalEventsFreeMemory();

    //
    // Free g_ScriptGlobalVariables
    //
    if (g_ScriptGlobalVariables != NULL)
    {
        PlatformMemFreePool(g_ScriptGlobalVariables);
        g_ScriptGlobalVariables = NULL;
    }

    //
    // Free core specific local and temp variables
    //
    for (SIZE_T i = 0; i < ProcessorsCount; i++)
    {
        CurrentDebuggerState = &g_DbgState[i];

        if (CurrentDebuggerState->ScriptEngineCoreSpecificStackBuffer != NULL)
        {
            PlatformMemFreePool(CurrentDebuggerState->ScriptEngineCoreSpecificStackBuffer);
            CurrentDebuggerState->ScriptEngineCoreSpecificStackBuffer = NULL;
        }
    }

    //
    // Free g_DbgState
    //
    GlobalDebuggingStateFreeMemory();
}

/**
 * @brief Create an Event Object
 *
 * @details should NOT be called in vmx-root
 *
 * @param Enabled Is the event enabled or disabled
 * @param CoreId The core id that this event is allowed to run
 * @param ProcessId The process id that this event is allowed to run
 * @param EventType The type of event
 * @param Tag User-mode generated unique tag (id) of the event
 * @param Options Optional parameters for the event
 * @param ConditionsBufferSize Size of condition code buffer (if any)
 * @param ConditionBuffer Address of condition code buffer (if any)
 * @param ResultsToReturn Result buffer that should be returned to
 * the user-mode
 * @param InputFromVmxRoot Whether the input comes from VMX root-mode or IOCTL
 *
 * @return PDEBUGGER_EVENT Returns null in the case of error and event
 * object address when it's successful
 */
PDEBUGGER_EVENT
DebuggerCreateEvent(BOOLEAN                           Enabled,
                    UINT32                            CoreId,
                    UINT32                            ProcessId,
                    VMM_EVENT_TYPE_ENUM               EventType,
                    UINT64                            Tag,
                    DEBUGGER_EVENT_OPTIONS *          Options,
                    UINT32                            ConditionsBufferSize,
                    PVOID                             ConditionBuffer,
                    PDEBUGGER_EVENT_AND_ACTION_RESULT ResultsToReturn,
                    BOOLEAN                           InputFromVmxRoot)
{
    PDEBUGGER_EVENT Event           = NULL;
    UINT32          EventBufferSize = sizeof(DEBUGGER_EVENT) + ConditionsBufferSize;

    //
    // Initialize the event structure
    //
    if (InputFromVmxRoot)
    {
        //
        // *** The buffer is coming from VMX-root mode ***
        //

        //
        // If the buffer is smaller than regular instant events
        //
        if (REGULAR_INSTANT_EVENT_CONDITIONAL_BUFFER >= EventBufferSize)
        {
            //
            // The buffer fits into a regular instant event
            //
            Event = (DEBUGGER_EVENT *)PoolManagerRequestPool(INSTANT_REGULAR_EVENT_BUFFER, TRUE, REGULAR_INSTANT_EVENT_CONDITIONAL_BUFFER);

            if (!Event)
            {
                //
                // Here we try again to see if we could store it into a big instant event instead
                //
                Event = (DEBUGGER_EVENT *)PoolManagerRequestPool(INSTANT_BIG_EVENT_BUFFER, TRUE, BIG_INSTANT_EVENT_CONDITIONAL_BUFFER);

                if (!Event)
                {
                    //
                    // Set the error
                    //
                    ResultsToReturn->IsSuccessful = FALSE;
                    ResultsToReturn->Error        = DEBUGGER_ERROR_INSTANT_EVENT_REGULAR_PREALLOCATED_BUFFER_NOT_FOUND;

                    //
                    // There is a problem with allocating event
                    //
                    return NULL;
                }
            }
        }
        else if (BIG_INSTANT_EVENT_CONDITIONAL_BUFFER >= EventBufferSize)
        {
            //
            // The buffer fits into a big instant event
            //
            Event = (DEBUGGER_EVENT *)PoolManagerRequestPool(INSTANT_BIG_EVENT_BUFFER, TRUE, BIG_INSTANT_EVENT_CONDITIONAL_BUFFER);

            if (!Event)
            {
                //
                // Set the error
                //
                ResultsToReturn->IsSuccessful = FALSE;
                ResultsToReturn->Error        = DEBUGGER_ERROR_INSTANT_EVENT_BIG_PREALLOCATED_BUFFER_NOT_FOUND;

                //
                // There is a problem with allocating event
                //
                return NULL;
            }
        }
        else
        {
            //
            // The buffer doesn't fit into any of the regular or big event's preallocated buffers
            //

            //
            // Set the error
            //
            ResultsToReturn->IsSuccessful = FALSE;
            ResultsToReturn->Error        = DEBUGGER_ERROR_INSTANT_EVENT_PREALLOCATED_BUFFER_IS_NOT_ENOUGH_FOR_EVENT_AND_CONDITIONALS;

            return NULL;
        }
    }
    else
    {
        //
        // If it's not coming from the VMX-root mode then we're allocating it from the OS buffers
        //
        Event = PlatformMemAllocateZeroedNonPagedPool(EventBufferSize);

        if (!Event)
        {
            //
            // Set the error
            //
            ResultsToReturn->IsSuccessful = FALSE;
            ResultsToReturn->Error        = DEBUGGER_ERROR_UNABLE_TO_CREATE_EVENT;

            //
            // There is a problem with allocating event
            //
            return NULL;
        }
    }

    Event->CoreId         = CoreId;
    Event->ProcessId      = ProcessId;
    Event->Enabled        = Enabled;
    Event->EventType      = EventType;
    Event->Tag            = Tag;
    Event->CountOfActions = 0; // currently there is no action

    //
    // Copy Options
    //
    memcpy(&Event->InitOptions, Options, sizeof(DEBUGGER_EVENT_OPTIONS));

    //
    // check if this event is conditional or not
    //
    if (ConditionBuffer != 0)
    {
        //
        // It's conditional
        //
        Event->ConditionsBufferSize   = ConditionsBufferSize;
        Event->ConditionBufferAddress = (PVOID)((UINT64)Event + sizeof(DEBUGGER_EVENT));

        //
        // copy the condition buffer to the end of the buffer of the event
        //
        memcpy(Event->ConditionBufferAddress, ConditionBuffer, ConditionsBufferSize);
    }
    else
    {
        //
        // It's unconditioanl
        //
        Event->ConditionsBufferSize = 0;
    }

    //
    // Make the action lists ready
    //
    InitializeListHead(&Event->ActionsListHead);

    //
    // Return our event
    //
    return Event;
}

/**
 * @brief Allocates buffer for requested safe buffer
 *
 * @param SizeOfRequestedSafeBuffer The size of the requested safe buffer
 * @param ResultsToReturn The buffer address that should be returned
 * to the user-mode as the result
 * @param InputFromVmxRoot Whether the input comes from VMX root-mode or IOCTL
 *
 * @return PVOID
 */
PVOID
DebuggerAllocateSafeRequestedBuffer(SIZE_T                            SizeOfRequestedSafeBuffer,
                                    PDEBUGGER_EVENT_AND_ACTION_RESULT ResultsToReturn,
                                    BOOLEAN                           InputFromVmxRoot)
{
    PVOID RequestedBuffer = NULL;

    //
    // Check whether the buffer comes from VMX-root mode or non-root mode
    //
    if (InputFromVmxRoot)
    {
        //
        // *** The buffer is coming from VMX-root mode ***
        //

        //
        // If the requested safe buffer is smaller than regular safe buffers
        //
        if (REGULAR_INSTANT_EVENT_REQUESTED_SAFE_BUFFER >= SizeOfRequestedSafeBuffer)
        {
            //
            // The buffer fits into a regular safe requested buffer
            //
            RequestedBuffer = (PVOID)PoolManagerRequestPool(INSTANT_REGULAR_SAFE_BUFFER_FOR_EVENTS, TRUE, REGULAR_INSTANT_EVENT_REQUESTED_SAFE_BUFFER);

            if (!RequestedBuffer)
            {
                //
                // Here we try again to see if we could store it into a big instant event safe requested buffer instead
                //
                RequestedBuffer = (PVOID)PoolManagerRequestPool(INSTANT_BIG_SAFE_BUFFER_FOR_EVENTS, TRUE, BIG_INSTANT_EVENT_REQUESTED_SAFE_BUFFER);

                if (!RequestedBuffer)
                {
                    //
                    // Set the error
                    //
                    ResultsToReturn->IsSuccessful = FALSE;
                    ResultsToReturn->Error        = DEBUGGER_ERROR_INSTANT_EVENT_REGULAR_REQUESTED_SAFE_BUFFER_NOT_FOUND;

                    //
                    // There is a problem with allocating requested safe buffer
                    //
                    return NULL;
                }
            }
        }
        else if (BIG_INSTANT_EVENT_REQUESTED_SAFE_BUFFER >= SizeOfRequestedSafeBuffer)
        {
            //
            // The buffer fits into a big instant requested safe buffer
            //
            RequestedBuffer = (PVOID)PoolManagerRequestPool(INSTANT_BIG_SAFE_BUFFER_FOR_EVENTS, TRUE, BIG_INSTANT_EVENT_REQUESTED_SAFE_BUFFER);

            if (!RequestedBuffer)
            {
                //
                // Set the error
                //
                ResultsToReturn->IsSuccessful = FALSE;
                ResultsToReturn->Error        = DEBUGGER_ERROR_INSTANT_EVENT_BIG_REQUESTED_SAFE_BUFFER_NOT_FOUND;

                //
                // There is a problem with allocating event
                //
                return NULL;
            }
        }
        else
        {
            //
            // The buffer doesn't fit into any of the regular or big safe requested buffers
            //

            //
            // Set the error
            //
            ResultsToReturn->IsSuccessful = FALSE;
            ResultsToReturn->Error        = DEBUGGER_ERROR_INSTANT_EVENT_PREALLOCATED_BUFFER_IS_NOT_ENOUGH_FOR_REQUESTED_SAFE_BUFFER;

            return NULL;
        }
    }
    else
    {
        RequestedBuffer = PlatformMemAllocateZeroedNonPagedPool(SizeOfRequestedSafeBuffer);

        if (!RequestedBuffer)
        {
            ResultsToReturn->IsSuccessful = FALSE;
            ResultsToReturn->Error        = DEBUGGER_ERROR_UNABLE_TO_ALLOCATE_REQUESTED_SAFE_BUFFER;

            return NULL;
        }
    }

    return RequestedBuffer;
}

/**
 * @brief Create an action and add the action to an event
 *
 * @param Event Target event object
 * @param ActionType Type of action
 * @param SendTheResultsImmediately whether the results should be received
 * by the user-mode immediately
 * @param InTheCaseOfCustomCode Custom code structure (if any)
 * @param InTheCaseOfRunScript Run script structure (if any)
 * @param ResultsToReturn The buffer address that should be returned
 * to the user-mode as the result
 * @param InputFromVmxRoot Whether the input comes from VMX root-mode or IOCTL
 *
 * @return PDEBUGGER_EVENT_ACTION
 */
PDEBUGGER_EVENT_ACTION
DebuggerAddActionToEvent(PDEBUGGER_EVENT                                 Event,
                         DEBUGGER_EVENT_ACTION_TYPE_ENUM                 ActionType,
                         BOOLEAN                                         SendTheResultsImmediately,
                         PDEBUGGER_EVENT_REQUEST_CUSTOM_CODE             InTheCaseOfCustomCode,
                         PDEBUGGER_EVENT_ACTION_RUN_SCRIPT_CONFIGURATION InTheCaseOfRunScript,
                         PDEBUGGER_EVENT_AND_ACTION_RESULT               ResultsToReturn,
                         BOOLEAN                                         InputFromVmxRoot)
{
    PDEBUGGER_EVENT_ACTION Action;
    SIZE_T                 ActionBufferSize;
    PVOID                  RequestedBuffer = NULL;

    //
    // Allocate action + allocate code for custom code
    //

    if (InTheCaseOfCustomCode != NULL)
    {
        //
        // We should allocate extra buffer for custom code
        //
        ActionBufferSize = sizeof(DEBUGGER_EVENT_ACTION) + InTheCaseOfCustomCode->CustomCodeBufferSize;
    }
    else if (InTheCaseOfRunScript != NULL)
    {
        //
        // We should allocate extra buffer for script
        //
        ActionBufferSize = sizeof(DEBUGGER_EVENT_ACTION) + InTheCaseOfRunScript->ScriptLength;
    }
    else
    {
        //
        // We shouldn't allocate extra buffer as there is no custom code
        //
        ActionBufferSize = sizeof(DEBUGGER_EVENT_ACTION);
    }

    //
    // Allocate buffer for storing the action
    //

    if (InputFromVmxRoot)
    {
        //
        // *** The buffer is coming from VMX-root mode ***
        //

        //
        // If the buffer is smaller than regular instant events's action
        //
        if (REGULAR_INSTANT_EVENT_ACTION_BUFFER >= ActionBufferSize)
        {
            //
            // The buffer fits into a regular instant event's action
            //
            Action = (DEBUGGER_EVENT_ACTION *)PoolManagerRequestPool(INSTANT_REGULAR_EVENT_ACTION_BUFFER, TRUE, REGULAR_INSTANT_EVENT_ACTION_BUFFER);

            if (!Action)
            {
                //
                // Here we try again to see if we could store it into a big instant event's action buffer instead
                //
                Action = (DEBUGGER_EVENT_ACTION *)PoolManagerRequestPool(INSTANT_BIG_EVENT_ACTION_BUFFER, TRUE, BIG_INSTANT_EVENT_ACTION_BUFFER);

                if (!Action)
                {
                    //
                    // Set the error
                    //
                    ResultsToReturn->IsSuccessful = FALSE;
                    ResultsToReturn->Error        = DEBUGGER_ERROR_INSTANT_EVENT_ACTION_REGULAR_PREALLOCATED_BUFFER_NOT_FOUND;

                    //
                    // There is a problem with allocating event's action
                    //
                    return NULL;
                }
            }
        }
        else if (BIG_INSTANT_EVENT_ACTION_BUFFER >= ActionBufferSize)
        {
            //
            // The buffer fits into a big instant event's action buffer
            //
            Action = (DEBUGGER_EVENT_ACTION *)PoolManagerRequestPool(INSTANT_BIG_EVENT_ACTION_BUFFER, TRUE, BIG_INSTANT_EVENT_ACTION_BUFFER);

            if (!Action)
            {
                //
                // Set the error
                //
                ResultsToReturn->IsSuccessful = FALSE;
                ResultsToReturn->Error        = DEBUGGER_ERROR_INSTANT_EVENT_ACTION_BIG_PREALLOCATED_BUFFER_NOT_FOUND;

                //
                // There is a problem with allocating event's action buffer
                //
                return NULL;
            }
        }
        else
        {
            //
            // The buffer doesn't fit into any of the regular or big event's action preallocated buffers
            //

            //
            // Set the error
            //
            ResultsToReturn->IsSuccessful = FALSE;
            ResultsToReturn->Error        = DEBUGGER_ERROR_INSTANT_EVENT_PREALLOCATED_BUFFER_IS_NOT_ENOUGH_FOR_ACTION_BUFFER;

            return NULL;
        }
    }
    else
    {
        //
        // If it's not coming from the VMX-root mode then we're allocating it from the OS buffers
        //
        Action = PlatformMemAllocateZeroedNonPagedPool(ActionBufferSize);

        if (Action == NULL)
        {
            //
            // Set the appropriate error
            //
            ResultsToReturn->IsSuccessful = FALSE;
            ResultsToReturn->Error        = DEBUGGER_ERROR_UNABLE_TO_CREATE_ACTION_CANNOT_ALLOCATE_BUFFER;

            //
            // There was an error in allocation
            //
            return NULL;
        }
    }

    //
    // If the user needs a buffer to be passed to the debugger then
    // we should allocate it here (Requested buffer is only available for custom code types)
    //
    if (ActionType == RUN_CUSTOM_CODE &&
        InTheCaseOfCustomCode != NULL &&
        InTheCaseOfCustomCode->OptionalRequestedBufferSize != 0)
    {
        //
        // Check if the optional buffer is not more that the size
        // we can send to usermode
        //
        if (InTheCaseOfCustomCode->OptionalRequestedBufferSize >= MaximumPacketsCapacity)
        {
            //
            // There was an error
            //
            if (InputFromVmxRoot)
            {
                PoolManagerFreePool((UINT64)Action);
            }
            else
            {
                PlatformMemFreePool(Action);
            }

            //
            // Set the appropriate error
            //
            ResultsToReturn->IsSuccessful = FALSE;
            ResultsToReturn->Error        = DEBUGGER_ERROR_INSTANT_EVENT_REQUESTED_OPTIONAL_BUFFER_IS_BIGGER_THAN_DEBUGGERS_SEND_RECEIVE_STACK;

            return NULL;
        }

        //
        // User needs a buffer to play with
        //
        RequestedBuffer = DebuggerAllocateSafeRequestedBuffer(InTheCaseOfCustomCode->OptionalRequestedBufferSize, ResultsToReturn, InputFromVmxRoot);

        if (!RequestedBuffer)
        {
            //
            // There was an error in allocation
            //
            if (InputFromVmxRoot)
            {
                PoolManagerFreePool((UINT64)Action);
            }
            else
            {
                PlatformMemFreePool(Action);
            }

            //
            // Not need to set error as the above function already adjust the error
            //
            return NULL;
        }

        //
        // Add it to the action
        //
        Action->RequestedBuffer.EnabledRequestBuffer = TRUE;
        Action->RequestedBuffer.RequestBufferSize    = InTheCaseOfCustomCode->OptionalRequestedBufferSize;
        Action->RequestedBuffer.RequstBufferAddress  = (UINT64)RequestedBuffer;
    }

    //
    // If the user needs a buffer to be passed to the debugger script then
    // we should allocate it here (Requested buffer is only available for custom code types)
    //
    if (ActionType == RUN_SCRIPT &&
        InTheCaseOfRunScript != NULL &&
        InTheCaseOfRunScript->OptionalRequestedBufferSize != 0)
    {
        //
        // Check if the optional buffer is not more that the size
        // we can send to usermode
        //
        if (InTheCaseOfRunScript->OptionalRequestedBufferSize >= MaximumPacketsCapacity)
        {
            //
            // There was an error
            //
            if (InputFromVmxRoot)
            {
                PoolManagerFreePool((UINT64)Action);
            }
            else
            {
                PlatformMemFreePool(Action);
            }

            //
            // Set the appropriate error
            //
            ResultsToReturn->IsSuccessful = FALSE;
            ResultsToReturn->Error        = DEBUGGER_ERROR_INSTANT_EVENT_REQUESTED_OPTIONAL_BUFFER_IS_BIGGER_THAN_DEBUGGERS_SEND_RECEIVE_STACK;

            return NULL;
        }

        //
        // User needs a buffer to play with
        //
        RequestedBuffer = DebuggerAllocateSafeRequestedBuffer(InTheCaseOfRunScript->OptionalRequestedBufferSize, ResultsToReturn, InputFromVmxRoot);

        if (!RequestedBuffer)
        {
            //
            // There was an error in allocation
            //
            if (InputFromVmxRoot)
            {
                PoolManagerFreePool((UINT64)Action);
            }
            else
            {
                PlatformMemFreePool(Action);
            }

            //
            // Not need to set error as the above function already adjust the error
            //
            return NULL;
        }

        //
        // Add it to the action
        //
        Action->RequestedBuffer.EnabledRequestBuffer = TRUE;
        Action->RequestedBuffer.RequestBufferSize    = InTheCaseOfRunScript->OptionalRequestedBufferSize;
        Action->RequestedBuffer.RequstBufferAddress  = (UINT64)RequestedBuffer;
    }

    if (ActionType == RUN_CUSTOM_CODE && InTheCaseOfCustomCode != NULL)
    {
        //
        // Check if it's a Custom code without custom code buffer which is invalid
        //
        if (InTheCaseOfCustomCode != NULL && InTheCaseOfCustomCode->CustomCodeBufferSize == 0)
        {
            //
            // There was an error
            //
            if (InputFromVmxRoot)
            {
                PoolManagerFreePool((UINT64)Action);

                if (RequestedBuffer != NULL)
                {
                    PoolManagerFreePool((UINT64)RequestedBuffer);
                }
            }
            else
            {
                PlatformMemFreePool(Action);

                if (RequestedBuffer != NULL)
                {
                    PlatformMemFreePool(RequestedBuffer);
                }
            }

            ResultsToReturn->IsSuccessful = FALSE;
            ResultsToReturn->Error        = DEBUGGER_ERROR_ACTION_BUFFER_SIZE_IS_ZERO;

            return NULL;
        }

        //
        // Move the custom code buffer to the end of the action
        //
        Action->CustomCodeBufferSize    = InTheCaseOfCustomCode->CustomCodeBufferSize;
        Action->CustomCodeBufferAddress = (PVOID)((UINT64)Action + sizeof(DEBUGGER_EVENT_ACTION));

        //
        // copy the custom code buffer to the end of the buffer of the action
        //
        memcpy(Action->CustomCodeBufferAddress, InTheCaseOfCustomCode->CustomCodeBufferAddress, InTheCaseOfCustomCode->CustomCodeBufferSize);
    }

    //
    // If it's run script action type
    //
    else if (ActionType == RUN_SCRIPT && InTheCaseOfRunScript != NULL)
    {
        //
        // Check the buffers of run script
        //
        if (InTheCaseOfRunScript->ScriptBuffer == NULL64_ZERO || InTheCaseOfRunScript->ScriptLength == NULL_ZERO)
        {
            //
            // There was an error
            //
            if (InputFromVmxRoot)
            {
                PoolManagerFreePool((UINT64)Action);

                if (RequestedBuffer != 0)
                {
                    PoolManagerFreePool((UINT64)RequestedBuffer);
                }
            }
            else
            {
                PlatformMemFreePool(Action);

                if (RequestedBuffer != 0)
                {
                    PlatformMemFreePool(RequestedBuffer);
                }
            }

            ResultsToReturn->IsSuccessful = FALSE;
            ResultsToReturn->Error        = DEBUGGER_ERROR_ACTION_BUFFER_SIZE_IS_ZERO;

            return NULL;
        }

        //
        // Allocate the buffer from a non-page pool on the script
        //
        Action->ScriptConfiguration.ScriptBuffer = (UINT64)((BYTE *)Action + sizeof(DEBUGGER_EVENT_ACTION));

        //
        // Copy the memory of script to our non-paged pool
        //
        RtlCopyMemory((PVOID)Action->ScriptConfiguration.ScriptBuffer, (const PVOID)InTheCaseOfRunScript->ScriptBuffer, InTheCaseOfRunScript->ScriptLength);

        //
        // Set other fields
        //
        Action->ScriptConfiguration.ScriptLength                = InTheCaseOfRunScript->ScriptLength;
        Action->ScriptConfiguration.ScriptPointer               = InTheCaseOfRunScript->ScriptPointer;
        Action->ScriptConfiguration.OptionalRequestedBufferSize = InTheCaseOfRunScript->OptionalRequestedBufferSize;
    }

    //
    // Create an order code for the current action
    // and also increase the Count of action in event
    //
    Event->CountOfActions++;
    Action->ActionOrderCode = Event->CountOfActions;

    //
    // Fill other parts of the action
    //
    Action->ImmediatelySendTheResults = SendTheResultsImmediately;
    Action->ActionType                = ActionType;
    Action->Tag                       = Event->Tag;

    //
    // Now we should add the action to the event's LIST_ENTRY of actions
    //
    InsertHeadList(&Event->ActionsListHead, &(Action->ActionsList));

    return Action;
}

/**
 * @brief Register an event to a list of active events
 *
 * @param Event Event structure
 * @return BOOLEAN TRUE if it successfully registered and FALSE if not registered
 */
BOOLEAN
DebuggerRegisterEvent(PDEBUGGER_EVENT Event)
{
    PLIST_ENTRY TargetEventList = NULL;

    //
    // Register the event
    //
    TargetEventList = DebuggerGetEventListByEventType(Event->EventType);

    if (TargetEventList != NULL)
    {
        InsertHeadList(TargetEventList, &(Event->EventsOfSameTypeList));

        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

/**
 * @brief Trigger events of a special type to be managed by debugger
 *
 * @param EventType Type of events
 * @param CallingStage Stage of calling (pre-event or post-event)
 * @param Context An optional parameter (different in each event)
 * @param PostEventRequired Whether the caller is requested to
 * trigger a post-event event
 * @param Regs Guest gp-registers
 *
 * @return VMM_CALLBACK_TRIGGERING_EVENT_STATUS_TYPE returns the status
 * of handling events
 */
VMM_CALLBACK_TRIGGERING_EVENT_STATUS_TYPE
DebuggerTriggerEvents(VMM_EVENT_TYPE_ENUM                   EventType,
                      VMM_CALLBACK_EVENT_CALLING_STAGE_TYPE CallingStage,
                      PVOID                                 Context,
                      BOOLEAN *                             PostEventRequired,
                      GUEST_REGS *                          Regs)
{
    PROCESSOR_DEBUGGING_STATE *      DbgState = NULL;
    DebuggerCheckForCondition *      ConditionFunc;
    DEBUGGER_TRIGGERED_EVENT_DETAILS EventTriggerDetail = {0};
    PEPT_HOOKS_CONTEXT               EptContext;
    PLIST_ENTRY                      TempList         = 0;
    PLIST_ENTRY                      TempList2        = 0;
    const PVOID                      OriginalContext  = Context;
    BOOLEAN                          SkipUserModeCall = FALSE;
    BOOLEAN                          CallEpilogue     = FALSE;

    //
    // Check if triggering debugging actions are allowed or not
    //
    if (!g_EnableDebuggerVmxEvents || g_InterceptBreakpointsAndEventsForCommandsInRemoteComputer)
    {
        //
        // Debugger is not enabled
        //
        return VMM_CALLBACK_TRIGGERING_EVENT_STATUS_DEBUGGER_NOT_ENABLED;
    }

    //
    // Find the debugging state structure
    //
    DbgState = &g_DbgState[KeGetCurrentProcessorNumberEx(NULL)];

    //
    // Set the registers for debug state
    //
    DbgState->Regs = Regs;

    //
    // Find the debugger events list base on the type of the event
    //
    TempList  = DebuggerGetEventListByEventType(EventType);
    TempList2 = TempList;

    if (TempList == NULL)
    {
        return VMM_CALLBACK_TRIGGERING_EVENT_STATUS_INVALID_EVENT_TYPE;
    }

    while (TempList2 != TempList->Flink)
    {
        TempList                     = TempList->Flink;
        PDEBUGGER_EVENT CurrentEvent = CONTAINING_RECORD(TempList, DEBUGGER_EVENT, EventsOfSameTypeList);

        //
        // check if the event is enabled or not
        //
        if (!CurrentEvent->Enabled)
        {
            continue;
        }

        //
        // Check if this event is for this core or not
        //
        if (CurrentEvent->CoreId != DEBUGGER_EVENT_APPLY_TO_ALL_CORES && CurrentEvent->CoreId != DbgState->CoreId)
        {
            //
            // This event is not related to either or core or all cores
            //
            continue;
        }

        //
        // Check if this event is for this process or not
        //
        if (CurrentEvent->ProcessId != DEBUGGER_EVENT_APPLY_TO_ALL_PROCESSES && CurrentEvent->ProcessId != HANDLE_TO_UINT32(PsGetCurrentProcessId()))
        {
            //
            // This event is not related to either our process or all processes
            //
            continue;
        }

        //
        // Check event type specific conditions, if the event is not mentioned
        // here, it means that it doesn't have any special condition
        //
        switch (CurrentEvent->EventType)
        {
        case EXTERNAL_INTERRUPT_OCCURRED:

            //
            // For external interrupt exiting events we check whether the
            // vector match the event's vector or not
            //
            // Context is the physical address
            //
            if ((UINT64)Context != CurrentEvent->Options.OptionalParam1)
            {
                //
                // The interrupt is not for this event
                //
                continue;
            }

            break;

        case HIDDEN_HOOK_READ_AND_WRITE_AND_EXECUTE:
        case HIDDEN_HOOK_READ_AND_WRITE:
        case HIDDEN_HOOK_READ_AND_EXECUTE:
        case HIDDEN_HOOK_WRITE_AND_EXECUTE:
        case HIDDEN_HOOK_READ:
        case HIDDEN_HOOK_WRITE:
        case HIDDEN_HOOK_EXECUTE:

            //
            // For hidden hook read/write/execute we check whether the address
            // is in the range of what user specified or not, this is because
            // we get the events for all hidden hooks in a page granularity
            //

            //
            // Here the OriginalContext is used because the context
            // might be changed but the OriginalContext is constant
            //
            EptContext = (PEPT_HOOKS_CONTEXT)OriginalContext;

            //
            // EPT context should be checked with hooking tag
            // The hooking tag is same as the event tag if both
            // of them match together
            //
            if (EptContext->HookingTag != CurrentEvent->Tag)
            {
                //
                // The value is not within our expected range
                //
                continue;
            }
            else
            {
                //
                // Fix the context to virtual address
                //
                Context = (PVOID)EptContext->VirtualAddress;
            }

            break;

        case HIDDEN_HOOK_EXEC_CC:

            //
            // Here we check if it's HIDDEN_HOOK_EXEC_CC then it means
            // so we have to make sure to perform its actions only if
            // the hook is triggered for the address described in
            // event, note that address in event is a virtual address
            //
            if ((UINT64)Context != CurrentEvent->Options.OptionalParam1)
            {
                //
                // Context is the virtual address
                //

                //
                // The hook is not for this (virtual) address
                //
                continue;
            }

            //
            // Call the prologue function
            //
            SkipUserModeCall = MasoudPrologue(DbgState->CoreId, Context, Regs);

            if (SkipUserModeCall)
            {
                continue;
            }
            else
            {
                CallEpilogue = TRUE;
            }

            break;

        case HIDDEN_HOOK_EXEC_DETOURS:

            //
            // Here the OriginalContext is used because the context
            // might be changed but the OriginalContext is constant
            //
            EptContext = (PEPT_HOOKS_CONTEXT)OriginalContext;

            //
            // Here we check if it's HIDDEN_HOOK_EXEC_DETOURS
            // then it means that it's detours hidden hook exec so we have
            // to make sure to perform its actions, only if the hook is triggered
            // for the address described in event, note that address in event is
            // a physical address and the address that the function that triggers
            // these events and sent here as the context is also converted to its
            // physical form
            // This way we are sure that no one can bypass our hook by remapping
            // address to another virtual address as everything is physical
            //
            if (EptContext->PhysicalAddress != CurrentEvent->Options.OptionalParam1)
            {
                //
                // Context is the physical address
                //

                //
                // The hook is not for this (physical) address
                //
                continue;
            }
            else
            {
                //
                // Convert it to virtual address
                //
                Context = (PVOID)(EptContext->VirtualAddress);
            }

            break;

        case RDMSR_INSTRUCTION_EXECUTION:
        case WRMSR_INSTRUCTION_EXECUTION:

            //
            // check if MSR exit is what we want or not
            //
            if (CurrentEvent->Options.OptionalParam1 != DEBUGGER_EVENT_MSR_READ_OR_WRITE_ALL_MSRS && CurrentEvent->Options.OptionalParam1 != (UINT64)Context)
            {
                //
                // The msr is not what we want
                //
                continue;
            }

            break;

        case EXCEPTION_OCCURRED:

            //
            // check if exception is what we need or not
            //
            if (CurrentEvent->Options.OptionalParam1 != DEBUGGER_EVENT_EXCEPTIONS_ALL_FIRST_32_ENTRIES && CurrentEvent->Options.OptionalParam1 != (UINT64)Context)
            {
                //
                // The exception is not what we want
                //
                continue;
            }

            break;

        case IN_INSTRUCTION_EXECUTION:
        case OUT_INSTRUCTION_EXECUTION:

            //
            // check if I/O port is what we want or not
            //
            if (CurrentEvent->Options.OptionalParam1 != DEBUGGER_EVENT_ALL_IO_PORTS && CurrentEvent->Options.OptionalParam1 != (UINT64)Context)
            {
                //
                // The port is not what we want
                //
                continue;
            }

            break;

        case SYSCALL_HOOK_EFER_SYSCALL:

            //
            // case SYSCALL_HOOK_EFER_SYSRET:
            //
            // I don't know how to find syscall number when sysret is executed so
            // that's why we don't support extra argument for sysret
            //

            //
            // check syscall number
            //
            if (CurrentEvent->Options.OptionalParam1 != DEBUGGER_EVENT_SYSCALL_ALL_SYSRET_OR_SYSCALLS && CurrentEvent->Options.OptionalParam1 != (UINT64)Context)
            {
                //
                // The syscall number is not what we want
                //
                continue;
            }

            break;

        case CPUID_INSTRUCTION_EXECUTION:

            //
            // check if CPUID is what we want or not
            //
            if (CurrentEvent->Options.OptionalParam1 != (UINT64)NULL /*FALSE*/ && CurrentEvent->Options.OptionalParam2 != (UINT64)Context)
            {
                //
                // The CPUID is not what we want (and the user didn't intend to get all CPUIDs)
                //
                continue;
            }

            //
            // WinAFL persistence park: the parked guest polls for GO by running a
            // delay loop + CPUID. If this CPUID is our park stub, handle it and return
            // TRUE so `continue` skips this event's script action (no per-poll
            // notification flood) AND HvHandleCpuid, leaving DbgState->ShortCircuitingEvent
            // set. On GO/STOP the handler redirects RIP + suppresses the increment; on
            // idle it leaves the increment so RIP advances past the CPUID and the stub
            // keeps spinning. Only CPUIDs that are NOT our park stub fall through to
            // normal emulation (so the target's own CPUIDs still get correct results).
            //
            if (WinaflHookOnParkCpuid(DbgState))
            {
                continue;
            }

            break;

        case CONTROL_REGISTER_MODIFIED:

            //
            // check if CR exit is what we want or not
            //
            if (CurrentEvent->Options.OptionalParam1 != (UINT64)Context)
            {
                //
                // The CR is not what we want
                //
                continue;
            }

            break;

        case TRAP_EXECUTION_MODE_CHANGED:

            //
            // check if the debugger needs user-to-kernel or kernel-to-user events
            //
            if (CurrentEvent->Options.OptionalParam1 != DEBUGGER_EVENT_MODE_TYPE_USER_MODE_AND_KERNEL_MODE)
            {
                if ((CurrentEvent->Options.OptionalParam1 == DEBUGGER_EVENT_MODE_TYPE_USER_MODE &&
                     Context == (PVOID)DEBUGGER_EVENT_MODE_TYPE_KERNEL_MODE) ||
                    (CurrentEvent->Options.OptionalParam1 == DEBUGGER_EVENT_MODE_TYPE_KERNEL_MODE &&
                     Context == (PVOID)DEBUGGER_EVENT_MODE_TYPE_USER_MODE))
                {
                    continue;
                }
            }

            break;

        case XSETBV_INSTRUCTION_EXECUTION:

            //
            // check if XSETBV is what we want or not
            //
            if (CurrentEvent->Options.OptionalParam1 != (UINT64)NULL /*FALSE*/ && CurrentEvent->Options.OptionalParam2 != (UINT64)Context)
            {
                //
                // The XCR is not what we want (and the user didn't intend to get all XSETBVs)
                //
                continue;
            }

            break;

        default: // All other events that don't have conditions
            break;
        }

        //
        // Check the stage of calling (pre, all, or post event)
        //
        if (CallingStage == VMM_CALLBACK_CALLING_STAGE_PRE_EVENT_EMULATION &&
            (CurrentEvent->EventMode == VMM_CALLBACK_CALLING_STAGE_ALL_EVENT_EMULATION ||
             CurrentEvent->EventMode == VMM_CALLBACK_CALLING_STAGE_POST_EVENT_EMULATION))
        {
            //
            // Here it means that the current event is a post, or all event event
            // and the current stage of calling is for the pre-event events, thus
            // this event is not supposed to be ran at the current stage.
            // However, we'll set a flag so the caller will know that there is
            // a valid post-event available for the parameters related to this
            // event.
            // This mechanism notifies the caller to trigger the event after
            // emulation, we implement it in a way that the caller knows when
            // to trigger a post-event thus it optimizes the number of times
            // that the caller triggers the events and avoid unnecessary triggering
            // of the event (for post-event) but at the same time we have the
            // flexibility of having both pre-event and post-event concepts
            //
            *PostEventRequired = TRUE;

            if (CurrentEvent->EventMode == VMM_CALLBACK_CALLING_STAGE_POST_EVENT_EMULATION)
            {
                //
                // If it's not an 'all' event and it is only the 'post' event,
                // then we ignore the trigger stage
                //
                continue;
            }
        }

        //
        // Check if condition is met or not , if the condition
        // is not met then we have to avoid performing the actions
        //
        if (CurrentEvent->ConditionsBufferSize != 0)
        {
            //
            // Means that there is some conditions
            //
            ConditionFunc = (DebuggerCheckForCondition *)CurrentEvent->ConditionBufferAddress;

            //
            // Run and check for results
            //
            // Because the user might change the nonvolatile registers, we save fastcall nonvolatile registers
            //
            if (AsmDebuggerConditionCodeHandler((UINT64)DbgState->Regs, (UINT64)Context, (UINT64)ConditionFunc) == 0)
            {
                //
                // The condition function returns null, mean that the
                // condition didn't met, we can ignore this event
                //
                continue;
            }
        }

        //
        // Reset the event ignorance mechanism (apply 'sc on/off' to the events)
        //
        DbgState->ShortCircuitingEvent = CurrentEvent->EnableShortCircuiting;

        //
        // Setup event trigger detail
        //
        EventTriggerDetail.Context = Context;
        EventTriggerDetail.Tag     = CurrentEvent->Tag;
        EventTriggerDetail.Stage   = CallingStage;

        //
        // perform the actions
        //
        DebuggerPerformActions(DbgState, CurrentEvent, &EventTriggerDetail);

        //
        // Check if Epilogue needs to be called
        //
        if (CallEpilogue)
        {
            MasoudEpilogue(DbgState->CoreId, Context, Regs);
        }
    }

    //
    // Check if the event should be ignored or not
    //
    if (DbgState->ShortCircuitingEvent)
    {
        //
        // Reset the event ignorance (short-circuit) mechanism
        //
        DbgState->ShortCircuitingEvent = FALSE;

        //
        // Event should be ignored
        //
        return VMM_CALLBACK_TRIGGERING_EVENT_STATUS_SUCCESSFUL_IGNORE_EVENT;
    }
    else
    {
        //
        // Event shouldn't be ignored
        //
        return VMM_CALLBACK_TRIGGERING_EVENT_STATUS_SUCCESSFUL;
    }
}

/**
 * @brief Run a special event's action(s)
 *
 * @param DbgState The state of the debugger on the current core
 * @param Event Event Object
 * @param EventTriggerDetail Event trigger details
 *
 * @return VOID
 */
VOID
DebuggerPerformActions(PROCESSOR_DEBUGGING_STATE *        DbgState,
                       DEBUGGER_EVENT *                   Event,
                       DEBUGGER_TRIGGERED_EVENT_DETAILS * EventTriggerDetail)
{
    PLIST_ENTRY TempList = 0;

    //
    // Find and run all the actions in this Event
    //
    TempList = &Event->ActionsListHead;
    while (&Event->ActionsListHead != TempList->Flink)
    {
        TempList                             = TempList->Flink;
        PDEBUGGER_EVENT_ACTION CurrentAction = CONTAINING_RECORD(TempList, DEBUGGER_EVENT_ACTION, ActionsList);

        //
        // Perform the action
        //
        switch (CurrentAction->ActionType)
        {
        case BREAK_TO_DEBUGGER:

            DebuggerPerformBreakToDebugger(DbgState, CurrentAction, EventTriggerDetail);

            break;

        case RUN_SCRIPT:

            DebuggerPerformRunScript(DbgState, CurrentAction, NULL, EventTriggerDetail);

            break;

        case RUN_CUSTOM_CODE:

            DebuggerPerformRunTheCustomCode(DbgState, CurrentAction, EventTriggerDetail);

            break;

        default:

            //
            // Invalid action type
            //
            break;
        }
    }
}

/**
 * @brief Managing run script action
 *
 * @param DbgState The state of the debugger on the current core
 * @param Action Action object
 * @param ScriptDetails Details of script
 * @param EventTriggerDetail Event trigger detail
 * @return BOOLEAN
 */
BOOLEAN
DebuggerPerformRunScript(PROCESSOR_DEBUGGING_STATE *        DbgState,
                         DEBUGGER_EVENT_ACTION *            Action,
                         DEBUGGEE_SCRIPT_PACKET *           ScriptDetails,
                         DEBUGGER_TRIGGERED_EVENT_DETAILS * EventTriggerDetail)
{
    SYMBOL_BUFFER                   CodeBuffer             = {0};
    ACTION_BUFFER                   ActionBuffer           = {0};
    SYMBOL                          ErrorSymbol            = {0};
    SCRIPT_ENGINE_GENERAL_REGISTERS ScriptGeneralRegisters = {0};

    if (Action != NULL)
    {
        //
        // Fill the action buffer's calling stage
        //
        if (EventTriggerDetail->Stage == VMM_CALLBACK_CALLING_STAGE_POST_EVENT_EMULATION)
        {
            ActionBuffer.CallingStage = 1;
        }
        else
        {
            ActionBuffer.CallingStage = 0;
        }

        //
        // Fill the action buffer
        //
        ActionBuffer.Context                   = (UINT64)EventTriggerDetail->Context;
        ActionBuffer.Tag                       = EventTriggerDetail->Tag;
        ActionBuffer.ImmediatelySendTheResults = Action->ImmediatelySendTheResults;
        ActionBuffer.CurrentAction             = (UINT64)Action;

        //
        // Context point to the registers
        //
        CodeBuffer.Head    = (PSYMBOL)Action->ScriptConfiguration.ScriptBuffer;
        CodeBuffer.Size    = Action->ScriptConfiguration.ScriptLength;
        CodeBuffer.Pointer = Action->ScriptConfiguration.ScriptPointer;
    }
    else if (ScriptDetails != NULL)
    {
        //
        // Fill the action buffer's calling stage
        //
        if (EventTriggerDetail->Stage == VMM_CALLBACK_CALLING_STAGE_POST_EVENT_EMULATION)
        {
            ActionBuffer.CallingStage = 1;
        }
        else
        {
            ActionBuffer.CallingStage = 0;
        }

        //
        // Fill the action buffer
        //
        ActionBuffer.Context                   = (UINT64)EventTriggerDetail->Context;
        ActionBuffer.Tag                       = EventTriggerDetail->Tag;
        ActionBuffer.ImmediatelySendTheResults = TRUE;
        ActionBuffer.CurrentAction             = (UINT64)NULL;

        //
        // Context point to the registers
        //
        CodeBuffer.Head    = (SYMBOL *)((CHAR *)ScriptDetails + sizeof(DEBUGGEE_SCRIPT_PACKET));
        CodeBuffer.Size    = ScriptDetails->ScriptBufferSize;
        CodeBuffer.Pointer = ScriptDetails->ScriptBufferPointer;
    }
    else
    {
        //
        // The parameters are wrong !
        //
        return FALSE;
    }

    //
    // Fill the stack buffer for this run
    //
    ScriptGeneralRegisters.StackBuffer         = DbgState->ScriptEngineCoreSpecificStackBuffer;
    ScriptGeneralRegisters.GlobalVariablesList = g_ScriptGlobalVariables;
    RtlZeroMemory(ScriptGeneralRegisters.StackBuffer, MAX_STACK_BUFFER_COUNT * sizeof(UINT64));

    UINT64 EXECUTENUMBER = 0;

    for (UINT64 i = 0; i < CodeBuffer.Pointer;)
    {
        //
        // If has error, show error message and abort.
        //

        if (ScriptEngineExecute(DbgState->Regs,
                                &ActionBuffer,
                                &ScriptGeneralRegisters,
                                &CodeBuffer,
                                &i,
                                &ErrorSymbol) == TRUE)
        {
            LogInfo("Err, ScriptEngineExecute, function = % s\n ",
                    FunctionNames[ErrorSymbol.Value]);
            break;
        }
        else if (ScriptGeneralRegisters.StackIndx >= MAX_STACK_BUFFER_COUNT)
        {
            LogInfo("Err, stack buffer overflow (more information: https://docs.hyperdbg.org/tips-and-tricks/misc/customize-build/change-script-engine-limitations)\n");
            break;
        }
        else if (EXECUTENUMBER >= MAX_EXECUTION_COUNT)
        {
            LogInfo("Err, exceeding the max execution count (more information: https://docs.hyperdbg.org/tips-and-tricks/misc/customize-build/change-script-engine-limitations)\n");
            break;
        }

        EXECUTENUMBER++;
    }

    return TRUE;
}

/**
 * @brief Manage running the custom code action
 *
 * @param DbgState The state of the debugger on the current core
 * @param Action Action object
 * @param EventTriggerDetail Event trigger detail
 *
 * @return VOID
 */
VOID
DebuggerPerformRunTheCustomCode(PROCESSOR_DEBUGGING_STATE *        DbgState,
                                DEBUGGER_EVENT_ACTION *            Action,
                                DEBUGGER_TRIGGERED_EVENT_DETAILS * EventTriggerDetail)
{
    if (Action->CustomCodeBufferSize == 0)
    {
        //
        // Sth went wrong ! the buffer size for custom code shouldn't be zero
        //
        return;
    }

    //
    // -----------------------------------------------------------------------------------------------------
    // Test
    //
    // LogInfo("%X       Called from : %llx", Tag, Context);
    //
    //
    // LogInfo("Process Id : %x , Rax : %llx , R8 : %llx , Context : 0x%llx ", PsGetCurrentProcessId(), Regs->rax, Regs->r8, Context);
    // return;
    //
    // -----------------------------------------------------------------------------------------------------
    //

    //
    // Run the custom code
    //
    if (Action->RequestedBuffer.RequestBufferSize == 0)
    {
        //
        // Because the user might change the nonvolatile registers, we save fastcall nonvolatile registers
        //
        AsmDebuggerCustomCodeHandler((UINT64)NULL,
                                     (UINT64)DbgState->Regs,
                                     (UINT64)EventTriggerDetail->Context,
                                     (UINT64)Action->CustomCodeBufferAddress);
    }
    else
    {
        //
        // Because the user might change the nonvolatile registers, we save fastcall nonvolatile registers
        //
        AsmDebuggerCustomCodeHandler((UINT64)Action->RequestedBuffer.RequstBufferAddress,
                                     (UINT64)DbgState->Regs,
                                     (UINT64)EventTriggerDetail->Context,
                                     (UINT64)Action->CustomCodeBufferAddress);
    }
}

/**
 * @brief Manage breaking to the debugger action
 *
 * @param DbgState The state of the debugger on the current core
 * @param Tag Tag of event
 * @param Action Action object
 * @param EventTriggerDetail Event trigger detail
 *
 * @return VOID
 */
VOID
DebuggerPerformBreakToDebugger(PROCESSOR_DEBUGGING_STATE *        DbgState,
                               DEBUGGER_EVENT_ACTION *            Action,
                               DEBUGGER_TRIGGERED_EVENT_DETAILS * EventTriggerDetail)
{
    UNREFERENCED_PARAMETER(Action);

    if (VmFuncVmxGetCurrentExecutionMode() == TRUE)
    {
        //
        // The guest is already in vmx-root mode
        // Halt other cores
        //

        KdHandleBreakpointAndDebugBreakpoints(
            DbgState,
            DEBUGGEE_PAUSING_REASON_DEBUGGEE_EVENT_TRIGGERED,
            EventTriggerDetail);
    }
    else
    {
        //
        // The guest is on vmx non-root mode and this is an event
        //
        VmFuncVmxVmcall(DEBUGGER_VMCALL_VM_EXIT_HALT_SYSTEM_AS_A_RESULT_OF_TRIGGERING_EVENT,
                        (UINT64)EventTriggerDetail,
                        (UINT64)DbgState->Regs,
                        (UINT64)NULL);
    }
}

/**
 * @brief Find event object by tag
 *
 * @param Tag Tag of event
 * @return PDEBUGGER_EVENT Returns null if not found and event object if found
 */
PDEBUGGER_EVENT
DebuggerGetEventByTag(UINT64 Tag)
{
    PLIST_ENTRY TempList  = 0;
    PLIST_ENTRY TempList2 = 0;

    //
    // We have to iterate through all events
    //
    for (SIZE_T i = 0; i < sizeof(DEBUGGER_CORE_EVENTS) / sizeof(LIST_ENTRY); i++)
    {
        TempList  = (PLIST_ENTRY)((UINT64)(g_Events) + (i * sizeof(LIST_ENTRY)));
        TempList2 = TempList;

        while (TempList2 != TempList->Flink)
        {
            TempList                     = TempList->Flink;
            PDEBUGGER_EVENT CurrentEvent = CONTAINING_RECORD(TempList, DEBUGGER_EVENT, EventsOfSameTypeList);

            //
            // Check if we find the event or not
            //
            if (CurrentEvent->Tag == Tag)
            {
                return CurrentEvent;
            }
        }
    }

    //
    // We didn't find anything, so return null
    //
    return NULL;
}

/**
 * @brief Enable or disable all events from all the types
 *
 * @param IsEnable If you want to enable then true and if
 * you want to disable then false
 * @return BOOLEAN if at least one event enabled/disabled then
 * it returns true, and otherwise false
 */
BOOLEAN
DebuggerEnableOrDisableAllEvents(BOOLEAN IsEnable)
{
    BOOLEAN     FindAtLeastOneEvent = FALSE;
    PLIST_ENTRY TempList            = 0;
    PLIST_ENTRY TempList2           = 0;

    //
    // We have to iterate through all events
    //
    for (SIZE_T i = 0; i < sizeof(DEBUGGER_CORE_EVENTS) / sizeof(LIST_ENTRY); i++)
    {
        TempList  = (PLIST_ENTRY)((UINT64)(g_Events) + (i * sizeof(LIST_ENTRY)));
        TempList2 = TempList;

        while (TempList2 != TempList->Flink)
        {
            TempList                     = TempList->Flink;
            PDEBUGGER_EVENT CurrentEvent = CONTAINING_RECORD(TempList, DEBUGGER_EVENT, EventsOfSameTypeList);

            //
            // Check if we find at least one event or not
            //
            if (!FindAtLeastOneEvent)
            {
                FindAtLeastOneEvent = TRUE;
            }

            //
            // Enable or disable event
            // (We could directly modify the "enabled" flag here, however
            // in the case of any possible callback for enabling/disabling let's
            // modify the state of being enable all of them in a single place)
            //
            if (IsEnable)
            {
                DebuggerEnableEvent(CurrentEvent->Tag);
            }
            else
            {
                DebuggerDisableEvent(CurrentEvent->Tag);
            }
        }
    }

    return FindAtLeastOneEvent;
}

/**
 * @brief Terminate effect and configuration to vmx-root
 * and non-root for all the events
 *
 * @param InputFromVmxRoot Whether the input comes from VMX root-mode or IOCTL
 *
 * @return BOOLEAN if at least one event terminated then
 * it returns true, and otherwise false
 */
BOOLEAN
DebuggerTerminateAllEvents(BOOLEAN InputFromVmxRoot)
{
    BOOLEAN     FindAtLeastOneEvent = FALSE;
    PLIST_ENTRY TempList            = 0;
    PLIST_ENTRY TempList2           = 0;

    //
    // We have to iterate through all events
    //
    for (SIZE_T i = 0; i < sizeof(DEBUGGER_CORE_EVENTS) / sizeof(LIST_ENTRY); i++)
    {
        TempList  = (PLIST_ENTRY)((UINT64)(g_Events) + (i * sizeof(LIST_ENTRY)));
        TempList2 = TempList;

        while (TempList2 != TempList->Flink)
        {
            TempList                     = TempList->Flink;
            PDEBUGGER_EVENT CurrentEvent = CONTAINING_RECORD(TempList, DEBUGGER_EVENT, EventsOfSameTypeList);

            //
            // Check if we find at least one event or not
            //
            if (!FindAtLeastOneEvent)
            {
                FindAtLeastOneEvent = TRUE;
            }

            //
            // Terminate the current event
            //
            DebuggerTerminateEvent(CurrentEvent->Tag, InputFromVmxRoot);
        }
    }

    return FindAtLeastOneEvent;
}

/**
 * @brief Remove all the events from all the lists
 * and also de-allocate their structures and actions
 *
 * @details should not be called from vmx-root mode, also
 * it won't terminate their effects, so the events should
 * be terminated first then we can remove them
 *
 * @param PoolManagerAllocatedMemory Whether the pools are allocated from the
 * pool manager or original OS pools
 *
 * @return BOOLEAN if at least one event removed then
 * it returns true, and otherwise false
 */
BOOLEAN
DebuggerRemoveAllEvents(BOOLEAN PoolManagerAllocatedMemory)
{
    BOOLEAN     FindAtLeastOneEvent = FALSE;
    PLIST_ENTRY TempList            = 0;
    PLIST_ENTRY TempList2           = 0;

    //
    // We have to iterate through all events
    //
    for (SIZE_T i = 0; i < sizeof(DEBUGGER_CORE_EVENTS) / sizeof(LIST_ENTRY); i++)
    {
        TempList  = (PLIST_ENTRY)((UINT64)(g_Events) + (i * sizeof(LIST_ENTRY)));
        TempList2 = TempList;

        while (TempList2 != TempList->Flink)
        {
            TempList                     = TempList->Flink;
            PDEBUGGER_EVENT CurrentEvent = CONTAINING_RECORD(TempList, DEBUGGER_EVENT, EventsOfSameTypeList);

            //
            // Check if we find at least one event or not
            //
            if (!FindAtLeastOneEvent)
            {
                FindAtLeastOneEvent = TRUE;
            }

            //
            // Remove the current event
            //
            DebuggerRemoveEvent(CurrentEvent->Tag, PoolManagerAllocatedMemory);
        }
    }

    return FindAtLeastOneEvent;
}

/**
 * @brief Count the list of events in a special list
 *
 * @param TargetEventList target event list
 * @return UINT32 count of events on the list
 */
UINT32
DebuggerEventListCount(PLIST_ENTRY TargetEventList)
{
    PLIST_ENTRY TempList = 0;
    UINT32      Counter  = 0;

    //
    // We have to iterate through all events of this list
    //
    TempList = TargetEventList;

    while (TargetEventList != TempList->Flink)
    {
        TempList = TempList->Flink;
        /* PDEBUGGER_EVENT CurrentEvent = CONTAINING_RECORD(TempList, DEBUGGER_EVENT, EventsOfSameTypeList); */

        //
        // Increase the counter
        //
        Counter++;
    }

    return Counter;
}

/**
 * @brief Get List of event based on event type
 *
 * @param EventType type of event
 * @return PLIST_ENTRY
 */
PLIST_ENTRY
DebuggerGetEventListByEventType(VMM_EVENT_TYPE_ENUM EventType)
{
    PLIST_ENTRY ResultList = NULL;
    //
    // Register the event
    //
    switch (EventType)
    {
    case HIDDEN_HOOK_READ_AND_WRITE_AND_EXECUTE:
        ResultList = &g_Events->HiddenHookReadAndWriteAndExecuteEventsHead;
        break;
    case HIDDEN_HOOK_READ_AND_WRITE:
        ResultList = &g_Events->HiddenHookReadAndWriteEventsHead;
        break;
    case HIDDEN_HOOK_READ_AND_EXECUTE:
        ResultList = &g_Events->HiddenHookReadAndExecuteEventsHead;
        break;
    case HIDDEN_HOOK_WRITE_AND_EXECUTE:
        ResultList = &g_Events->HiddenHookWriteAndExecuteEventsHead;
        break;
    case HIDDEN_HOOK_READ:
        ResultList = &g_Events->HiddenHookReadEventsHead;
        break;
    case HIDDEN_HOOK_WRITE:
        ResultList = &g_Events->HiddenHookWriteEventsHead;
        break;
    case HIDDEN_HOOK_EXECUTE:
        ResultList = &g_Events->HiddenHookExecuteEventsHead;
        break;
    case HIDDEN_HOOK_EXEC_DETOURS:
        ResultList = &g_Events->EptHook2sExecDetourEventsHead;
        break;
    case HIDDEN_HOOK_EXEC_CC:
        ResultList = &g_Events->EptHookExecCcEventsHead;
        break;
    case SYSCALL_HOOK_EFER_SYSCALL:
        ResultList = &g_Events->SyscallHooksEferSyscallEventsHead;
        break;
    case SYSCALL_HOOK_EFER_SYSRET:
        ResultList = &g_Events->SyscallHooksEferSysretEventsHead;
        break;
    case CPUID_INSTRUCTION_EXECUTION:
        ResultList = &g_Events->CpuidInstructionExecutionEventsHead;
        break;
    case RDMSR_INSTRUCTION_EXECUTION:
        ResultList = &g_Events->RdmsrInstructionExecutionEventsHead;
        break;
    case WRMSR_INSTRUCTION_EXECUTION:
        ResultList = &g_Events->WrmsrInstructionExecutionEventsHead;
        break;
    case EXCEPTION_OCCURRED:
        ResultList = &g_Events->ExceptionOccurredEventsHead;
        break;
    case TSC_INSTRUCTION_EXECUTION:
        ResultList = &g_Events->TscInstructionExecutionEventsHead;
        break;
    case PMC_INSTRUCTION_EXECUTION:
        ResultList = &g_Events->PmcInstructionExecutionEventsHead;
        break;
    case IN_INSTRUCTION_EXECUTION:
        ResultList = &g_Events->InInstructionExecutionEventsHead;
        break;
    case OUT_INSTRUCTION_EXECUTION:
        ResultList = &g_Events->OutInstructionExecutionEventsHead;
        break;
    case DEBUG_REGISTERS_ACCESSED:
        ResultList = &g_Events->DebugRegistersAccessedEventsHead;
        break;
    case EXTERNAL_INTERRUPT_OCCURRED:
        ResultList = &g_Events->ExternalInterruptOccurredEventsHead;
        break;
    case VMCALL_INSTRUCTION_EXECUTION:
        ResultList = &g_Events->VmcallInstructionExecutionEventsHead;
        break;
    case TRAP_EXECUTION_MODE_CHANGED:
        ResultList = &g_Events->TrapExecutionModeChangedEventsHead;
        break;
    case TRAP_EXECUTION_INSTRUCTION_TRACE:
        ResultList = &g_Events->TrapExecutionInstructionTraceEventsHead;
        break;
    case CONTROL_REGISTER_3_MODIFIED:
        ResultList = &g_Events->ControlRegister3ModifiedEventsHead;
        break;
    case CONTROL_REGISTER_MODIFIED:
        ResultList = &g_Events->ControlRegisterModifiedEventsHead;
        break;
    case XSETBV_INSTRUCTION_EXECUTION:
        ResultList = &g_Events->XsetbvInstructionExecutionEventsHead;
        break;
    default:

        //
        // Wrong event type
        //
        LogError("Err, wrong event type is specified");
        ResultList = NULL;
        break;
    }

    return ResultList;
}

/**
 * @brief Count the list of events in a special list that
 * are activate on a target core
 *
 * @param TargetEventList target event list
 * @param TargetCore target core
 * @return UINT32 count of events on the list which is activated
 * on the target core
 */
UINT32
DebuggerEventListCountByCore(PLIST_ENTRY TargetEventList, UINT32 TargetCore)
{
    PLIST_ENTRY TempList = 0;
    UINT32      Counter  = 0;

    //
    // We have to iterate through all events of this list
    //
    TempList = TargetEventList;

    while (TargetEventList != TempList->Flink)
    {
        TempList                     = TempList->Flink;
        PDEBUGGER_EVENT CurrentEvent = CONTAINING_RECORD(TempList, DEBUGGER_EVENT, EventsOfSameTypeList);

        if (CurrentEvent->CoreId == DEBUGGER_EVENT_APPLY_TO_ALL_CORES || CurrentEvent->CoreId == TargetCore)
        {
            //
            // Increase the counter
            //
            Counter++;
        }
    }

    return Counter;
}

/**
 * @brief Count the list of events by a special event type that
 * are activate on a target core
 *
 * @param EventType target event type
 * @param TargetCore target core
 *
 * @return UINT32 count of events on the list which is activated
 * on the target core
 */
UINT32
DebuggerEventListCountByEventType(VMM_EVENT_TYPE_ENUM EventType, UINT32 TargetCore)
{
    PLIST_ENTRY TempList = 0;
    UINT32      Counter  = 0;

    PLIST_ENTRY TargetEventList = DebuggerGetEventListByEventType(EventType);

    //
    // We have to iterate through all events of this list
    //
    TempList = TargetEventList;

    while (TargetEventList != TempList->Flink)
    {
        TempList                     = TempList->Flink;
        PDEBUGGER_EVENT CurrentEvent = CONTAINING_RECORD(TempList, DEBUGGER_EVENT, EventsOfSameTypeList);

        if (CurrentEvent->CoreId == DEBUGGER_EVENT_APPLY_TO_ALL_CORES || CurrentEvent->CoreId == TargetCore)
        {
            //
            // Increase the counter
            //
            Counter++;
        }
    }

    return Counter;
}

/**
 * @brief Get the mask related to the !exception command for the
 * target core
 *
 * @param CoreIndex The index of core
 *
 * @return UINT32 Returns the current mask for the core
 */
UINT32
DebuggerExceptionEventBitmapMask(UINT32 CoreIndex)
{
    PLIST_ENTRY TempList      = 0;
    UINT32      ExceptionMask = 0;

    //
    // We have to iterate through all events of this list
    //
    TempList = &g_Events->ExceptionOccurredEventsHead;

    while (&g_Events->ExceptionOccurredEventsHead != TempList->Flink)
    {
        TempList                     = TempList->Flink;
        PDEBUGGER_EVENT CurrentEvent = CONTAINING_RECORD(TempList, DEBUGGER_EVENT, EventsOfSameTypeList);

        if (CurrentEvent->CoreId == DEBUGGER_EVENT_APPLY_TO_ALL_CORES || CurrentEvent->CoreId == CoreIndex)
        {
            ExceptionMask |= CurrentEvent->Options.OptionalParam1;
        }
    }

    return ExceptionMask;
}

/**
 * @brief Enable an event by tag
 *
 * @param Tag Tag of target event
 * @return BOOLEAN TRUE if event enabled and FALSE if event not
 * found
 */
BOOLEAN
DebuggerEnableEvent(UINT64 Tag)
{
    PDEBUGGER_EVENT Event;
    //
    // Search all the cores for enable this event
    //
    Event = DebuggerGetEventByTag(Tag);

    //
    // Check if tag is valid or not
    //
    if (Event == NULL)
    {
        return FALSE;
    }

    //
    // Enable the event
    //
    Event->Enabled = TRUE;

    return TRUE;
}

/**
 * @brief returns whether an event is enabled/disabled by tag
 * @details this function won't check for Tag validity and if
 * not found then returns false
 *
 * @param Tag Tag of target event
 * @return BOOLEAN TRUE if event enabled and FALSE if event not
 * found
 */
BOOLEAN
DebuggerQueryStateEvent(UINT64 Tag)
{
    PDEBUGGER_EVENT Event;
    //
    // Search all the cores for enable this event
    //
    Event = DebuggerGetEventByTag(Tag);

    //
    // Check if tag is valid or not
    //
    if (Event == NULL)
    {
        return FALSE;
    }

    return Event->Enabled;
}

/**
 * @brief Disable an event by tag
 *
 * @param Tag Tag of target event
 * @return BOOLEAN TRUE if event enabled and FALSE if event not
 * found
 */
BOOLEAN
DebuggerDisableEvent(UINT64 Tag)
{
    PDEBUGGER_EVENT Event;

    //
    // Search all the cores for enable this event
    //
    Event = DebuggerGetEventByTag(Tag);

    //
    // Check if tag is valid or not
    //
    if (Event == NULL)
    {
        return FALSE;
    }

    //
    // Disable the event
    //
    Event->Enabled = FALSE;

    return TRUE;
}

/**
 * @brief Clear an event by tag
 *
 * @param Tag Tag of target event
 * @param InputFromVmxRoot Whether the input comes from VMX root-mode or IOCTL
 * @param PoolManagerAllocatedMemory Whether the pools are allocated from the
 * pool manager or original OS pools
 *
 * @return BOOLEAN
 *
 */
BOOLEAN
DebuggerClearEvent(UINT64 Tag, BOOLEAN InputFromVmxRoot, BOOLEAN PoolManagerAllocatedMemory)
{
    //
    // Because we want to delete all the objects and buffers (pools)
    // after we finished termination, the debugger might still use
    // the buffers for events and action, for solving this problem
    // we first disable the tag(s) and this way the debugger no longer
    // use that event and this way we can safely remove and deallocate
    // the buffers later after termination
    //

    //
    // First, disable just one event
    //
    DebuggerDisableEvent(Tag);

    //
    // Second, terminate it
    //
    DebuggerTerminateEvent(Tag, InputFromVmxRoot);

    //
    // Third, remove it from the list
    //
    return DebuggerRemoveEvent(Tag, PoolManagerAllocatedMemory);
}

/**
 * @brief Clear all events
 *
 * @param InputFromVmxRoot Whether the input comes from VMX root-mode or IOCTL
 * @param PoolManagerAllocatedMemory Whether the pools are allocated from the
 * pool manager or original OS pools
 *
 * @return VOID
 */
VOID
DebuggerClearAllEvents(BOOLEAN InputFromVmxRoot, BOOLEAN PoolManagerAllocatedMemory)
{
    //
    // Because we want to delete all the objects and buffers (pools)
    // after we finished termination, the debugger might still use
    // the buffers for events and action, for solving this problem
    // we first disable the tag(s) and this way the debugger no longer
    // use that event and this way we can safely remove and deallocate
    // the buffers later after termination
    //

    //
    // First, disable all events
    //
    DebuggerEnableOrDisableAllEvents(FALSE);

    //
    // Second, terminate all events
    //
    DebuggerTerminateAllEvents(InputFromVmxRoot);

    //
    // Third, remove all events
    //
    DebuggerRemoveAllEvents(PoolManagerAllocatedMemory);
}

/**
 * @brief Detect whether the tag exists or not
 *
 * @param Tag Tag of target event
 * @return BOOLEAN TRUE if event found and FALSE if event not found
 */
BOOLEAN
DebuggerIsTagValid(UINT64 Tag)
{
    PDEBUGGER_EVENT Event;

    //
    // Search this event
    //
    Event = DebuggerGetEventByTag(Tag);

    //
    // Check if tag is valid or not
    //
    if (Event == NULL)
    {
        return FALSE;
    }

    return TRUE;
}

/**
 * @brief Detect whether the user or kernel debugger
 * is active or not
 *
 * @return BOOLEAN TRUE if any of the are activated and FALSE if not
 */
BOOLEAN
DebuggerQueryDebuggerStatus()
{
    if (g_KernelDebuggerState || g_UserDebuggerState)
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

/**
 * @brief Remove the event from event list by its tag
 *
 * @details should not be called from vmx-root mode, also
 * it won't terminate their effects, so the events should
 * be terminated first then we can remove them
 *
 * @param Tag Target events tag
 * @return BOOLEAN If the event was removed then TRUE and FALSE
 * if not found
 */
BOOLEAN
DebuggerRemoveEventFromEventList(UINT64 Tag)
{
    PLIST_ENTRY TempList  = 0;
    PLIST_ENTRY TempList2 = 0;

    //
    // We have to iterate through all events
    //
    for (SIZE_T i = 0; i < sizeof(DEBUGGER_CORE_EVENTS) / sizeof(LIST_ENTRY); i++)
    {
        TempList  = (PLIST_ENTRY)((UINT64)(g_Events) + (i * sizeof(LIST_ENTRY)));
        TempList2 = TempList;

        while (TempList2 != TempList->Flink)
        {
            TempList                     = TempList->Flink;
            PDEBUGGER_EVENT CurrentEvent = CONTAINING_RECORD(TempList, DEBUGGER_EVENT, EventsOfSameTypeList);

            //
            // Check if we find the event or not
            //
            if (CurrentEvent->Tag == Tag)
            {
                //
                // We have to remove the event from the list
                //
                RemoveEntryList(&CurrentEvent->EventsOfSameTypeList);
                return TRUE;
            }
        }
    }

    //
    // We didn't find anything, so return null
    //
    return FALSE;
}

/**
 * @brief Remove the actions and de-allocate its buffer
 *
 * @details should not be called from vmx-root mode, also
 * it won't terminate their effects, so the events should
 * be terminated first then we can remove them *
 *
 * @param Event Event Object
 * @param PoolManagerAllocatedMemory Whether the pools are allocated from the
 * pool manager or original OS pools
 *
 * @return BOOLEAN TRUE if it was successful and FALSE if not successful
 */
BOOLEAN
DebuggerRemoveAllActionsFromEvent(PDEBUGGER_EVENT Event, BOOLEAN PoolManagerAllocatedMemory)
{
    PLIST_ENTRY TempList  = 0;
    PLIST_ENTRY TempList2 = 0;

    //
    // Remove all actions
    //
    TempList  = Event->ActionsListHead.Flink;
    TempList2 = &Event->ActionsListHead;

    while (TempList != TempList2)
    {
        PLIST_ENTRY            NextList      = TempList->Flink;
        PDEBUGGER_EVENT_ACTION CurrentAction = CONTAINING_RECORD(TempList, DEBUGGER_EVENT_ACTION, ActionsList);

        //
        // Check if it has a OptionalRequestedBuffer probably for
        // CustomCode
        //
        if (CurrentAction->RequestedBuffer.RequestBufferSize != 0 && CurrentAction->RequestedBuffer.RequstBufferAddress != (UINT64)NULL)
        {
            //
            // There is a buffer
            //
            if (PoolManagerAllocatedMemory)
            {
                PoolManagerFreePool(CurrentAction->RequestedBuffer.RequstBufferAddress);
            }
            else
            {
                PlatformMemFreePool((PVOID)CurrentAction->RequestedBuffer.RequstBufferAddress);
            }
        }

        //
        // Remove the action and free the pool,
        // if it's a custom buffer then the buffer
        // is appended to the Action
        //
        RemoveEntryList(&CurrentAction->ActionsList);

        if (PoolManagerAllocatedMemory)
        {
            PoolManagerFreePool((UINT64)CurrentAction);
        }
        else
        {
            PlatformMemFreePool(CurrentAction);
        }

        TempList = NextList;
    }
    //
    // Remember to free the pool
    //
    return TRUE;
}

/**
 * @brief Remove the event by its tags and also remove its actions
 * and de-allocate their buffers
 *
 * @details it won't terminate their effects, so the events should
 * be terminated first then we can remove them
 *
 * @param Tag Target event tag
 * @param PoolManagerAllocatedMemory Whether the pools are allocated from the
 * pool manager or original OS pools
 *
 * @return BOOLEAN TRUE if it was successful and FALSE if not successful
 */
BOOLEAN
DebuggerRemoveEvent(UINT64 Tag, BOOLEAN PoolManagerAllocatedMemory)
{
    PDEBUGGER_EVENT Event;

    //
    // First of all, we disable event
    //
    if (!DebuggerDisableEvent(Tag))
    {
        //
        // Not found, tag is wrong !
        //
        return FALSE;
    }

    //
    // When we're here, we are sure that the tag is valid
    // because if it was not valid, then we have to return
    // for the above function (DebuggerDisableEvent)
    //
    Event = DebuggerGetEventByTag(Tag);

    //
    // Now we get the PDEBUGGER_EVENT so we have to remove
    // it from the event list
    //
    if (!DebuggerRemoveEventFromEventList(Tag))
    {
        return FALSE;
    }

    //
    // Remove all of the actions and free its pools
    //
    DebuggerRemoveAllActionsFromEvent(Event, PoolManagerAllocatedMemory);

    //
    // Free the pools of Event, when we free the pool,
    // ConditionsBufferAddress is also a part of the
    // event pool (ConditionBufferAddress and event
    // are both allocate in a same pool ) so both of
    // them are freed
    //
    if (PoolManagerAllocatedMemory)
    {
        PoolManagerFreePool((UINT64)Event);
    }
    else
    {
        PlatformMemFreePool(Event);
    }

    return TRUE;
}

/**
 * @brief validating events
 *
 * @param EventDetails The structure that describes event that came
 * from the user-mode or VMX-root mode
 * @param ResultsToReturn Result buffer that should be returned to
 * the user-mode
 * @param InputFromVmxRoot Whether the input comes from VMX root-mode or IOCTL
 *
 * @return BOOLEAN TRUE if the event was valid otherwise returns FALSE
 */
BOOLEAN
DebuggerValidateEvent(PDEBUGGER_GENERAL_EVENT_DETAIL    EventDetails,
                      PDEBUGGER_EVENT_AND_ACTION_RESULT ResultsToReturn,
                      BOOLEAN                           InputFromVmxRoot)
{
    //
    // Check whether the event mode (calling stage)  to see whether
    // short-cicuiting event is used along with the post-event,
    // it is because using the short-circuiting mechanism with
    // post-events doesn't make sense; it's not supported!
    //
    if ((EventDetails->EventStage == VMM_CALLBACK_CALLING_STAGE_POST_EVENT_EMULATION ||
         EventDetails->EventStage == VMM_CALLBACK_CALLING_STAGE_ALL_EVENT_EMULATION) &&
        EventDetails->EnableShortCircuiting == TRUE)
    {
        ResultsToReturn->IsSuccessful = FALSE;
        ResultsToReturn->Error        = DEBUGGER_ERROR_USING_SHORT_CIRCUITING_EVENT_WITH_POST_EVENT_MODE_IS_FORBIDDEDN;
        return FALSE;
    }

    //
    // Check whether the core Id is valid or not, we read cores count
    // here because we use it in later parts
    //
    if (EventDetails->CoreId != DEBUGGER_EVENT_APPLY_TO_ALL_CORES)
    {
        //
        // Check if the core number is not invalid
        //
        if (!CommonValidateCoreNumber(EventDetails->CoreId))
        {
            //
            // CoreId is invalid (Set the error)
            //
            ResultsToReturn->IsSuccessful = FALSE;
            ResultsToReturn->Error        = DEBUGGER_ERROR_INVALID_CORE_ID;
            return FALSE;
        }
    }

    //
    // Check if process id is valid or not, we won't touch process id here
    // because some of the events use the exact value of DEBUGGER_EVENT_APPLY_TO_ALL_PROCESSES
    //
    if (EventDetails->ProcessId != DEBUGGER_EVENT_APPLY_TO_ALL_PROCESSES && EventDetails->ProcessId != 0)
    {
        //
        // Here we prefer not to validate the process id, if it's applied from VMX-root mode
        //
        if (!InputFromVmxRoot)
        {
            //
            // The used specified a special pid, let's check if it's valid or not
            //
            if (!CommonIsProcessExist(EventDetails->ProcessId))
            {
                ResultsToReturn->IsSuccessful = FALSE;
                ResultsToReturn->Error        = DEBUGGER_ERROR_INVALID_PROCESS_ID;
                return FALSE;
            }
        }
    }

    //
    // *** Event specific validations ***
    //
    switch (EventDetails->EventType)
    {
    case EXCEPTION_OCCURRED:
    {
        //
        // Check if exception parameters are valid
        //
        if (!ValidateEventException(EventDetails, ResultsToReturn, InputFromVmxRoot))
        {
            //
            // Event parameters are not valid, let break the further execution at this stage
            //
            return FALSE;
        }

        break;
    }
    case EXTERNAL_INTERRUPT_OCCURRED:
    {
        //
        // Check if interrupt parameters are valid
        //
        if (!ValidateEventInterrupt(EventDetails, ResultsToReturn, InputFromVmxRoot))
        {
            //
            // Event parameters are not valid, let break the further execution at this stage
            //
            return FALSE;
        }

        break;
    }
    case TRAP_EXECUTION_MODE_CHANGED:
    {
        //
        // Check if trap exec mode parameters are valid
        //
        if (!ValidateEventTrapExec(EventDetails, ResultsToReturn, InputFromVmxRoot))
        {
            //
            // Event parameters are not valid, let break the further execution at this stage
            //
            return FALSE;
        }

        break;
    }
    case HIDDEN_HOOK_EXEC_DETOURS:
    case HIDDEN_HOOK_EXEC_CC:
    {
        //
        // Check if EPT hook exec (hidden breakpoint and inline hook) parameters are valid
        //
        if (!ValidateEventEptHookHiddenBreakpointAndInlineHooks(EventDetails, ResultsToReturn, InputFromVmxRoot))
        {
            //
            // Event parameters are not valid, let break the further execution at this stage
            //
            return FALSE;
        }

        break;
    }
    case HIDDEN_HOOK_READ_AND_WRITE_AND_EXECUTE:
    case HIDDEN_HOOK_READ_AND_WRITE:
    case HIDDEN_HOOK_READ_AND_EXECUTE:
    case HIDDEN_HOOK_WRITE_AND_EXECUTE:
    case HIDDEN_HOOK_READ:
    case HIDDEN_HOOK_WRITE:
    case HIDDEN_HOOK_EXECUTE:
    {
        //
        // Check if EPT memory monitor hook parameters are valid
        //
        if (!ValidateEventMonitor(EventDetails, ResultsToReturn, InputFromVmxRoot))
        {
            //
            // Event parameters are not valid, let break the further execution at this stage
            //
            return FALSE;
        }

        break;
    }
    default:

        //
        // Other not specified events doesn't have any special validation
        //
        break;
    }

    //
    // As we reached, all the checks are passed and it means the event is valid
    //
    return TRUE;
}

/**
 * @brief Applying events
 *
 * @param Event The created event object
 * @param ResultsToReturn Result buffer that should be returned to
 * the user-mode
 * @param InputFromVmxRoot Whether the input comes from VMX root-mode or IOCTL
 *
 * @return BOOLEAN TRUE if the event was applied otherwise returns FALSE
 */
BOOLEAN
DebuggerApplyEvent(PDEBUGGER_EVENT                   Event,
                   PDEBUGGER_EVENT_AND_ACTION_RESULT ResultsToReturn,
                   BOOLEAN                           InputFromVmxRoot)
{
    //
    // Now we should configure the cpu to generate the events
    //
    switch (Event->EventType)
    {
    case HIDDEN_HOOK_READ_AND_WRITE_AND_EXECUTE:
    case HIDDEN_HOOK_READ_AND_WRITE:
    case HIDDEN_HOOK_READ_AND_EXECUTE:
    case HIDDEN_HOOK_WRITE_AND_EXECUTE:
    case HIDDEN_HOOK_READ:
    case HIDDEN_HOOK_WRITE:
    case HIDDEN_HOOK_EXECUTE:
    {
        //
        // Apply the monitor memory hook events
        //
        if (!ApplyEventMonitorEvent(Event, ResultsToReturn, InputFromVmxRoot))
        {
            goto ClearTheEventAfterCreatingEvent;
        }

        break;
    }
    case HIDDEN_HOOK_EXEC_CC:
    {
        //
        // Apply the EPT hidden hook (hidden breakpoint) events
        //
        if (!ApplyEventEptHookExecCcEvent(Event, ResultsToReturn, InputFromVmxRoot))
        {
            goto ClearTheEventAfterCreatingEvent;
        }

        break;
    }
    case HIDDEN_HOOK_EXEC_DETOURS:
    {
        //
        // Apply the EPT hook trampoline (inline hook) events
        //
        if (!ApplyEventEpthookInlineEvent(Event, ResultsToReturn, InputFromVmxRoot))
        {
            goto ClearTheEventAfterCreatingEvent;
        }

        break;
    }
    case RDMSR_INSTRUCTION_EXECUTION:
    {
        //
        // Apply the RDMSR execution exiting events
        //
        ApplyEventRdmsrExecutionEvent(Event, ResultsToReturn, InputFromVmxRoot);

        break;
    }
    case WRMSR_INSTRUCTION_EXECUTION:
    {
        //
        // Apply the WRMSR execution exiting events
        //
        ApplyEventWrmsrExecutionEvent(Event, ResultsToReturn, InputFromVmxRoot);

        break;
    }
    case IN_INSTRUCTION_EXECUTION:
    case OUT_INSTRUCTION_EXECUTION:
    {
        //
        // Apply the IN/OUT instructions execution exiting events
        //
        ApplyEventInOutExecutionEvent(Event, ResultsToReturn, InputFromVmxRoot);

        break;
    }
    case TSC_INSTRUCTION_EXECUTION:
    {
        //
        // Apply the RDTSC/RDTSCP instructions execution exiting events
        //
        ApplyEventTscExecutionEvent(Event, ResultsToReturn, InputFromVmxRoot);

        break;
    }
    case PMC_INSTRUCTION_EXECUTION:
    {
        //
        // Apply the RDPMC instruction execution exiting events
        //
        ApplyEventRdpmcExecutionEvent(Event, ResultsToReturn, InputFromVmxRoot);

        break;
    }
    case DEBUG_REGISTERS_ACCESSED:
    {
        //
        // Apply the mov 2 debug register exiting events
        //
        ApplyEventMov2DebugRegExecutionEvent(Event, ResultsToReturn, InputFromVmxRoot);

        break;
    }
    case CONTROL_REGISTER_MODIFIED:
    {
        //
        // Apply the control register access exiting events
        //
        ApplyEventControlRegisterAccessedEvent(Event, ResultsToReturn, InputFromVmxRoot);

        break;
    }
    case EXCEPTION_OCCURRED:
    {
        //
        // Apply the exception events
        //
        ApplyEventExceptionEvent(Event, ResultsToReturn, InputFromVmxRoot);

        break;
    }
    case EXTERNAL_INTERRUPT_OCCURRED:
    {
        //
        // Apply the interrupt events
        //
        ApplyEventInterruptEvent(Event, ResultsToReturn, InputFromVmxRoot);

        break;
    }
    case SYSCALL_HOOK_EFER_SYSCALL:
    {
        //
        // Apply the EFER SYSCALL hook events
        //
        ApplyEventEferSyscallHookEvent(Event, ResultsToReturn, InputFromVmxRoot);

        break;
    }
    case SYSCALL_HOOK_EFER_SYSRET:
    {
        //
        // Apply the EFER SYSRET hook events
        //
        ApplyEventEferSysretHookEvent(Event, ResultsToReturn, InputFromVmxRoot);

        break;
    }
    case VMCALL_INSTRUCTION_EXECUTION:
    {
        //
        // Apply the VMCALL instruction interception events
        //
        ApplyEventVmcallExecutionEvent(Event, ResultsToReturn, InputFromVmxRoot);

        break;
    }
    case TRAP_EXECUTION_MODE_CHANGED:
    {
        //
        // Apply the trap mode change and single instruction trace events
        //
        if (!ApplyEventTrapModeChangeEvent(Event, ResultsToReturn, InputFromVmxRoot))
        {
            goto ClearTheEventAfterCreatingEvent;
        }

        break;
    }
    case CPUID_INSTRUCTION_EXECUTION:
    {
        //
        // Apply the CPUID instruction execution events
        //
        ApplyEventCpuidExecutionEvent(Event, ResultsToReturn, InputFromVmxRoot);

        break;
    }
    case TRAP_EXECUTION_INSTRUCTION_TRACE:
    {
        //
        // Apply the tracing events
        //
        ApplyEventTracingEvent(Event, ResultsToReturn, InputFromVmxRoot);

        break;
    }
    case XSETBV_INSTRUCTION_EXECUTION:
    {
        //
        // Apply the XSETBV instruction execution events
        //
        ApplyEventXsetbvExecutionEvent(Event, ResultsToReturn, InputFromVmxRoot);

        break;
    }
    default:
    {
        //
        // Set the error
        //
        ResultsToReturn->IsSuccessful = FALSE;
        ResultsToReturn->Error        = DEBUGGER_ERROR_EVENT_TYPE_IS_INVALID;
        goto ClearTheEventAfterCreatingEvent;

        break;
    }
    }

    //
    // Set the status
    //
    ResultsToReturn->IsSuccessful = TRUE;
    ResultsToReturn->Error        = 0;

    //
    // Event was applied successfully
    //
    return TRUE;

ClearTheEventAfterCreatingEvent:

    return FALSE;
}

/**
 * @brief Routine for parsing events
 *
 * @param EventDetails The structure that describes event that came
 * from the user-mode
 * @param ResultsToReturn Result buffer that should be returned to
 * the user-mode
 * @param InputFromVmxRoot Whether the input comes from VMX root-mode or IOCTL
 *
 * @return BOOLEAN TRUE if the event was valid and registered without error,
 * otherwise returns FALSE
 */
BOOLEAN
DebuggerParseEvent(PDEBUGGER_GENERAL_EVENT_DETAIL    EventDetails,
                   PDEBUGGER_EVENT_AND_ACTION_RESULT ResultsToReturn,
                   BOOLEAN                           InputFromVmxRoot)
{
    PDEBUGGER_EVENT Event;

    //
    // ----------------------------------------------------------------------------------
    // ***                     Validating the Event's parameters                      ***
    // ----------------------------------------------------------------------------------
    //

    //
    // Validate the event parameters
    //
    if (!DebuggerValidateEvent(EventDetails, ResultsToReturn, InputFromVmxRoot))
    {
        //
        // Input event is not valid
        //
        return FALSE;
    }

    //
    // ----------------------------------------------------------------------------------
    // ***                                Create Event                                ***
    // ----------------------------------------------------------------------------------
    //

    //
    // We initialize event with disabled mode as it doesn't have action yet
    //
    if (EventDetails->ConditionBufferSize != 0)
    {
        //
        // Conditional Event
        //
        Event = DebuggerCreateEvent(FALSE,
                                    EventDetails->CoreId,
                                    EventDetails->ProcessId,
                                    EventDetails->EventType,
                                    EventDetails->Tag,
                                    &EventDetails->Options,
                                    EventDetails->ConditionBufferSize,
                                    (PVOID)((UINT64)EventDetails + sizeof(DEBUGGER_GENERAL_EVENT_DETAIL)),
                                    ResultsToReturn,
                                    InputFromVmxRoot);
    }
    else
    {
        //
        // Unconditional Event
        //
        Event = DebuggerCreateEvent(FALSE,
                                    EventDetails->CoreId,
                                    EventDetails->ProcessId,
                                    EventDetails->EventType,
                                    EventDetails->Tag,
                                    &EventDetails->Options,
                                    0,
                                    NULL,
                                    ResultsToReturn,
                                    InputFromVmxRoot);
    }

    if (Event == NULL)
    {
        //
        // Error is already set in the creation function
        //
        return FALSE;
    }

    //
    // Register the event
    //
    DebuggerRegisterEvent(Event);

    //
    // ----------------------------------------------------------------------------------
    // ***                            Apply & Enable Event                            ***
    // ----------------------------------------------------------------------------------
    //
    if (DebuggerApplyEvent(Event, ResultsToReturn, InputFromVmxRoot))
    {
        //
        // *** Set the short-circuiting state ***
        //
        Event->EnableShortCircuiting = EventDetails->EnableShortCircuiting;

        //
        // Set the event stage (pre- post- event)
        //
        if (EventDetails->EventStage == VMM_CALLBACK_CALLING_STAGE_POST_EVENT_EMULATION)
        {
            Event->EventMode = VMM_CALLBACK_CALLING_STAGE_POST_EVENT_EMULATION;
        }
        else if (EventDetails->EventStage == VMM_CALLBACK_CALLING_STAGE_ALL_EVENT_EMULATION)
        {
            Event->EventMode = VMM_CALLBACK_CALLING_STAGE_ALL_EVENT_EMULATION;
        }
        else
        {
            //
            // Any other value results to be pre-event
            //
            Event->EventMode = VMM_CALLBACK_CALLING_STAGE_PRE_EVENT_EMULATION;
        }

        return TRUE;
    }
    else
    {
        //
        // Remove the event as it was not successful
        // The same input as of input from VMX-root is
        // selected here because we apply it directly in the
        // above function and based on this input we can
        // conclude whether the pool is allocated from the
        // pool manager or not
        //
        if (Event != NULL)
        {
            DebuggerRemoveEvent(Event->Tag, InputFromVmxRoot);
        }

        return FALSE;
    }
}

/**
 * @brief Routine for validating and parsing actions that are coming from
 * the user-mode
 *
 * @param ActionDetails Structure that describes the action that comes from the
 * user-mode
 * @param ResultsToReturn The buffer address that should be returned
 * to the user-mode as the result
 * @param InputFromVmxRoot Whether the input comes from VMX root-mode or IOCTL
 *
 * @return BOOLEAN if action was parsed and added successfully, return TRUE
 * otherwise, returns FALSE
 */
BOOLEAN
DebuggerParseAction(PDEBUGGER_GENERAL_ACTION          ActionDetails,
                    PDEBUGGER_EVENT_AND_ACTION_RESULT ResultsToReturn,
                    BOOLEAN                           InputFromVmxRoot)
{
    DEBUGGER_EVENT_ACTION * Action = NULL;

    //
    // Check if Tag is valid or not
    //
    PDEBUGGER_EVENT Event = DebuggerGetEventByTag(ActionDetails->EventTag);

    if (Event == NULL)
    {
        //
        // Set the appropriate error
        //
        ResultsToReturn->IsSuccessful = FALSE;
        ResultsToReturn->Error        = DEBUGGER_ERROR_TAG_NOT_EXISTS;

        //
        // Show that the
        //
        return FALSE;
    }

    if (ActionDetails->ActionType == RUN_CUSTOM_CODE)
    {
        //
        // Check if buffer is not invalid
        //
        if (ActionDetails->CustomCodeBufferSize == 0)
        {
            //
            // Set the appropriate error
            //
            ResultsToReturn->IsSuccessful = FALSE;
            ResultsToReturn->Error        = DEBUGGER_ERROR_ACTION_BUFFER_SIZE_IS_ZERO;

            //
            // Show that the
            //
            return FALSE;
        }

        //
        // Add action for RUN_CUSTOM_CODE
        //
        DEBUGGER_EVENT_REQUEST_CUSTOM_CODE CustomCode = {0};

        CustomCode.CustomCodeBufferSize        = ActionDetails->CustomCodeBufferSize;
        CustomCode.CustomCodeBufferAddress     = (PVOID)((UINT64)ActionDetails + sizeof(DEBUGGER_GENERAL_ACTION));
        CustomCode.OptionalRequestedBufferSize = ActionDetails->PreAllocatedBuffer;

        //
        // Add action to event
        //
        Action = DebuggerAddActionToEvent(Event,
                                          RUN_CUSTOM_CODE,
                                          ActionDetails->ImmediateMessagePassing,
                                          &CustomCode,
                                          NULL,
                                          ResultsToReturn,
                                          InputFromVmxRoot);

        if (!Action)
        {
            //
            // Show that there was an error (error is set by the above function)
            //
            return FALSE;
        }
    }
    else if (ActionDetails->ActionType == RUN_SCRIPT)
    {
        //
        // Check if buffer is not invalid
        //
        if (ActionDetails->ScriptBufferSize == 0)
        {
            //
            // Set the appropriate error
            //
            ResultsToReturn->IsSuccessful = FALSE;
            ResultsToReturn->Error        = DEBUGGER_ERROR_ACTION_BUFFER_SIZE_IS_ZERO;

            //
            // Show that the
            //
            return FALSE;
        }

        //
        // Add action for RUN_SCRIPT
        //
        DEBUGGER_EVENT_ACTION_RUN_SCRIPT_CONFIGURATION UserScriptConfig = {0};
        UserScriptConfig.ScriptBuffer                                   = (UINT64)ActionDetails + sizeof(DEBUGGER_GENERAL_ACTION);
        UserScriptConfig.ScriptLength                                   = ActionDetails->ScriptBufferSize;
        UserScriptConfig.ScriptPointer                                  = ActionDetails->ScriptBufferPointer;
        UserScriptConfig.OptionalRequestedBufferSize                    = ActionDetails->PreAllocatedBuffer;

        Action = DebuggerAddActionToEvent(Event,
                                          RUN_SCRIPT,
                                          ActionDetails->ImmediateMessagePassing,
                                          NULL,
                                          &UserScriptConfig,
                                          ResultsToReturn,
                                          InputFromVmxRoot);

        if (!Action)
        {
            //
            // Show that there was an error (error is set by the above function)
            //
            return FALSE;
        }
    }
    else if (ActionDetails->ActionType == BREAK_TO_DEBUGGER)
    {
        //
        // Add action BREAK_TO_DEBUGGER to event
        //
        Action = DebuggerAddActionToEvent(Event,
                                          BREAK_TO_DEBUGGER,
                                          ActionDetails->ImmediateMessagePassing,
                                          NULL,
                                          NULL,
                                          ResultsToReturn,
                                          InputFromVmxRoot);

        if (!Action)
        {
            //
            // Show that there was an error (error is set by the above function)
            //
            return FALSE;
        }
    }
    else
    {
        //
        // Set the appropriate error
        //
        ResultsToReturn->IsSuccessful = FALSE;
        ResultsToReturn->Error        = DEBUGGER_ERROR_INVALID_ACTION_TYPE;

        //
        // Show that there was an error
        //
        return FALSE;
    }

    //
    // Enable the event
    //
    DebuggerEnableEvent(Event->Tag);

    ResultsToReturn->IsSuccessful = TRUE;
    ResultsToReturn->Error        = 0;

    return TRUE;
}

/**
 * @brief Terminate one event's effect by its tag
 *
 * @details This function won't remove the event from
 * the lists of event or de-allocated them, this should
 * be called BEFORE the removing function
 *
 * @param Tag Target event's tag
 * @param InputFromVmxRoot Whether the input comes from VMX root-mode or IOCTL
 *
 * @return BOOLEAN if it was found and terminated without error
 * then it returns TRUE, otherwise FALSE
 */
BOOLEAN
DebuggerTerminateEvent(UINT64 Tag, BOOLEAN InputFromVmxRoot)
{
    PDEBUGGER_EVENT Event;
    BOOLEAN         Result = FALSE;

    //
    // Find the event by its tag
    //
    Event = DebuggerGetEventByTag(Tag);

    if (Event == NULL)
    {
        //
        // event, not found
        //
        return FALSE;
    }

    //
    // Check the event type of our specific tag
    //
    switch (Event->EventType)
    {
    case EXTERNAL_INTERRUPT_OCCURRED:
    {
        //
        // Call external interrupt terminator
        //
        TerminateExternalInterruptEvent(Event, InputFromVmxRoot);
        Result = TRUE;

        break;
    }
    case HIDDEN_HOOK_READ_AND_WRITE_AND_EXECUTE:
    case HIDDEN_HOOK_READ_AND_WRITE:
    case HIDDEN_HOOK_READ_AND_EXECUTE:
    case HIDDEN_HOOK_WRITE_AND_EXECUTE:
    case HIDDEN_HOOK_READ:
    case HIDDEN_HOOK_WRITE:
    case HIDDEN_HOOK_EXECUTE:
    {
        //
        // Call read and write and execute ept hook terminator
        //
        TerminateHiddenHookReadAndWriteAndExecuteEvent(Event, InputFromVmxRoot);
        Result = TRUE;

        break;
    }
    case HIDDEN_HOOK_EXEC_CC:
    {
        //
        // Call ept hook (hidden breakpoint) terminator
        //
        TerminateHiddenHookExecCcEvent(Event, InputFromVmxRoot);
        Result = TRUE;

        break;
    }
    case HIDDEN_HOOK_EXEC_DETOURS:
    {
        //
        // Call ept hook (hidden inline hook) terminator
        //
        TerminateHiddenHookExecDetoursEvent(Event, InputFromVmxRoot);
        Result = TRUE;

        break;
    }
    case RDMSR_INSTRUCTION_EXECUTION:
    {
        //
        // Call rdmsr execution event terminator
        //
        TerminateRdmsrExecutionEvent(Event, InputFromVmxRoot);
        Result = TRUE;

        break;
    }
    case WRMSR_INSTRUCTION_EXECUTION:
    {
        //
        // Call wrmsr execution event terminator
        //
        TerminateWrmsrExecutionEvent(Event, InputFromVmxRoot);
        Result = TRUE;

        break;
    }
    case EXCEPTION_OCCURRED:
    {
        //
        // Call exception events terminator
        //
        TerminateExceptionEvent(Event, InputFromVmxRoot);
        Result = TRUE;

        break;
    }
    case IN_INSTRUCTION_EXECUTION:
    {
        //
        // Call IN instruction execution event terminator
        //
        TerminateInInstructionExecutionEvent(Event, InputFromVmxRoot);
        Result = TRUE;

        break;
    }
    case OUT_INSTRUCTION_EXECUTION:
    {
        //
        // Call OUT instruction execution event terminator
        //
        TerminateOutInstructionExecutionEvent(Event, InputFromVmxRoot);
        Result = TRUE;

        break;
    }
    case SYSCALL_HOOK_EFER_SYSCALL:
    {
        //
        // Call syscall hook event terminator
        //
        TerminateSyscallHookEferEvent(Event, InputFromVmxRoot);
        Result = TRUE;

        break;
    }
    case SYSCALL_HOOK_EFER_SYSRET:
    {
        //
        // Call sysret hook event terminator
        //
        TerminateSysretHookEferEvent(Event, InputFromVmxRoot);
        Result = TRUE;

        break;
    }
    case VMCALL_INSTRUCTION_EXECUTION:
    {
        //
        // Call vmcall instruction execution event terminator
        //
        TerminateVmcallExecutionEvent(Event, InputFromVmxRoot);
        Result = TRUE;

        break;
    }
    case TRAP_EXECUTION_MODE_CHANGED:
    {
        //
        // Call mode execution trap event terminator
        //
        TerminateExecTrapModeChangedEvent(Event, InputFromVmxRoot);
        Result = TRUE;

        break;
    }
    case TSC_INSTRUCTION_EXECUTION:
    {
        //
        // Call rdtsc/rdtscp instruction execution event terminator
        //
        TerminateTscEvent(Event, InputFromVmxRoot);
        Result = TRUE;

        break;
    }
    case PMC_INSTRUCTION_EXECUTION:
    {
        //
        // Call rdtsc/rdtscp instructions execution event terminator
        //
        TerminatePmcEvent(Event, InputFromVmxRoot);
        Result = TRUE;

        break;
    }
    case DEBUG_REGISTERS_ACCESSED:
    {
        //
        // Call mov to debugger register event terminator
        //
        TerminateDebugRegistersEvent(Event, InputFromVmxRoot);
        Result = TRUE;

        break;
    }
    case CPUID_INSTRUCTION_EXECUTION:
    {
        //
        // Call cpuid instruction execution event terminator
        //
        TerminateCpuidExecutionEvent(Event, InputFromVmxRoot);
        Result = TRUE;

        break;
    }
    case CONTROL_REGISTER_MODIFIED:
    {
        //
        // Call mov to control register event terminator
        //
        TerminateControlRegistersEvent(Event, InputFromVmxRoot);
        Result = TRUE;

        break;
    }
    case XSETBV_INSTRUCTION_EXECUTION:
    {
        //
        // Call XSETBV instruction execution event terminator
        //
        TerminateXsetbvExecutionEvent(Event, InputFromVmxRoot);
        Result = TRUE;

        break;
    }
    default:
        LogError("Err, unknown event for termination");
        Result = FALSE;

        break;
    }

    //
    // Return status
    //
    return Result;
}

/**
 * @brief Parse and validate requests to enable/disable/clear
 * from the user-mode
 *
 * @param DebuggerEventModificationRequest event modification request details
 * @param InputFromVmxRoot Whether the input comes from VMX root-mode or IOCTL
 * @param PoolManagerAllocatedMemory Whether the pools are allocated from the
 * pool manager or original OS pools
 *
 * @return BOOLEAN returns TRUE if there was no error, and FALSE if there was
 * an error
 */
BOOLEAN
DebuggerParseEventsModification(PDEBUGGER_MODIFY_EVENTS DebuggerEventModificationRequest,
                                BOOLEAN                 InputFromVmxRoot,
                                BOOLEAN                 PoolManagerAllocatedMemory)
{
    BOOLEAN IsForAllEvents = FALSE;

    //
    // Check if the tag is valid or not
    //
    if (DebuggerEventModificationRequest->Tag == DEBUGGER_MODIFY_EVENTS_APPLY_TO_ALL_TAG)
    {
        IsForAllEvents = TRUE;
    }
    else if (!DebuggerIsTagValid(DebuggerEventModificationRequest->Tag))
    {
        //
        // Tag is invalid
        //
        DebuggerEventModificationRequest->KernelStatus = DEBUGGER_ERROR_MODIFY_EVENTS_INVALID_TAG;

        return FALSE;
    }

    //
    // ***************************************************************************
    //

    //
    // Check if it's a ENABLE, DISABLE or CLEAR
    //
    if (DebuggerEventModificationRequest->TypeOfAction == DEBUGGER_MODIFY_EVENTS_ENABLE)
    {
        if (IsForAllEvents)
        {
            //
            // Enable all events
            //
            DebuggerEnableOrDisableAllEvents(TRUE);
        }
        else
        {
            //
            // Enable just one event
            //
            DebuggerEnableEvent(DebuggerEventModificationRequest->Tag);
        }
    }
    else if (DebuggerEventModificationRequest->TypeOfAction == DEBUGGER_MODIFY_EVENTS_DISABLE)
    {
        if (IsForAllEvents)
        {
            //
            // Disable all events
            //
            DebuggerEnableOrDisableAllEvents(FALSE);
        }
        else
        {
            //
            // Disable just one event
            //
            DebuggerDisableEvent(DebuggerEventModificationRequest->Tag);
        }
    }
    else if (DebuggerEventModificationRequest->TypeOfAction == DEBUGGER_MODIFY_EVENTS_CLEAR)
    {
        if (IsForAllEvents)
        {
            //
            // Clear all events
            //
            DebuggerClearAllEvents(InputFromVmxRoot, PoolManagerAllocatedMemory);
        }
        else
        {
            //
            // Clear just one event
            //
            DebuggerClearEvent(DebuggerEventModificationRequest->Tag, InputFromVmxRoot, PoolManagerAllocatedMemory);
        }
    }
    else if (DebuggerEventModificationRequest->TypeOfAction == DEBUGGER_MODIFY_EVENTS_QUERY_STATE)
    {
        //
        // check if tag is valid or not
        //
        if (!DebuggerIsTagValid(DebuggerEventModificationRequest->Tag))
        {
            DebuggerEventModificationRequest->KernelStatus = DEBUGGER_ERROR_TAG_NOT_EXISTS;
            return FALSE;
        }

        //
        // Set event state
        //
        if (DebuggerQueryStateEvent(DebuggerEventModificationRequest->Tag))
        {
            DebuggerEventModificationRequest->IsEnabled = TRUE;
        }
        else
        {
            DebuggerEventModificationRequest->IsEnabled = FALSE;
        }
    }
    else
    {
        //
        // Invalid parameter specified in TypeOfAction
        //
        DebuggerEventModificationRequest->KernelStatus = DEBUGGER_ERROR_MODIFY_EVENTS_INVALID_TYPE_OF_ACTION;

        return FALSE;
    }

    //
    // The function was successful
    //
    DebuggerEventModificationRequest->KernelStatus = DEBUGGER_OPERATION_WAS_SUCCESSFUL;
    return TRUE;
}
