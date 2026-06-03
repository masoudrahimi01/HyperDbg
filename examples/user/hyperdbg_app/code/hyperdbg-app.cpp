/**
 * @file hyperdbg-app.cpp
 * @author Sina Karvandi (sina@hyperdbg.org)
 * @brief Controller of the reversing machine's module
 * @details
 *
 * @version 0.2
 * @date 2023-02-01
 *
 * @copyright This project is released under the GNU Public License v3.
 *
 */
#include "pch.h"

PVOID g_SharedMessageBuffer = NULL;

/**
 * @brief Show messages
 *
 * @param Text
 * @return int
 */
int
hyperdbg_show_messages(const char * Text)
{
    printf("%s", Text);
    return 0;
}

/**
 * @brief Show messages (shared buffer)
 *
 * @param Text
 * @return int
 */
int
hyperdbg_show_messages_shared_buffer()
{
    printf("%s", (char *)g_SharedMessageBuffer);
    return 0;
}

/**
 * @brief Load the driver
 *
 * @return int return zero if it was successful or non-zero if there
 * was error
 */
int
hyperdbg_load()
{
    char CpuId[13] = {0};

    //
    // Read the vendor string
    //
    hyperdbg_u_read_vendor_string(CpuId);

    printf("current processor vendor is : %s\n", CpuId);

    if (strcmp(CpuId, "GenuineIntel") == 0)
    {
        printf("virtualization technology is vt-x\n");
    }
    else
    {
        printf("this program is not designed to run in a non-VT-x "
               "environment !\n");
        return 1;
    }

    //
    // Detect if the processor supports vmx operation
    //
    if (hyperdbg_u_detect_vmx_support())
    {
        printf("vmx operation is supported by your processor\n");
    }
    else
    {
#ifdef HYPERDBG_ENV_WINDOWS
        printf("vmx operation is not supported by your processor "
            "(if you are using an Intel processor, it might be because VBS is not disabled!)\n");
#endif        
        return 1;
    }

    //
    // Set callback function for showing messages
    //
    hyperdbg_u_set_text_message_callback(hyperdbg_show_messages);

    //
    // Test interpreter with shared buffer
    //
    // g_SharedMessageBuffer = hyperdbg_u_set_text_message_callback_using_shared_buffer(hyperdbg_show_messages_shared_buffer);

    //
    // Test interpreter
    //
    hyperdbg_u_connect_remote_debugger_using_named_pipe("\\\\.\\pipe\\HyperDbgPipe", TRUE);
    Sleep(10000);
    hyperdbg_u_run_command((CHAR *)"r");
    hyperdbg_u_run_command((CHAR *)".start path c:\\Windows\\system32\\calc.exe");
    hyperdbg_u_continue_debuggee();
    hyperdbg_u_continue_debuggee();
    hyperdbg_u_continue_debuggee();
    hyperdbg_u_continue_debuggee();
    hyperdbg_u_continue_debuggee();
    hyperdbg_u_continue_debuggee();
    hyperdbg_u_continue_debuggee();

    return 0;
}

//
// ===========================================================================
//  Intel PT demo
//
//  Trace ONLY a target process with HyperDbg's hypervisor PT engine, then
//  (optionally) decode the captured packets with libipt. Define USE_LIBIPT
//  (and point the LIBIPT_ROOT environment variable at a libipt install) for
//  full packet decoding; otherwise the demo just captures and prints a summary
//  so this example keeps building with no extra dependency. The HyperDbg SDK
//  PT structs / IOCTLs come in via pch.h -> SDK/HyperDbgSdk.h.
//
//  HyperDbg must already be loaded (e.g. via the hyperdbg-cli 'load vmm').
// ===========================================================================

#define HYPERDBG_PT_DEVICE_NAME "\\\\.\\HyperDbgDebuggerDevice"

#ifdef USE_LIBIPT
#include <intel-pt.h>
#endif

/**
 * @brief One synchronous PT operation IOCTL round-trip
 *
 * @param Device
 * @param Req
 * @return BOOLEAN
 */
static BOOLEAN
hyperdbg_pt_operation(HANDLE Device, HYPERTRACE_PT_OPERATION_PACKETS * Req)
{
    DWORD Returned = 0;

    if (!DeviceIoControl(Device,
                         IOCTL_PERFORM_HYPERTRACE_PT_OPERATION,
                         Req,
                         SIZEOF_HYPERTRACE_PT_OPERATION_PACKETS,
                         Req,
                         SIZEOF_HYPERTRACE_PT_OPERATION_PACKETS,
                         &Returned,
                         NULL) ||
        Req->KernelStatus != DEBUGGER_OPERATION_WAS_SUCCESSFUL)
    {
        printf("[-] PT op %u failed (err=%lu, KernelStatus=0x%x)\n",
               Req->PtOperationType, GetLastError(), Req->KernelStatus);
        return FALSE;
    }

    return TRUE;
}

#ifdef USE_LIBIPT
/**
 * @brief Decode one CPU's raw PT byte stream with the libipt packet decoder
 *
 * @param Cpu
 * @param Buffer
 * @param Size
 * @return VOID
 */
static void
hyperdbg_pt_decode_cpu(UINT32 Cpu, const uint8_t * Buffer, uint64_t Size)
{
    struct pt_config           Config;
    struct pt_packet_decoder * Decoder;
    uint64_t                   Packets = 0;

    memset(&Config, 0, sizeof(Config));
    Config.size  = sizeof(Config);
    Config.begin = (uint8_t *)Buffer;
    Config.end   = (uint8_t *)Buffer + Size;

    Decoder = pt_pkt_alloc_decoder(&Config);
    if (Decoder == NULL)
        return;

    for (;;)
    {
        int Status = pt_pkt_sync_forward(Decoder);
        if (Status < 0)
            break;

        for (;;)
        {
            struct pt_packet Packet;
            Status = pt_pkt_next(Decoder, &Packet, sizeof(Packet));
            if (Status < 0)
                break;
            if (Packet.type != ppt_pad)
                Packets++;
        }

        if (Status == -pte_eos)
            break;
    }

    printf("  [cpu %u] decoded %llu packets from 0x%llx bytes\n",
           Cpu, (unsigned long long)Packets, (unsigned long long)Size);

    pt_pkt_free_decoder(Decoder);
}
#endif

/**
 * @brief Trace a single process end-to-end with HyperDbg's Intel PT engine
 *
 * @param TargetCommandLine
 * @return int zero on success
 */
int
hyperdbg_intel_pt_demo(const char * TargetCommandLine)
{
    HANDLE                          Device;
    HYPERTRACE_PT_OPERATION_PACKETS Op;
    HYPERTRACE_PT_MMAP_PACKETS      Mmap;
    STARTUPINFOA                    Startup = {0};
    PROCESS_INFORMATION             Proc    = {0};
    char                            CommandLine[1024] = {0};
    DWORD                           Returned          = 0;

    strncpy_s(CommandLine, sizeof(CommandLine), TargetCommandLine, _TRUNCATE);

    //
    // Open the HyperDbg device
    //
    Device = CreateFileA(HYPERDBG_PT_DEVICE_NAME,
                         GENERIC_READ | GENERIC_WRITE,
                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL,
                         OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL,
                         NULL);
    if (Device == INVALID_HANDLE_VALUE)
    {
        printf("[-] cannot open %s (err=%lu). Is HyperDbg loaded? Run elevated.\n",
               HYPERDBG_PT_DEVICE_NAME, GetLastError());
        return 1;
    }

    //
    // Create the target SUSPENDED so PT is armed before any code runs
    //
    Startup.cb = sizeof(Startup);
    if (!CreateProcessA(NULL, CommandLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &Startup, &Proc))
    {
        printf("[-] CreateProcess('%s') failed (err=%lu)\n", CommandLine, GetLastError());
        CloseHandle(Device);
        return 1;
    }
    printf("[+] launched '%s' suspended, pid=%lu\n", CommandLine, Proc.dwProcessId);

    //
    // Filter PT to this process only (the driver resolves the PID to its CR3)
    //
    memset(&Op, 0, sizeof(Op));
    Op.PtOperationType = HYPERTRACE_PT_OPERATION_REQUEST_TYPE_FILTER;
    Op.TraceUser       = 1;
    Op.TargetProcessId = Proc.dwProcessId;
    if (!hyperdbg_pt_operation(Device, &Op))
        goto Fail;

    //
    // Enable tracing (allocates per-CPU buffers and starts)
    //
    memset(&Op, 0, sizeof(Op));
    Op.PtOperationType = HYPERTRACE_PT_OPERATION_REQUEST_TYPE_ENABLE;
    if (!hyperdbg_pt_operation(Device, &Op))
        goto Fail;

    //
    // Map the per-CPU buffers into this process
    //
    memset(&Mmap, 0, sizeof(Mmap));
    if (!DeviceIoControl(Device,
                         IOCTL_PERFORM_HYPERTRACE_PT_MMAP,
                         &Mmap,
                         SIZEOF_HYPERTRACE_PT_MMAP_PACKETS,
                         &Mmap,
                         SIZEOF_HYPERTRACE_PT_MMAP_PACKETS,
                         &Returned,
                         NULL) ||
        Mmap.KernelStatus != DEBUGGER_OPERATION_WAS_SUCCESSFUL)
    {
        printf("[-] pt_mmap failed (err=%lu, KernelStatus=0x%x)\n", GetLastError(), Mmap.KernelStatus);
        goto Disable;
    }
    printf("[+] PT enabled and %u per-CPU buffers mapped\n", Mmap.NumCpus);

    //
    // Run the target to completion
    //
    ResumeThread(Proc.hThread);
    WaitForSingleObject(Proc.hProcess, INFINITE);
    printf("[+] target exited, collecting trace\n");

    //
    // Pause tracing, then snapshot the per-CPU byte counts
    //
    memset(&Op, 0, sizeof(Op));
    Op.PtOperationType = HYPERTRACE_PT_OPERATION_REQUEST_TYPE_PAUSE;
    hyperdbg_pt_operation(Device, &Op);

    memset(&Op, 0, sizeof(Op));
    Op.PtOperationType = HYPERTRACE_PT_OPERATION_REQUEST_TYPE_SIZE;
    if (!hyperdbg_pt_operation(Device, &Op))
        goto Disable;

    //
    // Decode (or summarize) each CPU's captured trace
    //
    for (UINT32 i = 0; i < Mmap.NumCpus; i++)
    {
        UINT32 Cpu   = Mmap.Cpus[i].CpuId;
        UINT64 Bytes = (Cpu < Op.NumCpus) ? Op.BytesPerCpu[Cpu] : 0;

        if (Bytes > Mmap.Cpus[i].Size)
            Bytes = Mmap.Cpus[i].Size;
        if (Bytes == 0)
            continue;

#ifdef USE_LIBIPT
        hyperdbg_pt_decode_cpu(Cpu, (const uint8_t *)(ULONG_PTR)Mmap.Cpus[i].UserVa, Bytes);
#else
        printf("  [cpu %u] captured 0x%llx bytes at va 0x%llx (define USE_LIBIPT to decode)\n",
               Cpu,
               (unsigned long long)Bytes,
               (unsigned long long)Mmap.Cpus[i].UserVa);
#endif
    }

    //
    // Disable PT (frees buffers and tears down the mappings)
    //
    memset(&Op, 0, sizeof(Op));
    Op.PtOperationType = HYPERTRACE_PT_OPERATION_REQUEST_TYPE_DISABLE;
    hyperdbg_pt_operation(Device, &Op);

    CloseHandle(Proc.hThread);
    CloseHandle(Proc.hProcess);
    CloseHandle(Device);
    return 0;

Disable:
    memset(&Op, 0, sizeof(Op));
    Op.PtOperationType = HYPERTRACE_PT_OPERATION_REQUEST_TYPE_DISABLE;
    hyperdbg_pt_operation(Device, &Op);
Fail:
    TerminateProcess(Proc.hProcess, 1);
    CloseHandle(Proc.hThread);
    CloseHandle(Proc.hProcess);
    CloseHandle(Device);
    return 1;
}

/**
 * @brief main function
 *
 * @return int
 */
int
main(int argc, char * argv[])
{
    //
    // Target process to trace; pass one on the command line or use the default
    //
    const char * Target = (argc > 1) ? argv[1] : "C:\\Windows\\System32\\hostname.exe";

    return hyperdbg_intel_pt_demo(Target);
}
