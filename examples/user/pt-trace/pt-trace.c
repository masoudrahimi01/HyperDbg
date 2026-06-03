/**
 * @file pt-trace.c
 * @author Masoud Rahimi Jafari (Masoodrahimy1379@gmail.com)
 * @brief Launch an executable, trace ONLY that process with HyperDbg's
 *        Intel PT engine, then decode the captured packets with libipt.
 *
 * @details Flow:
 *            1. open the HyperDbg device
 *            2. create the target process suspended
 *            3. !pt filter user, process = <pid>   (driver resolves PID->CR3)
 *            4. !pt enable
 *            5. pt_mmap  -> per-CPU buffer VAs are mapped into THIS process
 *            6. resume the target and wait for it to exit
 *            7. !pt pause ; !pt size  -> per-CPU valid byte counts
 *            8. decode every CPU's buffer with libipt and print packets
 *            9. !pt disable  (tears the mappings down)
 *
 * @copyright This project is released under the GNU Public License v3.
 */
#include "hyperdbg-pt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <intel-pt.h>

//
// One synchronous PT operation IOCTL round-trip.
//
static BOOLEAN
PtOperation(HANDLE Device, HYPERTRACE_PT_OPERATION_PACKETS * Req)
{
    DWORD Returned = 0;

    if (!DeviceIoControl(Device,
                         IOCTL_PERFORM_HYPERTRACE_PT_OPERATION,
                         Req,
                         sizeof(*Req),
                         Req,
                         sizeof(*Req),
                         &Returned,
                         NULL))
    {
        printf("[-] PT ioctl failed (op %u), GetLastError = 0x%lx\n", Req->PtOperationType, GetLastError());
        return FALSE;
    }

    if (Req->KernelStatus != DEBUGGER_OPERATION_WAS_SUCCESSFUL)
    {
        printf("[-] PT op %u rejected by driver, KernelStatus = 0x%x\n", Req->PtOperationType, Req->KernelStatus);
        return FALSE;
    }

    return TRUE;
}

//
// Pretty-print one decoded PT packet (pad packets are counted, not printed).
//
static void
PrintPacket(uint64_t Offset, const struct pt_packet * P)
{
    printf("    %09llx  ", (unsigned long long)Offset);

    switch (P->type)
    {
    case ppt_psb:     printf("psb\n"); break;
    case ppt_psbend:  printf("psbend\n"); break;
    case ppt_tnt_8:   printf("tnt.8    %u bits\n", (unsigned)P->payload.tnt.bit_size); break;
    case ppt_tnt_64:  printf("tnt.64   %u bits\n", (unsigned)P->payload.tnt.bit_size); break;
    case ppt_tip:     printf("tip      %016llx\n", (unsigned long long)P->payload.ip.ip); break;
    case ppt_tip_pge: printf("tip.pge  %016llx\n", (unsigned long long)P->payload.ip.ip); break;
    case ppt_tip_pgd: printf("tip.pgd  %016llx\n", (unsigned long long)P->payload.ip.ip); break;
    case ppt_fup:     printf("fup      %016llx\n", (unsigned long long)P->payload.ip.ip); break;
    case ppt_pip:     printf("pip      cr3 %016llx\n", (unsigned long long)P->payload.pip.cr3); break;
    case ppt_mode:    printf("mode\n"); break;
    case ppt_tsc:     printf("tsc      %llu\n", (unsigned long long)P->payload.tsc.tsc); break;
    case ppt_cbr:     printf("cbr      %u\n", (unsigned)P->payload.cbr.ratio); break;
    case ppt_tma:     printf("tma      ctc %u fc %u\n", (unsigned)P->payload.tma.ctc, (unsigned)P->payload.tma.fc); break;
    case ppt_mtc:     printf("mtc      %u\n", (unsigned)P->payload.mtc.ctc); break;
    case ppt_cyc:     printf("cyc      %llu\n", (unsigned long long)P->payload.cyc.value); break;
    case ppt_ovf:     printf("ovf\n"); break;
    case ppt_stop:    printf("stop\n"); break;
    case ppt_vmcs:    printf("vmcs     %016llx\n", (unsigned long long)P->payload.vmcs.base); break;
    case ppt_ptw:     printf("ptw      %016llx\n", (unsigned long long)P->payload.ptw.payload); break;
    case ppt_mnt:     printf("mnt      %016llx\n", (unsigned long long)P->payload.mnt.payload); break;
    default:          printf("type %d  (size %u)\n", (int)P->type, (unsigned)P->size); break;
    }
}

//
// Decode one CPU's raw PT byte stream with the libipt packet decoder.
//
static void
DecodeCpuBuffer(uint32_t Cpu, const uint8_t * Buffer, uint64_t Size)
{
    struct pt_config          Config;
    struct pt_packet_decoder * Decoder;
    uint64_t                   Packets = 0;
    uint64_t                   Pads    = 0;

    memset(&Config, 0, sizeof(Config));
    Config.size  = sizeof(Config);
    Config.begin = (uint8_t *)Buffer;
    Config.end   = (uint8_t *)Buffer + Size;

    Decoder = pt_pkt_alloc_decoder(&Config);
    if (Decoder == NULL)
    {
        printf("  [cpu %u] failed to allocate libipt decoder\n", Cpu);
        return;
    }

    printf("  [cpu %u] decoding 0x%llx bytes:\n", Cpu, (unsigned long long)Size);

    for (;;)
    {
        int Status = pt_pkt_sync_forward(Decoder);
        if (Status < 0)
        {
            if (Status != -pte_eos)
                printf("    sync error: %s\n", pt_errstr(pt_errcode(Status)));
            break;
        }

        for (;;)
        {
            struct pt_packet Packet;
            uint64_t         Offset = 0;

            Status = pt_pkt_next(Decoder, &Packet, sizeof(Packet));
            if (Status < 0)
                break;

            if (Packet.type == ppt_pad)
            {
                Pads++;
                continue;
            }

            pt_pkt_get_offset(Decoder, &Offset);
            PrintPacket(Offset, &Packet);
            Packets++;
        }

        if (Status == -pte_eos)
            break;
    }

    printf("  [cpu %u] %llu packets (+%llu pad) decoded\n\n",
           Cpu,
           (unsigned long long)Packets,
           (unsigned long long)Pads);

    pt_pkt_free_decoder(Decoder);
}

int
main(int argc, char ** argv)
{
    HANDLE                          Device;
    HYPERTRACE_PT_OPERATION_PACKETS Op;
    HYPERTRACE_PT_MMAP_PACKETS      Mmap;
    STARTUPINFOA                    Startup = {0};
    PROCESS_INFORMATION             Proc    = {0};
    char                            CommandLine[1024]= {0};
    DWORD                           Returned = 0;
    int                             i;

    if (argc < 2)
    {
        printf("usage: %s <target.exe> [args...]\n", argv[0]);
        return 1;
    }

    //
    // Stitch argv[1..] back into a single command line for CreateProcess.
    //
    for (i = 1; i < argc; i++)
    {
        strncat_s(CommandLine, sizeof(CommandLine), argv[i], _TRUNCATE);
        if (i + 1 < argc)
            strncat_s(CommandLine, sizeof(CommandLine), " ", _TRUNCATE);
    }

    //
    // 1. Open the HyperDbg device.
    //
    Device = CreateFileA(HYPERDBG_DEVICE_NAME,
                         GENERIC_READ | GENERIC_WRITE,
                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL,
                         OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL,
                         NULL);
    if (Device == INVALID_HANDLE_VALUE)
    {
        printf("[-] cannot open %s (err 0x%lx). Is HyperDbg loaded? Run as admin.\n",
               HYPERDBG_DEVICE_NAME, GetLastError());
        return 1;
    }

    //
    // 2. Create the target SUSPENDED so we can arm PT before any code runs.
    //
    Startup.cb = sizeof(Startup);
    if (!CreateProcessA(NULL, CommandLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &Startup, &Proc))
    {
        printf("[-] CreateProcess('%s') failed (err 0x%lx)\n", CommandLine, GetLastError());
        CloseHandle(Device);
        return 1;
    }
    printf("[+] launched '%s' suspended, pid = %lu\n", CommandLine, Proc.dwProcessId);

    //
    // 3. Filter PT to this process only (user mode). The driver turns the
    //    PID into the process CR3 and programs IA32_RTIT_CR3_MATCH.
    //
    memset(&Op, 0, sizeof(Op));
    Op.PtOperationType = HYPERTRACE_PT_OP_FILTER;
    Op.TraceUser       = 1;
    Op.TraceKernel     = 0;
    Op.TargetProcessId = Proc.dwProcessId;
    if (!PtOperation(Device, &Op))
        goto Fail;
    printf("[+] PT filter set to pid %lu (user-mode only)\n", Proc.dwProcessId);

    //
    // 4. Enable PT (allocates per-CPU ToPA/output buffers and starts tracing).
    //
    memset(&Op, 0, sizeof(Op));
    Op.PtOperationType = HYPERTRACE_PT_OP_ENABLE;
    if (!PtOperation(Device, &Op))
        goto Fail;
    printf("[+] PT enabled\n");

    //
    // 5. Map the per-CPU buffers into this process's address space.
    //
    memset(&Mmap, 0, sizeof(Mmap));
    if (!DeviceIoControl(Device, IOCTL_PERFORM_HYPERTRACE_PT_MMAP,
                         &Mmap, sizeof(Mmap), &Mmap, sizeof(Mmap), &Returned, NULL) ||
        Mmap.KernelStatus != DEBUGGER_OPERATION_WAS_SUCCESSFUL)
    {
        printf("[-] pt_mmap failed (err 0x%lx, KernelStatus 0x%x)\n", GetLastError(), Mmap.KernelStatus);
        goto DisableFail;
    }
    printf("[+] pt_mmap mapped %u per-CPU buffers:\n", Mmap.NumCpus);
    for (i = 0; i < (int)Mmap.NumCpus; i++)
        printf("      cpu %u : va 0x%016llx  size 0x%llx\n",
               Mmap.Cpus[i].CpuId,
               (unsigned long long)Mmap.Cpus[i].UserVa,
               (unsigned long long)Mmap.Cpus[i].Size);

    //
    // 6. Resume the target and wait for it to finish.
    //
    ResumeThread(Proc.hThread);
    printf("[+] target resumed, waiting for exit...\n");
    WaitForSingleObject(Proc.hProcess, INFINITE);
    printf("[+] target exited\n");

    //
    // 7. Pause tracing, then snapshot how many valid bytes each CPU holds.
    //
    memset(&Op, 0, sizeof(Op));
    Op.PtOperationType = HYPERTRACE_PT_OP_PAUSE;
    if (!PtOperation(Device, &Op))
        goto DisableFail;

    memset(&Op, 0, sizeof(Op));
    Op.PtOperationType = HYPERTRACE_PT_OP_SIZE;
    if (!PtOperation(Device, &Op))
        goto DisableFail;

    //
    // 8. Decode and print each CPU's captured trace.
    //
    printf("\n===== decoded Intel PT packets =====\n");
    for (i = 0; i < (int)Mmap.NumCpus; i++)
    {
        uint32_t Cpu   = Mmap.Cpus[i].CpuId;
        uint64_t Bytes = (Cpu < Op.NumCpus) ? Op.BytesPerCpu[Cpu] : 0;

        //
        // Never read past the actual mapping.
        //
        if (Bytes > Mmap.Cpus[i].Size)
            Bytes = Mmap.Cpus[i].Size;

        if (Bytes == 0)
            continue;

        DecodeCpuBuffer(Cpu, (const uint8_t *)(ULONG_PTR)Mmap.Cpus[i].UserVa, Bytes);
    }

    //
    // 9. Disable PT (frees buffers and tears down the user mappings).
    //
    memset(&Op, 0, sizeof(Op));
    Op.PtOperationType = HYPERTRACE_PT_OP_DISABLE;
    PtOperation(Device, &Op);
    printf("[+] PT disabled, done\n");

    CloseHandle(Proc.hThread);
    CloseHandle(Proc.hProcess);
    CloseHandle(Device);
    return 0;

DisableFail:
    //
    // Best-effort teardown of PT and the suspended/running target.
    //
    memset(&Op, 0, sizeof(Op));
    Op.PtOperationType = HYPERTRACE_PT_OP_DISABLE;
    PtOperation(Device, &Op);

Fail:
    TerminateProcess(Proc.hProcess, 1);
    CloseHandle(Proc.hThread);
    CloseHandle(Proc.hProcess);
    CloseHandle(Device);
    return 1;
}
