// SPDX-License-Identifier: GPL-2.0
// La liscence pour le code quand la section sera pour le binaire ELF
#include "vmlinux.h" //headers de BPF CO-RE (Compile Once, Run Everywhere)
#include <bpf/bpf_helpers.h> 
#include <bpf/bpf_tracing.h>

// req : bpftool
//get vmlinux.h -> bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
//Compile w/ clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c eBPF_payload.c -o eBPF_payload.bpf.o

SEC("kprobe/do_sys_openat2") // défini une section du binaire ELF pour l'eBPF loader, on lui indique d'utiliser kprobe pour hook do_sys_openat2
int BPF_KPROBE(handle_do_sys_openat2, int dfd, const char *filename, int flags, umode_t mode)
//BPF_KPROBE -> macro pour declarer une fonction kprobe, avec eBPF on peux récupérer les argument typé des syscall (contrairement a kprob seul)
//Défini ici : https://docs.ebpf.io/ebpf-library/libbpf/ebpf/BPF_KPROBE/
{
    // [tgid(32b)]|[pid(32b)]
    __UINT32_TYPE__ pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    bpf_printk("[eBPF-openat2] File %s openend by PID : %d\n", filename, pid);
    return 0;
}
/*
Sans la Macro BPF_PROBE

SEC("kprobe/do_sys_openat2")
int handle_do_sys_open(struct pt_regs *ctx)
{
    // Récupération des arguments depuis les registres
    // Exemple : 
    // 1er argument -> PT_REGS_PARM1(ctx)
    // 2e argument -> PT_REGS_PARM2(ctx)
    // ...
    
    // Dans do_sys_openat2, l'ordre des arguments est (dfd, filename, flags, mode).
    // On peut donc faire:
    int dfd = (int)PT_REGS_PARM1(ctx);
    const char *filename = (const char *)PT_REGS_PARM2(ctx);
    int flags = (int)PT_REGS_PARM3(ctx);
    umode_t mode = (umode_t)PT_REGS_PARM4(ctx);

    // On peut ensuite appeler bpf_printk :
    __u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_printk("[eBPF] File %s opened by PID %d\n", filename, pid);

    return 0;
}
*/

SEC("kprobe/do_sys_open")
int BPF_KPROBE(handle_do_sys_open, int dfd, const char *filename, int flags, umode_t mode)

{
    __UINT32_TYPE__ pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    //écrit dans /sys/kernel/debug/tracing/trace_pipe
    bpf_printk("[eBPF-open] File %s openend by PID : %d\n", filename, pid);
    return 0;
}

//SEC("tracepoint/<catégorie>/<nom_du_tracepoint>")
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    bpf_printk("Execve called by PID %d\n", bpf_get_current_pid_tgid() & 0xFFFFFFFF);
    return 0;
}

//on ajoute une section au binaire pour précisé la liscense
//permet au BPF loader de confirmer les exigences légales etc... on s'en fou un peu
char LICENSE[] SEC("license") = "GPL";
