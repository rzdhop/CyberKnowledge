// Compile with: clang -O2 -g -Wall eBPF_loader.c -o eBPF_loader -lbpf -lelf -lz
#include <stdio.h>
#include <stdlib.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    int err;

    // Ouvrir l'ELF qui contient le code eBPF
    //
    obj = bpf_object__open_file("eBPF_payload.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Error opening BPF object\n");
        return 1;
    }

    // Charger le programme dans le noyau
    // c'est ici que le verificateur eBPF fait ses checks
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Error loading BPF object: %d\n", err);
        return 1;
    }

    // Attacher automatiquement les kprobes
    //parcours l'ELF BPF pour trouver le kprobe (SEC(...)) et register un callback kernel
	  // j'aurais pu le faire manuellement avec : 
	  /*
		struct bpf_program *prog = bpf_object__find_program_by_title(obj, "kprobe/do_sys_openat2");
			if (!prog) {
		    fprintf(stderr, "Program not found\n");
		    return -1;
			}
		int err = bpf_program__attach_kprobe(prog, false (`non-retprobe`) , "do_sys_openat2");

	  */
    // https://elixir.bootlin.com/linux/v6.12.1/source/tools/lib/bpf/libbpf.c#L11248
    err = bpf_object__attach_skeleton(obj);
    if (err) {
        fprintf(stderr, "Error attaching BPF program: %d\n", err);
        return 1;
    }

    printf("BPF program loaded and attached.\n");
    // Rester actif pour garder le programme en vie
    for (;;) {
        // liste les programmes eBPF : sudo bpftool prog show
        // On peut lire les logs via "sudo cat /sys/kernel/debug/tracing/trace_pipe"
        sleep(999999);
    }
    return 0;
}