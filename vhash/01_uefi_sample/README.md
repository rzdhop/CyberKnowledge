# UEFI Programming 101

## Ressources

- UEFI Specs : [UEFI Spec 2.8B May 2020.pdf](./assets/UEFI%%202.8B%20May%202020.pdf)
- Getting started guide : https://krinkinmu.github.io/2020/10/11/efi-getting-started.html
- Building guide : https://wiki.osdev.org/GNU-EFI


## Setup

- We need some libs to use uefi functions, here we use `gnu-efi` (from source)

```bash
git clone https://git.code.sf.net/p/gnu-efi/code gnu-efi
cd gnu-efi
make
```

- We compile ELF, link it, then convert to PE32

```bash
# compile into ELF object
gcc -I gnu-efi/inc/ \
    -fpic -ffreestanding -fno-stack-protector \
    -fno-stack-check -fshort-wchar -mno-red-zone \
    -maccumulate-outgoing-args \
    -c main.c -o main.o

# link into a ELF shared object
ld -shared -Bsymbolic \
    -L gnu-efi/x86_64/lib -L gnu-efi/x86_64/gnuefi \
    -T gnu-efi/gnuefi/elf_x86_64_efi.lds gnu-efi/x86_64/gnuefi/crt0-efi-x86_64.o \
    main.o -o main.so -lgnuefi -lefi

# convert to PE32
objcopy -j .text -j .sdata -j .data \
    -j .rodata -j .dynamic -j .dynsym  \
    -j .rel -j .rela -j .rel.* -j .rela.* \
    -j .reloc --target efi-app-x86_64 --subsystem=10 \
    main.so main.efi
```

## Running

### Virtualization (Qemu)

- Here we use the best emulator : `QEMU` (which is of course capable of UEFI firmwares like `OVMF`)

#### The EZ way with `uefi-run`

- `uefi-run` is a wrapped tool that automatically do the whole process of creating the FAT16 image disk, creating folder structure and copying EFI binary to it then running qemu with the right configuration to boot OVMF UEFI program that finally can load our own program either via the `Boot manager` entry or via the `UEFI shell`

#### The hard way

- create and format FAT16 image disk :

```bash
dd if=/dev/zero of=test.img bs=1M count=64
mkfs.fat test.img
```

- create folder structure and copy EFI program :

```bash
mmd -i test.img ::/EFI
mmd -i test.img ::/EFI/BOOT
mcopy -i test.img BOOTX64.EFI ::/EFI/BOOT/
```

- run qemu vm with the created disk :

```bash
qemu-system-x86_64 --boot menu=on -net none \
    -bios /usr/share/OVMF/x64/OVMF.4m.fd \
    -drive file=test.img,format=raw,media=disk \
    -nographic
```

- if binary is not named `BOOTX64.EFI` you should run it from the EFI Shell :

![demo](demo.png)

### Bare-metal

- TODO in MS-SIS classroom
