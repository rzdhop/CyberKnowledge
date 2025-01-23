# UEFI Programming 101

- see https://wiki.osdev.org/GNU-EFI

## Setup

- we need some libs to use uefi functions, here we use gnu-efi (from source)

```bash
git clone https://git.code.sf.net/p/gnu-efi/code gnu-efi
cd gnu-efi
make
```

- 

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

### In Qemu

- Here we use the best emulator QEMU (of course capable of UEFI) 

#### The EZ way with `uefi-run`

- uefir-run is a wrapped tool that automatically do the whole process of creating FAT image disk, copying EFI binary to it and running qemu with the right configuration to boot OVMF UEFI program that finally can load our won program via the Boot manager or via the UEFI shell

#### The hard way

- setup image disk

```bash
dd if=/dev/zero of=test.img bs=1M count=64
mkfs.fat test.img
```

```bash
mmd -i test.img ::/EFI
mmd -i test.img ::/EFI/BOOT
mcopy -i test.img BOOTX64.EFI ::/EFI/BOOT/
```

```bash
qemu-system-x86_64 --boot menu=on -net none -bios /usr/share/OVMF/x64/OVMF.4m.fd -drive file=test.img,format=raw,media=disk
```

### In bare-metal

- TODO