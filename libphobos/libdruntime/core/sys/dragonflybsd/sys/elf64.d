/**
 * D header file for DragonFlyBSD.
 *
 * Authors: Diederik de Groot(port:DragonFlyBSD)
 * Copied:  From core/sys/freebsd/sys
 */
module core.sys.dragonflybsd.sys.elf64;

version (DragonFlyBSD):

extern (C):

import core.stdc.stdint;
public import core.sys.dragonflybsd.sys.elf_common;

alias uint64_t Elf64_Lword;
alias Elf64_Word Elf64_Hashelt;
alias Elf64_Xword Elf64_Size;
alias Elf64_Sxword Elf64_Ssize;

extern (D) pure
{
    auto ELF64_R_TYPE_DATA(I)(I i) { return (cast(Elf64_Xword) i << 32) >> 40; }
    auto ELF64_R_TYPE_ID(I)(I i) { return (cast(Elf64_Xword) i << 56 ) >> 56; }
    auto ELF64_R_TYPE_INFO(D, T)(D d, T t) { return cast(Elf64_Xword) d << 8 + cast(Elf64_Xword) t; }
}

alias Elf_Note Elf64_Nhdr;

struct Elf64_Cap
{
    Elf64_Xword   c_tag;
    union _c_un
    {
        Elf64_Xword     c_val;
        Elf64_Addr      c_ptr;
    } _c_un c_un;
}

extern (D)
{
    auto ELF64_ST_VISIBILITY(O)(O o) { return o & 0x03; }
}
