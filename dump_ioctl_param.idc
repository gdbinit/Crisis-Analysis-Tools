/*
 * simple script to dump and comment request being passed to ioctl
 * OS.X/Crisis uses a device driver for controlling the rootkit
 * the requests are passed in esp+4 call to ioctl()
 * It's easy to dump since it's always in this format:
 * __text:0000E1FA C7 44 24 04+                mov     dword ptr [esp+4], 807AEEC0h ; unsigned __int32
 * __text:0000E202 E8 33 B1 03+                call    _ioctl          ; 0x807aeec0
 */
#include <idc.idc>

auto location, reference, totalrefs, previnst, opvalue, comment;
auto file, fd;

location = LocByName("_ioctl");

file = AskFile(1, "*.txt", "Select txt to dump output");
fd = fopen(file, "w");

for (reference = RfirstB(location); reference != BADADDR; reference = RnextB(location, reference))
{
    previnst = FindCode(reference, SEARCH_UP);
    comment = sprintf("0x%x", GetOperandValue(previnst, 1));
    MakeComm(reference, comment);
    fprintf(fd, "%s\n", comment);
    totalrefs = totalrefs + 1;
}
Message("Total references %d\n", totalrefs);
fclose(fd);
