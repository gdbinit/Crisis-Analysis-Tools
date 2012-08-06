/*
 * Quick IDC hack to search a given hash and comment out with library name
 * Put cursor on the push HASH instruction and execute this IDC.
 */
#include <idc.idc>

auto arrayid;
auto arrayindex;
auto hash, symbolname;
auto hashtomatch;
auto comment;

// the array where we imported hashes to
arrayid = GetArrayId("libsysbhashes");
arrayindex = 0;

// get hash value from the push operand
hashtomatch = GetOperandValue(ScreenEA(), 0);
// lookup hash in the array
while ((hash = GetArrayElement(AR_LONG, arrayid, arrayindex)) != 0)
{
    if (hash == hashtomatch)
    {
//        Message("Found hash %x -> %s\n", hash, GetArrayElement(AR_STR, arrayid, arrayindex));
        comment = form("\"%s\"", GetArrayElement(AR_STR, arrayid, arrayindex));
        MakeComm(ScreenEA(), comment);
        break;
    }
    arrayindex = arrayindex + 1;
}
