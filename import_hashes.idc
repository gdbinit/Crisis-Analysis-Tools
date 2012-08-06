/*
 * Quick IDC hack to import hashes database into IDA so we can search and comment
 * format of HASHES FILE should be: symbolname,hash
 */

#include <idc.idc>

auto hashes_file, hash_line;
auto arrayid;

hashes_file = fopen("PATH_TO_HASHES_FILE, "r");
// the id of the array we will create and then search from
arrayid = CreateArray("libsysbhashes");
if (arrayid == -1)
{
 Message("[ERROR] array already exists!\n");
}

auto arrayindex;
auto tlength, hash, symbolname, delimiter;

arrayindex = 0;

while ((hash_line = readstr(hashes_file)) != -1)
{
    tlength = strlen(hash_line)-1;
    delimiter = strstr(hash_line, ",");
    symbolname = substr(hash_line, 0, delimiter);
    hash = xtol(substr(hash_line, delimiter+1, tlength));
    SetArrayString(arrayid, arrayindex, symbolname);
    SetArrayLong(arrayid, arrayindex, hash);
    arrayindex = arrayindex + 1;
}
fclose(hashes_file);
Message("[OK] Hashes import successful!\n");
