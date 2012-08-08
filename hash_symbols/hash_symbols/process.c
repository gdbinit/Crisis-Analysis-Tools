/*
 *   ___ ___               .__                       
 *  /   |   \_____    _____|  |__                    
 * /    ~    \__  \  /  ___/  |  \                   
 * \    Y    // __ \_\___ \|   Y  \                  
 *  \___|_  /(____  /____  >___|  /                  
 *        \/      \/     \/     \/                   
 *   _________            ___.          .__          
 *  /   _____/__.__. _____\_ |__   ____ |  |   ______
 *  \_____  <   |  |/     \| __ \ /  _ \|  |  /  ___/
 *  /        \___  |  Y Y  \ \_\ (  <_> )  |__\___ \ 
 * /_______  / ____|__|_|  /___  /\____/|____/____  >
 *         \/\/          \/    \/                 \/ 
 *
 * (c) 2012, fG! - reverser@put.as - http://reverse.put.as
 *
 * -> You are free to use this code as long as you keep the original copyright <-
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * process.c
 *
 */

#include "process.h"
#include "structures.h"
#include "mach_o.h"
#include "hashing.h"
#include <mach-o/fat.h>
#include <mach-o/nlist.h>
#include <arpa/inet.h>

extern options_t options;

/*
 * process fat archives
 * we just find out how many binaries are inside the fat archive and call the function to
 * process non-fat binaries
 */
void
process_fat_binary(uint8_t **targetBuffer)
{
    // we need to read fat headers and get the location of each binary inside it
    // don't forget that fat headers are always big-endian :-)
    uint8_t *address = *targetBuffer;
    uint32_t nrFatArch  = 0;
    
    // retrieve the number of binaries inside the fat archive
    struct fat_header *fatheader_ptr = (struct fat_header *)address;
    nrFatArch = ntohl(fatheader_ptr->nfat_arch);
    // pointer to the first fat_arch structure
    struct fat_arch *fatArch = (struct fat_arch*)(address + sizeof(struct fat_header));
    
    // if arch is set find the selected arch
    if (options.arch)
    {
        // find the correct architecture
        for (uint32_t i = 0; i < nrFatArch; i++)
        {
            // for ARM we need to match cpusubtype!
            // FIXME: test with a ARM binary
            if (ntohl(fatArch->cputype) == options.arch || ntohl(fatArch->cpusubtype) == options.arch)
            {
                uint8_t *location = address + ntohl(fatArch->offset);
                process_nonfat_binary(&location);
                break;
            }
            fatArch++;
        }
    }
    // else iterate thru all fat_archs and process those binaries
    else
    {
        for (uint32_t i = 0; i < nrFatArch; i++)
        {
            uint8_t *location = address + ntohl(fatArch->offset);
            process_nonfat_binary(&location);
            fatArch++;
        }
    }
    
}

/*
 * this will process non-fat mach-o binaries/libraries
 * since fat binaries include the non-fat versions we can use it to process the fat binaries :-)
 *
 */
void
process_nonfat_binary(uint8_t **targetBuffer)
{
    uint8_t *address = *targetBuffer;
    struct header_info header_info;
    // read header information
    header_info = process_macho_header(targetBuffer);
    // process it
    struct nlist *nlist = NULL;
    struct nlist_64 *nlist64 = NULL;
    
    if (header_info.is64Bits)
    {
        nlist64 = (struct nlist_64*)(address + header_info.symtab_symoff);
        char *symbolString;
        for (uint32_t x = 0; x < header_info.symtab_nsyms; x++)
        {
            uint8_t isSymbolExternal = nlist64->n_type & N_EXT;
            uint8_t isSymbolDefined  = (nlist64->n_type & N_TYPE) == N_SECT ? 1 : 0;
            if (isSymbolExternal && isSymbolDefined && nlist64->n_sect == 1)
            {
                symbolString = ((char*)*targetBuffer + header_info.symtab_stroff+nlist64->n_un.n_strx);
                printf("Symbol found %s %llx %x section %d %x!\n", symbolString,nlist64->n_value, nlist64->n_un.n_strx, nlist64->n_sect, hash_string(symbolString));
            }
            nlist64++;            
        }
    }
    else
    {
        nlist = (struct nlist*)(address + header_info.symtab_symoff);
        char *symbolString;
        for (uint32_t x = 0; x < header_info.symtab_nsyms; x++)
        {
            // What we are looking for are:
            // 1) External symbols: N_EXT is set
            // 2) Defined in a section: N_SECT is set
            // 3) Defined in __TEXT section: n_sect = __TEXT section index
            // We might remove the 3) requirement!
            uint8_t isSymbolExternal = nlist->n_type & N_EXT;
            uint8_t isSymbolDefined  = (nlist->n_type & N_TYPE) == N_SECT ? 1 : 0;
            if (isSymbolExternal && isSymbolDefined && nlist->n_sect == 1)
            {
                symbolString = ((char*)*targetBuffer + header_info.symtab_stroff+nlist->n_un.n_strx);
                printf("Symbol found %s %x %x section %d %08x!\n", symbolString,nlist->n_value, nlist->n_un.n_strx, nlist->n_sect, hash_string(symbolString));
            }
            nlist++;
        }
    }
}

