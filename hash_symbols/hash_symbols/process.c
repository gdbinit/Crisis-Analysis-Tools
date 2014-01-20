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
 * (c) 2012, 2013, 2014 fG! - reverser@put.as - http://reverse.put.as
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

#include <mach-o/fat.h>
#include <mach-o/nlist.h>
#include <arpa/inet.h>
#include <string.h>
#include <libgen.h>
#include <sys/param.h>
#include <errno.h>

#include "structures.h"
#include "mach_o.h"
#include "hashing.h"
#include "logging.h"

extern struct options g_options;

/*
 * process fat archives
 * we just find out how many binaries are inside the fat archive and call the function to
 * process non-fat binaries
 */
void
process_fat_binary(uint8_t *targetBuffer)
{
    // we need to read fat headers and get the location of each binary inside it
    // don't forget that fat headers are always big-endian :-)
    uint32_t nrFatArch  = 0;
    
    // retrieve the number of binaries inside the fat archive
    struct fat_header *fatheader_ptr = (struct fat_header *)targetBuffer;
    nrFatArch = ntohl(fatheader_ptr->nfat_arch);
    // pointer to the first fat_arch structure
    struct fat_arch *fatArch = (struct fat_arch*)(targetBuffer + sizeof(struct fat_header));
    
    // if arch is set find the selected arch
    if (g_options.arch)
    {
        DEBUG_MSG("Processing the selected architecture inside the fat binary...");
        // find the correct architecture
        for (uint32_t i = 0; i < nrFatArch; i++)
        {
            // for ARM we need to match cpusubtype!
            if (ntohl(fatArch->cputype) == g_options.arch ||
                ntohl(fatArch->cpusubtype) == g_options.arch)
            {
                uint8_t *location = targetBuffer + ntohl(fatArch->offset);
                process_nonfat_binary(location);
                break;
            }
            fatArch++;
        }
    }
    // else iterate thru all fat_archs and process those binaries
    else
    {
        DEBUG_MSG("Processing all architectures inside the fat binary...");
        for (uint32_t i = 0; i < nrFatArch; i++)
        {
            uint8_t *location = targetBuffer + ntohl(fatArch->offset);
            // skip over not support ppc
            if (ntohl(fatArch->cputype) == CPU_TYPE_POWERPC ||
                ntohl(fatArch->cputype) == CPU_TYPE_POWERPC64)
            {
                continue;
            }
            process_nonfat_binary(location);
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
process_nonfat_binary(uint8_t *targetBuffer)
{
    uint32_t magic = *(uint32_t*)targetBuffer;
    switch (magic)
    {
        case MH_MAGIC:
        case MH_MAGIC_64:
            break;
        default:
            ERROR_MSG("Invalid target binary!");
            return;
    }
    struct header_info header_info = {0};
    // read header information
    header_info = process_macho_header(targetBuffer);
    // process it
    struct nlist *nlist = NULL;
    struct nlist_64 *nlist64 = NULL;

    // generate hash if we want to find a specific symbol
    uint32_t symbolToMatchHash = 0;
    FILE *outputFile = NULL;
    if (g_options.symbol != NULL)
    {
        symbolToMatchHash = FNV1A_Hash_Jesteress(g_options.symbol, strlen(g_options.symbol));
    }
    else
    {
        char outputName[MAXPATHLEN] = {0};
        if (g_options.outputFile == NULL)
        {
            snprintf(outputName, MAXPATHLEN, "%s_%s_hashes.txt", basename(g_options.targetName), header_info.cpuString);
            outputName[MAXPATHLEN-1] = '\0';
        }
        else
        {
            strlcpy(outputName, g_options.outputFile, MAXPATHLEN);
        }

        // open the file to write, finally!
        DEBUG_MSG("Output file is %s.", outputName);
        outputFile = fopen(outputName, "w+");
        if (outputFile == NULL)
        {
            ERROR_MSG("Failed to open target file for writing: %s.", strerror(errno));
            return;
        }
    }
    
    // start the fun!
    if (header_info.is64Bits)
    {
        char *symbolString = NULL;
        nlist64 = (struct nlist_64*)(targetBuffer + header_info.symtab_symoff);
        for (uint32_t x = 0; x < header_info.symtab_nsyms; x++)
        {
            uint8_t isSymbolExternal = nlist64->n_type & N_EXT;
            uint8_t isSymbolDefined  = (nlist64->n_type & N_TYPE) == N_SECT ? 1 : 0;
            // we want to extract symbols from __TEXT segment so we use the index previously found
            // when processing the mach-o header
            if (isSymbolExternal && isSymbolDefined)// && nlist64->n_sect == header_info.textSegmentIndex)
            {
                symbolString = (char*)(targetBuffer + header_info.symtab_stroff+nlist64->n_un.n_strx);
                if (symbolToMatchHash != 0)
                {
                    uint32_t currentSymbolHash = FNV1A_Hash_Jesteress(symbolString, strlen(symbolString));
                    if (currentSymbolHash == symbolToMatchHash)
                        printf("\nSymbol %s at address 0x%llx has hash 0x%08x !\n", symbolString,nlist64->n_value, hash_string(symbolString));
                }
                else
                {
                    fprintf(outputFile, "%s,%x\n", symbolString, hash_string(symbolString));
                }
            }
            nlist64++;            
        }
    }
    else
    {
        nlist = (struct nlist*)(targetBuffer + header_info.symtab_symoff);
        char *symbolString = NULL;
        
        for (uint32_t x = 0; x < header_info.symtab_nsyms; x++)
        {
            // What we are looking for are:
            // 1) External symbols: N_EXT is set
            // 2) Defined in a section: N_SECT is set
            // 3) Defined in __TEXT section: n_sect = __TEXT section index
            // We might remove the 3) requirement!
            uint8_t isSymbolExternal = nlist->n_type & N_EXT;
            uint8_t isSymbolDefined  = (nlist->n_type & N_TYPE) == N_SECT ? 1 : 0;
            
            if (isSymbolExternal && isSymbolDefined && nlist->n_sect == header_info.textSegmentIndex)
            {
                symbolString = (char*)(targetBuffer + header_info.symtab_stroff+nlist->n_un.n_strx);
                if (symbolToMatchHash != 0)
                {
                    uint32_t currentSymbolHash = FNV1A_Hash_Jesteress(symbolString, strlen(symbolString));
                    if (currentSymbolHash == symbolToMatchHash)
                        printf("\nSymbol %s at address 0x%x has hash 0x%08x !\n", symbolString,nlist->n_value, hash_string(symbolString));
                }
                else
                {
                    fprintf(outputFile, "%s,%x\n", symbolString, hash_string(symbolString));
                }
            }
            nlist++;
        }
    }
    // close file handle
    if (g_options.symbol == NULL)
    {
        fclose(outputFile);
    }
}

