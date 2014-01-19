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
 * mach_o.c
 *
 */

#include "mach_o.h"

#include <stdlib.h>
#include <stdio.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <string.h>

#include "structures.h"

struct header_info 
process_macho_header(uint8_t **targetBuffer)
{
    struct header_info temp_headerinfo = {0};
    uint8_t *address    = *targetBuffer;    
    uint32_t nrLoadCmds = 0;
    uint32_t indexCounter = 1; // ignore PAGEZERO

    int32_t magic = *(uint32_t*)address;
    if (magic == MH_MAGIC)
    {
        struct mach_header *mach_header = (struct mach_header*)(address);
        nrLoadCmds = mach_header->ncmds;
        switch (mach_header->cputype) 
        {
            case CPU_TYPE_X86:
                temp_headerinfo.cpuString = "i386";
                break;
            case CPU_TYPE_ARM:
                if (mach_header->cpusubtype == CPU_SUBTYPE_ARM_V6)
                    temp_headerinfo.cpuString = "armv6";
                else if (mach_header->cpusubtype == CPU_SUBTYPE_ARM_V7)
                    temp_headerinfo.cpuString = "armv7";
                break;
            default:
                break;
        }            
        // first load cmd address
        address = address + sizeof(struct mach_header);
    }
    else if (magic == MH_MAGIC_64)
    {
        struct mach_header_64 *mach_header64 = (struct mach_header_64*)(address);
        nrLoadCmds = mach_header64->ncmds;
        temp_headerinfo.is64Bits = 1;

        if (mach_header64->cputype == CPU_TYPE_X86_64)
            temp_headerinfo.cpuString = "x86_64";

        // first load cmd address
        address = address + sizeof(struct mach_header_64);
    }

    struct load_command *loadCommand = NULL;
    
    for (uint32_t i = 0; i < nrLoadCmds; i++)
    {
        loadCommand = (struct load_command*)address;
        if (loadCommand->cmd == LC_SEGMENT)
        {
            struct segment_command *segmentCommand = (struct segment_command*)address;
            // we want to find __LINKEDIT
            if (strncmp(segmentCommand->segname, "__LINKEDIT", 16) == 0)
            {
                temp_headerinfo.linkedit_vmaddr  = segmentCommand->vmaddr;
                temp_headerinfo.linkedit_fileoff = segmentCommand->fileoff;
            }
            // search for __TEXT so we can get its index
            // usually it's 1 but let's do it right :-)
            if (strncmp(segmentCommand->segname, "__TEXT", 16) == 0)
            {
                temp_headerinfo.textSegmentIndex = indexCounter;
            }
        }
        else if (loadCommand->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 *segmentCommand64 = (struct segment_command_64*)address;
            if (strncmp(segmentCommand64->segname, "__LINKEDIT", 16) == 0)
            {
                temp_headerinfo.linkedit_vmaddr  = segmentCommand64->vmaddr;
                temp_headerinfo.linkedit_fileoff = segmentCommand64->fileoff;
            }
        }
        else if (loadCommand->cmd == LC_SYMTAB)
        {
            struct symtab_command *symtabCommand = (struct symtab_command*)address;
            if (symtabCommand->cmd == LC_SYMTAB)
            {
                temp_headerinfo.symtab_symoff  = symtabCommand->symoff;
                temp_headerinfo.symtab_nsyms   = symtabCommand->nsyms;
                temp_headerinfo.symtab_stroff  = symtabCommand->stroff;
                temp_headerinfo.symtab_strsize = symtabCommand->strsize;
            }
        }
        else if (loadCommand->cmd == LC_DYSYMTAB)
        {
            struct dysymtab_command *dysymtabCommand = (struct dysymtab_command*)address;
            // just some "safety" check
            if (dysymtabCommand->cmd == LC_DYSYMTAB)
            {
                temp_headerinfo.dysymtab_iextdefsym = dysymtabCommand->iextdefsym;
                temp_headerinfo.dysymtab_nextdefsym = dysymtabCommand->nextdefsym;
                temp_headerinfo.dysymtab_iundefsym  = dysymtabCommand->iundefsym;
                temp_headerinfo.dysymtab_nundefsym  = dysymtabCommand->nundefsym;
            }
        }
        address += loadCommand->cmdsize;
        indexCounter++;
    }
    return temp_headerinfo;
}

