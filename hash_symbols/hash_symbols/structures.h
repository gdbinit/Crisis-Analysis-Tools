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
 * structures.h
 *
 */

#ifndef hash_symbols_structures_h
#define hash_symbols_structures_h

#include <stdint.h>
#include <mach-o/loader.h>

struct header_info
{
    uint8_t  is64Bits;
    uint32_t textSegmentIndex;
    char     *cpuString;
    uint64_t linkedit_vmaddr;
    uint64_t linkedit_fileoff;
    uint32_t symtab_symoff;
    uint32_t symtab_nsyms;
    uint32_t symtab_stroff;
    uint32_t symtab_strsize;
    uint32_t dysymtab_iextdefsym;
    uint32_t dysymtab_nextdefsym;
    uint32_t dysymtab_iundefsym;
    uint32_t dysymtab_nundefsym;
};

enum archs
{
    X86 = CPU_TYPE_I386,
    X86_64 = CPU_TYPE_X86_64,
    PPC = CPU_TYPE_POWERPC,
    PPC64 = CPU_TYPE_POWERPC64,
    ARMV6 = CPU_SUBTYPE_ARM_V6,
    ARMV7 = CPU_SUBTYPE_ARM_V7
};

struct options
{
    enum archs arch;
    char    *outputFolder;
    char    *symbol;
    char    *targetName;
};

typedef struct options options_t;


#endif
