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
 * v0.1
 *
 * (c) 2012, fG! - reverser@put.as - http://reverse.put.as
 *
 * A command line util to hash external symbols from a given Mach-O binary or library
 *
 * You can modify the hash algorithm to whatever you want, if required.
 * Default algorithm is the one used in OS.X/Crisis malware.
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
 * main.c
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <getopt.h>
#include <string.h>

#include "file_operations.h"
#include "process.h"
#include "structures.h"

#define VERSION "0.1"

static void help(const char *exe);
static void init_options(options_t *options);

options_t options;

static void
help(const char *exe)
{
    printf("\n");
    printf("Usage Syntax:\n");
    printf("%s target [<options>]\n\n", exe);
    printf("where:\n");
    printf("target - target binary read symbols from\n");
    printf("and options:\n");
    printf("-a: specific target architecture to hash symbols from if target is a fat archive\n");
    printf("    valid options are i386, x86_64, armv6, armv7\n");
    printf("-s: specific symbol name to hash\n");
    printf("-o: output folder, default is current path\n");
}

static void 
init_options(options_t *options)
{
    options->arch = 0;
    options->outputFolder = NULL;
    options->symbol = NULL;
}

int main (int argc, char *argv[])
{
    printf(" _____         _      _____           _       _     \n");
    printf("|  |  |___ ___| |_   |   __|_ _ _____| |_ ___| |___ \n");
    printf("|     | .'|_ -|   |  |__   | | |     | . | . | |_ -|\n");
    printf("|__|__|__,|___|_|_|  |_____|_  |_|_|_|___|___|_|___|\n");
    printf("                           |___|                    \n");
    printf(".------------------------------------------------.\n");
    printf("|             Hash Symbols - v%s                |\n", VERSION);
    printf("|        (c) fG!, 2012 - reverser@put.as         |\n");
    printf("`------------------------------------------------´\n");

    // required structure for long options
	static struct option long_options[]={
        { "arch",   no_argument, NULL, 'a' },
        { "symbol", no_argument, NULL, 's' },
        { "output", no_argument, NULL, 'o' },
        { "help",   no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};
	int option_index = 0;
    int c = 0;
    
    init_options(&options);
    const char *myProgramName = argv[0];

    // process command line options
	while ((c = getopt_long(argc, argv, "a:s:o:h", long_options, &option_index)) != -1)
	{
		switch (c)
		{
			case ':':
			case '?':
            case 'h':
				help(myProgramName);
				exit(1);
				break;
            case 'a':
            {
                if (strcmp(optarg, "i386") == 0)
                    options.arch = X86;
                else if (strcmp(optarg, "x86_64") == 0)
                    options.arch = X86_64;
                else if (strcmp(optarg, "armv6") == 0)
                    options.arch = ARMV6;
                else if (strcmp(optarg, "armv7") == 0)
                    options.arch = ARMV7;
                else
                {
                    help(myProgramName);
                    exit(1);
                }
                break;
            }
            case 's':
                options.symbol = optarg;
                break;
            case 'o':
                options.outputFolder = optarg;
                break;
			default:
				help(myProgramName);
				exit(1);
		}
	}
    
    // switches are set but there's no target configured
    if ((argv+optind)[0] == NULL)
    {
        fprintf(stderr, "*******************************\n");
        fprintf(stderr, "[ERROR] Target binary required!\n");
        fprintf(stderr, "*******************************\n");
        help(myProgramName);
        exit(1);
    }
    
    // FIXME: test if output folder exists
    
    // read the target into our buffer
    uint8_t *targetBuffer   = NULL;
    uint32_t fileSize       = 0;
    fileSize = read_target(&targetBuffer, (argv+optind)[0]);
    options.targetName = (argv+optind)[0];
    
    // verify if it's a valid mach-o target
    uint8_t isFat = 0;
    uint32_t magic = *(uint32_t*)(targetBuffer);
    
    if (magic == FAT_CIGAM)
        isFat = 1;
    else if (magic == MH_MAGIC || magic == MH_MAGIC_64)
        isFat = 0;
    else if (magic == MH_CIGAM || magic == MH_CIGAM_64)
    {
        printf("[ERROR] Target is not supported!\n");
        exit(1);
    }
    else
    {
		printf("[ERROR] Target is not a valid Mach-O binary!\n");
        exit(1);
    }
    
    // if it's a fat binary we will extract the symbols from all available archs if user
    // hasn't selected a specific arch
    if (isFat)
    {
        process_fat_binary(&targetBuffer);
    }
    // else our work is so much simpler!
    else
    {
        process_nonfat_binary(&targetBuffer);
    }
    
    free(targetBuffer);
    return 0;
}

