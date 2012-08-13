/*
 * hash_kernel_headers
 *
 * A util to hash the Mach-O headers of all kernel modules located at a given folder
 *
 * Copyright (c) fG!, 2012 - reverser@put.as - http://reverse.put.as
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * main.m
 *
 */

#define VERSION "0.1"

#import <Foundation/Foundation.h>
#include <CommonCrypto/CommonDigest.h>
#include <stdio.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <getopt.h>

static void header(void);
static void help(const char *exe);
static uint64_t read_target(uint8_t **targetBuffer, const char *target);
static int process_target(NSString *targetFullPath, NSString *targetKext);
static void process_macho_binary32(uint8_t *targetBuffer, const char *target_kext);
static void process_macho_binary64(uint8_t *targetBuffer, const char *target_kext);

// arch if target is a fat archive
uint32_t targetArch = CPU_TYPE_X86;

static void
header(void)
{
    // FIXME: we need the ascii!!!
    printf("v%s  \n", VERSION);
    printf("Hash kernel modules Mach-O headers\n");
    printf("(c) fG!, 2012 - reverser@put.as\n");   
}

static void 
help(const char *exe)
{
    header();
    printf("\n");
    printf("Usage Syntax:\n");
    printf("%s <path> [<options>]\n", exe);
    printf("where:\n");
    printf("<path>: path to the kernel module folder\n");
    printf("and options:\n");
    printf("-f: folder to search kernel modules from (example: /System/Library/Extensions)\n");
    printf("-a: target architecture\n");
    printf("    valid options are i386 or x86, x86_64 (default is i386)\n");
    printf("    if target doesn't have this arch it will be skipped\n");
}

/*
 * entry function to process a given target
 * supports fat and non-fat targets
 */
static int
process_target(NSString *targetFullPath, NSString *targetKext)
{
    @autoreleasepool 
    {
        int ret = 0;
        const char *target = NULL;
        // find the main executable by processing the Info.plist
        NSBundle *bundle = [NSBundle bundleWithPath:targetFullPath];
        if (bundle == nil)
        {
            fprintf(stderr, "[ERROR] No valid bundle found at %s\n", [targetFullPath UTF8String]);
            return 1;
        }
        NSDictionary *plistData = [bundle infoDictionary];
        NSString *targetExe = (NSString*)[plistData objectForKey:@"CFBundleExecutable"];
        
        if (targetExe != nil)
        {
            // the path to the binary to be analyzed
            NSString *tempTarget = [[targetFullPath stringByAppendingPathComponent:@"Contents/MacOS"]
                                    stringByAppendingPathComponent:targetExe];
            target = [tempTarget UTF8String];
            
            NSFileManager *fm = [NSFileManager new];
            if (![fm fileExistsAtPath:tempTarget])
            {
                fprintf(stderr, "[ERROR] Can't find the target exe at %s\n", target);
                [fm release];
                return 1;
            }
            [fm release];
        }
        else
        {
            fprintf(stderr, "[ERROR] Can't find the target exe at %s plist\n", [targetFullPath UTF8String]);
            return 1;
        }
        // read target file into a buffer
        uint64_t fileSize = 0;
        uint8_t *buf = NULL;
        fileSize = read_target(&buf, target);
        
        // verify if it's a valid mach-o target
        uint32_t magic = *(uint32_t*)(buf);
        if (magic == FAT_CIGAM)
        {
            uint32_t nrFatArch  = 0;
            uint8_t *address = buf;
            // retrieve the number of binaries inside the fat archive
            struct fat_header *fatheader_ptr = (struct fat_header *)address;
            nrFatArch = ntohl(fatheader_ptr->nfat_arch);
            // pointer to the first fat_arch structure
            struct fat_arch *fatArch = (struct fat_arch*)(address + sizeof(struct fat_header));
            // find the correct architecture
            for (uint32_t i = 0; i < nrFatArch; i++)
            {
                if (ntohl(fatArch->cputype) == targetArch)
                {
                    uint8_t *location = address + ntohl(fatArch->offset);
                    if (targetArch == CPU_TYPE_X86)
                        process_macho_binary32(location, [targetKext UTF8String]);
                    else if (targetArch == CPU_TYPE_X86_64)
                        process_macho_binary64(location, [targetKext UTF8String]);
                    break;
                }
                fatArch++;
            }
        }
        else if (magic == MH_MAGIC && targetArch == CPU_TYPE_X86)
        {
            process_macho_binary32(buf, [targetKext UTF8String]);
        }
        else if (magic == MH_MAGIC_64 && targetArch == CPU_TYPE_X86_64)
        {
            process_macho_binary64(buf, [targetKext UTF8String]);
        }
        else if (magic == MH_CIGAM || magic == MH_CIGAM_64)
        {
            fprintf(stderr, "[ERROR] Target arch not supported!\n");
            ret = 1;
        }
        else 
        {
            fprintf(stderr, "[ERROR] Target is not a valid mach-o binary or arch not present!\n");
            ret = 1;
        }
        
        free(buf);
        return ret;
    }

}

/*
 * read and SHA256 the 32bits mach-o header
 * we hash the mach_header plus all the commands
 */
static void
process_macho_binary32(uint8_t *targetBuffer, const char *target_kext)
{
    
    uint8_t *address = targetBuffer;
    uint32_t header_size = 0;
    // find the total header size to be hashed
    struct mach_header *mh = (struct mach_header*)address;
    header_size = sizeof(struct mach_header) + mh->sizeofcmds;
    // hash the header
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(address, header_size, digest);
    
    printf("%s,", target_kext);    
    for (uint32_t i = 0 ; i < CC_SHA256_DIGEST_LENGTH; i++)
    {
        printf("%02x", digest[i]);
    }
    printf(",%s\n", targetArch == CPU_TYPE_X86 ? "x86" : "x86_64");
}

/*
 * read and SHA256 the 64bits mach-o header
 */
static void
process_macho_binary64(uint8_t *targetBuffer, const char *target_kext)
{
    uint8_t *address = targetBuffer;
    uint32_t header_size = 0;
    struct mach_header_64 *mh64 = (struct mach_header_64*)address;
    header_size = sizeof(struct mach_header_64) + mh64->sizeofcmds;
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(address, header_size, digest);
    
    printf("%s,", target_kext);
    for (uint32_t i = 0 ; i < CC_SHA256_DIGEST_LENGTH; i++)
    {
        printf("%02x", digest[i]);
    }
    printf(",%s\n", targetArch == CPU_TYPE_X86 ? "x86" : "x86_64");
}


/*
 * read the target file into a buffer
 */
static uint64_t 
read_target(uint8_t **targetBuffer, const char *target)
{
    FILE *in_file = NULL;
	
    in_file = fopen(target, "r");
    if (!in_file)
    {
		fprintf(stderr, "[ERROR] Could not open target file %s!\n", target);
        exit(1);
    }
    if (fseek(in_file, 0, SEEK_END))
    {
		fprintf(stderr, "[ERROR] Fseek failed at %s\n", target);
        exit(1);
    }
    
    long fileSize = ftell(in_file);
    
    if (fseek(in_file, 0, SEEK_SET))
    {
		fprintf(stderr, "[ERROR] Fseek failed at %s\n", target);
        exit(1);
    }
    
    *targetBuffer = malloc(fileSize * sizeof(uint8_t));
    
    if (*targetBuffer == NULL)
    {
        fprintf(stderr, "[ERROR] Malloc failed!\n");
        exit(1);
    }
    
    fread(*targetBuffer, fileSize, 1, in_file);
	if (ferror(in_file))
	{
		fprintf(stderr, "[ERROR] fread failed at %s\n", target);
        free(*targetBuffer);
		exit(1);
	}
    fclose(in_file);  
    return(fileSize);
}

/*
 * where everything starts!
 */
int main (int argc, char * argv[])
{
    @autoreleasepool 
    {
        // required structure for long options
        static struct option long_options[]={
            { "folder", no_argument, NULL, 'f' },
            { "arch",   required_argument, NULL, 'a' },
            { "help",   no_argument, NULL, 'h' },
            { NULL, 0, NULL, 0 }
        };
        int option_index = 0;
        int c = 0;
        
        char *my_program_name = argv[0];
        char *search_path = NULL;
        uint8_t lookupKexts = 0;
        
        // process command line options
        while ((c = getopt_long(argc, argv, "fa:h", long_options, &option_index)) != -1)
        {
            switch (c)
            {
                case ':':
                case '?':
                case 'h':
                    help(my_program_name);
                    exit(1);
                    break;
                case 'a':
                {
                    if (strcmp(optarg, "i386") == 0 || strcmp(optarg, "x86") == 0)
                        targetArch = CPU_TYPE_X86;
                    else if (strcmp(optarg, "x86_64") == 0)
                        targetArch = CPU_TYPE_X86_64;
                    else
                    {
                        help(my_program_name);
                        exit(1);
                    }
                    break;
                }
                case 'f':
                    lookupKexts = 1;
                    break;
                default:
                    help(my_program_name);
                    exit(1);
            }
        }
        
        // switches are set but there's no target configured
        if ((argv+optind)[0] == NULL)
        {
            fprintf(stderr, "***************************************\n");
            fprintf(stderr, "[ERROR] Target kext or folder required!\n");
            fprintf(stderr, "***************************************\n");
            help(my_program_name);
            exit(1);
        }
        // set the target folder to process
        // either lookup if -f option was set else a single kext target
        search_path = (argv+optind)[0];
        
        // test if folder exists
        struct stat fstatus;
        if (stat(search_path, &fstatus))
        {
            fprintf(stderr, "[ERROR] Target folder %s does not exist or no access allowed!\n", search_path);
            exit(1);
        }
        
        if (lookupKexts)
        {
            // find target kexts
            NSFileManager *fm = [NSFileManager new];
            NSString *searchPath = [NSString stringWithCString:search_path encoding:NSUTF8StringEncoding];
            NSArray *kextMainList = [fm contentsOfDirectoryAtPath:searchPath error:NULL];
            
            // process each kernel extension
            // we need to be careful with PlugIns, which are additional kexts
            for (NSString *targetKext in kextMainList)
            {
                // build full path to the kext to be processed
                NSString *targetFullPath = [searchPath stringByAppendingPathComponent:targetKext];
                
#if DEBUG
                printf("[DEBUG] Processing %s...\n", [targetKext UTF8String]);
#endif
                process_target(targetFullPath, targetKext);
            }
        }
        else if (!lookupKexts)
        {
            NSString *targetFullPath =  [NSString stringWithCString:search_path encoding:NSUTF8StringEncoding];
            NSString *targetKext = [targetFullPath lastPathComponent];
            process_target(targetFullPath, targetKext);
        }
    }
    return 0;
}

