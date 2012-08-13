/*
 * hash_kernel_headers
 *
 * A util to hash the Mach-O headers of all kernel modules located at a given folder
 *
 * (c) fG!, 2012 - reverser@put.as - http://reverse.put.as
 * All rights reserved.
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

static void header(void);
static void help(const char *exe);
static uint64_t read_target(uint8_t **targetBuffer, const char *target);
static int process_target(NSString *searchPath, NSString *targetKext);
static void process_macho_binary32(uint8_t *targetBuffer);
static void process_macho_binary64(uint8_t *targetBuffer);


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
    printf("%s <path>\n", exe);
    printf("where:\n");
    printf("<path>: path to the kernel modules folder\n");
}

/*
 * entry function to process a given target
 * supports fat and non-fat targets
 */
static int
process_target(NSString *searchPath, NSString *targetKext)
{
    @autoreleasepool 
    {
        int ret = 0;
        const char *target = NULL;
        // build full path to the kext to be processed
        NSString *targetFolder = [searchPath stringByAppendingPathComponent:targetKext];
        // find the main executable by processing the Info.plist
        NSBundle *bundle = [NSBundle bundleWithPath:targetFolder];
        if (bundle == nil)
        {
            printf("No valid bundle found at %s\n", [targetFolder UTF8String]);
            return 1;
        }
        NSDictionary *plistData = [bundle infoDictionary];
        NSString *targetExe = (NSString*)[plistData objectForKey:@"CFBundleExecutable"];
        
        if (targetExe != nil)
        {
            // the path to the binary to be analyzed
            NSString *tempTarget = [[targetFolder stringByAppendingPathComponent:@"Contents/MacOS"]
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
            fprintf(stderr, "[ERROR] Can't find the target exe at %s plist\n", [targetFolder UTF8String]);
            return 1;
        }
        // read target file into a buffer
        uint64_t fileSize = 0;
        uint8_t *buf = NULL;
        fileSize = read_target(&buf, target);
        
        // FIXME
        int arch = CPU_TYPE_X86_64;
        
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
                if (ntohl(fatArch->cputype) == arch)
                {
                    uint8_t *location = address + ntohl(fatArch->offset);
                    process_macho_binary32(location);
                    break;
                }
                fatArch++;
            }
        }
        else if (magic == MH_MAGIC)
        {
            process_macho_binary32(buf);
        }
        else if (magic == MH_MAGIC_64)
        {
            process_macho_binary64(buf);
        }
        else 
        {
            printf("[ERROR] Target is not a valid mach-o binary or arch not supported!\n");
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
process_macho_binary32(uint8_t *targetBuffer)
{
    
    uint8_t *address = targetBuffer;
    uint32_t header_size = 0;
    // find the total header size to be hashed
    struct mach_header *mh = (struct mach_header*)address;
    header_size = sizeof(struct mach_header) + mh->sizeofcmds;
    // hash the header
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(address, header_size, digest);
    
    for (uint32_t i = 0 ; i < CC_SHA256_DIGEST_LENGTH; i++)
    {
        printf("%02x", digest[i]);
    }
    printf("\n");
}

/*
 * read and SHA256 the 64bits mach-o header
 */
static void
process_macho_binary64(uint8_t *targetBuffer)
{
    uint8_t *address = targetBuffer;
    uint32_t header_size = 0;
    struct mach_header_64 *mh64 = (struct mach_header_64*)address;
    header_size = sizeof(struct mach_header_64) + mh64->sizeofcmds;
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(address, header_size, digest);
    for (uint32_t i = 0 ; i < CC_SHA256_DIGEST_LENGTH; i++)
    {
        printf("%02x", digest[i]);
    }
    printf("\n");
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
int main (int argc, const char * argv[])
{
    @autoreleasepool 
    {
        if (argc <= 1)
        {
            header();
            printf("[ERROR] Missing path to kernel modules folder!\n");
            exit(1);
        }
        
        char *my_program_name = (char*)argv[0];
        char *search_path = (char*)argv[1];
        
        // test if folder exists
        struct stat fstatus;
        int folder_status = stat(search_path, &fstatus);
        if (folder_status)
        {
            printf("[ERROR] Target folder %s does not exist or no access allowed! %d\n", search_path, errno);
            exit(1);
        }
        
        // find target kexts
        NSFileManager *fm = [NSFileManager new];
        NSString *searchPath = [NSString stringWithCString:search_path encoding:NSUTF8StringEncoding];
        NSArray *kextMainList = [fm contentsOfDirectoryAtPath:searchPath error:NULL];
        
        // process each kernel extension
        // we need to be careful with PlugIns, which are additional kexts
        for (NSString *targetKext in kextMainList)
        {
#if DEBUG
            printf("Processing %s...\n", [targetKext UTF8String]);
#endif
            process_target(searchPath, targetKext);
        }        
    }
    return 0;
}

