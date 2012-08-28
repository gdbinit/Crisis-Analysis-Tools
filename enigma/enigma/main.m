/*
 *    ('-.       .-') _                    _   .-')      ('-.     
 *  _(  OO)     ( OO ) )                  ( '.( OO )_   ( OO ).-. 
 * (,------.,--./ ,--,' ,-.-')   ,----.    ,--.   ,--.) / . --. / 
 *  |  .---'|   \ |  |\ |  |OO) '  .-./-') |   `.'   |  | \-.  \  
 *  |  |    |    \|  | )|  |  \ |  |_( O- )|         |.-'-'  |  | 
 * (|  '--. |  .     |/ |  |(_/ |  | .--, \|  |'.'|  | \| |_.'  | 
 *  |  .--' |  |\    | ,|  |_.'(|  | '. (_/|  |   |  |  |  .-.  | 
 *  |  `---.|  | \   |(_|  |    |  '--'  | |  |   |  |  |  | |  | 
 *  `------'`--'  `--'  `--'     `------'  `--'   `--'  `--' `--' 
 *
 * Crisis configuration, data log files decryptor and cryptor
 *
 * (c) fG!, 2012 - reverser@put.as - http://reverse.put.as
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
 */

#import <Foundation/Foundation.h>
#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonDigest.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define OP_DECRYPT   1
#define OP_ENCRYPT   0

#define T_CONFIG 0
#define T_LOG    1

#define RECORD_SIZE_FIELD_LENGTH     4

#define LOG_EXTENSION ".gai"

#define VERSION "0.3"

char keyConfig[kCCKeySizeAES128+1] = "\xA6\xF7\xF3\x41\x23\xA6\xA1\xAB\x12\xFA\xE0\xAA\x61\xD0\x2C\x2D";
char keyLog[kCCKeySizeAES128+1]    = "\x1D\xD2\x06\xAD\x67\xC8\x52\xE8\x80\x72\xA4\x98\x41\x87\x63\x7F";

size_t crypt_operation(CCOperation op, void *inData, size_t inDataSize, void *outData, size_t outDataSize, char *key, CCOptions options);

static void
help(const char *exe)
{
    printf("\n");
    printf("Usage Syntax:\n");
    printf("%s target <options>\n\n", exe);
    printf("where:\n");
    printf("target - target binary to encrypt or decrypt\n");
    printf("and options:\n");
    printf("-c: encrypt\n");
    printf("-d: decrypt\n");
    printf("-t <type>: target type, 0-config, 1-log\n");
}

static void
header(void)
{
    printf(" _____     _               \n");
    printf("|   __|___|_|___ _____ ___ \n");
    printf("|   __|   | | . |     | .'|\n");
    printf("|_____|_|_|_|_  |_|_|_|__,|\n");
    printf("            |___|          \n");
    printf("                       v%s\n", VERSION);
    printf("              (c) fG!, 2012\n\n");
}

int main (int argc, char * argv[])
{

    @autoreleasepool
    {
        header();
        
        // required structure for long options
        static struct option long_options[]={
            { "encrypt", no_argument, NULL, 'e' },
            { "decrypt", no_argument, NULL, 'd' },
            { "type", required_argument, NULL, 't' },
            { "help",   no_argument, NULL, 'h' },
            { NULL, 0, NULL, 0 }
        };
        int option_index = 0;
        int c = 0;
        const char *myProgramName = argv[0];
        int operation = OP_DECRYPT;
        long type = 0;
        // process command line options
        while ((c = getopt_long(argc, argv, "edt:h", long_options, &option_index)) != -1)
        {
            switch (c)
            {
                case ':':
                case '?':
                case 'h':
                    help(myProgramName);
                    exit(0);
                    break;
                case 'e':
                {
                    operation = OP_ENCRYPT;
                    break;
                }
                case 'd':
                    operation = OP_DECRYPT;
                    break;
                case 't':
                    type = strtol(optarg, NULL, 0);
                    break;
                default:
                    help(myProgramName);
                    exit(0);
            }
        }
        
        // switches are set but there's no target configured
        if ((argv+optind)[0] == NULL)
        {
            fprintf(stderr, "*****************************\n");
            fprintf(stderr, "[ERROR] Target file required!\n");
            fprintf(stderr, "*****************************\n");
            help(myProgramName);
            exit(1);
        }
        
        NSString *targetFileName = [NSString stringWithCString:(argv+optind)[0] 
                                                      encoding:NSUTF8StringEncoding];
        
        NSFileManager *fm    = [NSFileManager defaultManager];
        NSData *inNSData     = [fm contentsAtPath:targetFileName];
        size_t inDataSize    = [inNSData length];    // size of data to be decrypted/encrypted
        void *inData         = NULL;                 // buffer to hold the input data
        void *outData        = NULL;                 // buffer that will hold the decrypted/encrypted data
        size_t outDataSize   = 0;                    // size of this buffer
        size_t processedSize = 0;                    // the total bytes process by CCCrypt()
        
        // allocate enough memory for the buffers and copy from the NSData object
        if (type == T_CONFIG && operation == OP_ENCRYPT)
        {
            inData = calloc(1, inDataSize+CC_SHA1_DIGEST_LENGTH); // we will need to append the SHA1 before encryption
            memcpy(inData, [inNSData bytes], inDataSize);
        }
        else
        {
            inData = calloc(1, inDataSize);
            memcpy(inData, [inNSData bytes], inDataSize);
        }
        
        
        // set the right encryption key based on target type
        char *key = NULL;
        
        switch (type) 
        {
            case T_CONFIG:
                key = keyConfig;
                break;
            case T_LOG:
                key = keyLog;
                break;
            default:
                break;
        }

        // DECRYPT CONFIG FILE
        if (type == T_CONFIG && operation == OP_DECRYPT)
        {
            // output buffer for CCCrypt()
            outDataSize = inDataSize + kCCBlockSizeAES128; // out data size, add the block size
            outData = calloc(1, outDataSize);
            // decrypt data, function will exit if there's any failure
            processedSize = crypt_operation(kCCDecrypt, inData, inDataSize, outData, outDataSize, key, kCCOptionPKCS7Padding);
            
            // verify if original SHA1 hash is ok
            // last 20 bytes of the decrypted file are the SHA1 hash
            NSUInteger noHashDataSize = processedSize-CC_SHA1_DIGEST_LENGTH;
            unsigned char hashBuffer[CC_SHA1_DIGEST_LENGTH+1];
            
            NSData *originalHash = [NSData dataWithBytes:outData+noHashDataSize length:CC_SHA1_DIGEST_LENGTH];
            // hash the decrypted data minus the SHA1 hash
            CC_SHA1(outData, (CC_LONG)noHashDataSize, hashBuffer);
#if DEBUG
            for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++)
            {
                printf("%02hhx", hashBuffer[i]);
            }
            printf("\n");
#endif
            // verify if original hash and our computed hash match
            if (memcmp([originalHash bytes], hashBuffer, CC_SHA1_DIGEST_LENGTH))
            {
                printf("[ERROR] Hashes do not match!\n");
                exit(1);
            }
            printf("Successfully decrypted %ld bytes!\n", processedSize);
            
            // everything is ok, so write that file!
            // last 20 bytes of the decrypted file are the SHA1 hash so we don't write them
            [fm createFileAtPath:[NSString stringWithFormat:@"%@.decrypted",targetFileName] 
                        contents:[NSData dataWithBytesNoCopy:outData length:noHashDataSize]
                      attributes:nil];

        }
        // ENCRYPT CONFIG FILE
        else if (type == T_CONFIG && operation == OP_ENCRYPT)
        {
            // we will need to add the SHA1 hash so we increase size of input data
            NSUInteger inDataPlusHashSize = inDataSize+CC_SHA1_DIGEST_LENGTH;
            // output buffer for CCCrypt()
            outDataSize = inDataPlusHashSize + kCCBlockSizeAES128;
            outData = calloc(1, outDataSize);
            
            // we need to hash the original unencrypted data
            unsigned char hashBuffer[CC_SHA1_DIGEST_LENGTH+1];
            CC_SHA1(inData, (CC_LONG)inDataSize, hashBuffer);
#if DEBUG
            for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++)
            {
                printf("%02hhx", hashBuffer[i]);
            }
            printf("\n");
#endif
            // add the SHA1 hash to the input buffer, enough size was already allocated at the beginning
            memcpy(inData+inDataSize, hashBuffer, CC_SHA1_DIGEST_LENGTH);
            // crypt data
            processedSize = crypt_operation(kCCEncrypt, inData, inDataPlusHashSize, outData, outDataSize, key, kCCOptionPKCS7Padding);
            
            printf("Successfully encrypted %ld bytes!\n", processedSize);
            
            [fm createFileAtPath:[NSString stringWithFormat:@"%@.encrypted",targetFileName] 
                        contents:[NSData dataWithBytesNoCopy:outData length:processedSize]
                      attributes:nil];
        }
        // WE JUST WANT TO DECRYPT LOG FILES
        else if (type == T_LOG)
        {
            // log files are composed by a header plus data
            // the record format is int(size)+data
            
            // create a folder for each log file where we will dump the decrypted data
            NSString *folderName = [targetFileName substringWithRange:(NSRange){0, [targetFileName length]-strlen(LOG_EXTENSION)}];
            
            if ([fm fileExistsAtPath:folderName] == NO)
            {
                [fm createDirectoryAtPath:folderName 
              withIntermediateDirectories:NO
                               attributes:nil
                                    error:NULL];
            }
            // start reading the buffer and decrypting it
            size_t count = 0;
            uint32_t recordSize = 0;
            uint32_t index = 0;

            printf("Decrypting and extracting contents of %s\n", [targetFileName UTF8String]);

            for (count = 0; count < inDataSize ; count += recordSize + RECORD_SIZE_FIELD_LENGTH)
            {
                printf("Processing record #%d\n", index);
                // first field is the record size
                recordSize = *(uint32_t*)inData;
                // verify if recordSize is sane versus the remaining available data
                if (recordSize > (inDataSize-count-RECORD_SIZE_FIELD_LENGTH))
                {
                    fprintf(stderr, "[ERROR] Record size bigger than file size! Something is wrong :-)\n");
                    exit(1);
                }
                // must be a multiple of kCCBlockSizeAES128
                // if remainder == 0 we pass no padding option to CCCrypt()
                // NOTE:
                // there's maybe a bug in here because in the header correct, the size seems to be always padded
                // while at data records the size is incorrect if there's padding (we must manually add it)
                uint16_t remainder = recordSize % kCCBlockSizeAES128;
                if (remainder != 0)
                    recordSize += (kCCBlockSizeAES128 - remainder);

                // output buffer for CCCrypt()
                outDataSize = recordSize + kCCBlockSizeAES128; // out data size, add the block size
                outData = NULL;
                outData = calloc(1, outDataSize);
                if (outData == NULL)
                {
                    fprintf(stderr, "[ERROR] Alloc of outData failed!\n");
                    exit(1);
                }
                
                // advance buffer to start of crypted data
                inData += RECORD_SIZE_FIELD_LENGTH;
                
                processedSize = crypt_operation(kCCDecrypt, 
                                                (void*)inData, 
                                                recordSize,
                                                outData,
                                                outDataSize,
                                                key, 
                                                remainder == 0 ? 0 : kCCOptionPKCS7Padding);

                // quick detection of jpeg files
                char *extension = calloc(1, 15);
                if (*(uint16_t*)(outData+2) == 0xE0FF && *(uint32_t*)(outData+6) == 0x4649464A)
                    strcpy(extension, "jpeg");
                else
                    strcpy(extension, "decrypted");
                
                // dump the decrypted file into the folder
                [fm createFileAtPath:[NSString stringWithFormat:@"%@/%d-%d.%s", folderName, index++,recordSize, extension] 
                            contents:[NSData dataWithBytesNoCopy:outData length:processedSize]
                          attributes:nil];
                
                printf("Successfully decrypted %ld bytes!\n", processedSize);
                
                // advance to next record
                inData += recordSize;
            }
        }
    }
    return 0;
}

/*
 * just a wrapper function for CCCrypt() that will encrypt or decrypt data
 * and return the number of processed bytes
 * it will exit application if CCCrypt() fails
 */
size_t
crypt_operation(CCOperation op, 
                void *inData, 
                size_t inDataSize, 
                void *outData, 
                size_t outDataSize,
                char *key,
                CCOptions options)
{
    size_t processedSize = 0;

    CCCryptorStatus ret = CCCrypt(op,                     // op
                                  kCCAlgorithmAES128,     // alg
                                  options,                // options
                                  key,                    // key
                                  kCCKeySizeAES128,       // keyLength
                                  NULL,                   // iv
                                  inData,                 // dataIn
                                  inDataSize,             // dataInLength
                                  outData,                // dataOut
                                  outDataSize,            // dataOutAvailable
                                  &processedSize);        // dataOutMoved

    if (ret != kCCSuccess || processedSize == 0)
    {
        fprintf(stderr, "[ERROR] Failed to decrypt! Wrong key or type? [Ret code:%d]\n", ret);
        exit(1);
    }
    return processedSize;
}


