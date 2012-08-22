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
 * Crisis configuration, log files and stolen data decryptor and cryptor
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
#define T_DATA   2

#define VERSION "0.2"

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
    printf("-t <type>: target type, 0-config, 1-log, 2-data\n");
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

    @autoreleasepool {
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
        
        NSFileManager *fm = [NSFileManager defaultManager];
        NSData *inData    = [fm contentsAtPath:targetFileName];
        
        // the encryption keys
        char *key = NULL;
        char keyConfig[kCCKeySizeAES128+1] = "\xA6\xF7\xF3\x41\x23\xA6\xA1\xAB\x12\xFA\xE0\xAA\x61\xD0\x2C\x2D";
        char keyLog[kCCKeySizeAES128+1]    = "\x1D\xD2\x06\xAD\x67\xC8\x52\xE8\x80\x72\xA4\x98\x41\x87\x63\x7F";
        
        switch (type) 
        {
            case T_CONFIG:
                key = keyConfig;
                break;
            case T_LOG:
                key = keyLog;
                break;
            case T_DATA:
                break;
            default:
                break;
        }

        void *outData         = NULL; // buffer that will hold the decrypted/encrypted data
        size_t outDataSize    = 0;    // size of this buffer
        size_t processedSize  = 0;    // the total bytes process by CCCrypt()
        NSUInteger inDataSize = 0;    // size of data to be decrypted/encrypted

        // DECRYPT IT !!!!!
        if (operation == OP_DECRYPT)
        {
            inDataSize = [inData length];
            // output buffer for CCCrypt()
            outDataSize = inDataSize + kCCBlockSizeAES128;
            outData = calloc(1, outDataSize);
            
            CCCryptorStatus ret = CCCrypt(kCCDecrypt,             // op
                                          kCCAlgorithmAES128,     // alg
                                          kCCOptionPKCS7Padding,  // options
                                          key,                    // key
                                          kCCKeySizeAES128,       // keyLength
                                          NULL,                   // iv
                                          [inData bytes],         // dataIn
                                          inDataSize,             // dataInLength
                                          outData,                // dataOut
                                          outDataSize,            // dataOutAvailable
                                          &processedSize);        // dataOutMoved
            
            if (processedSize > 0 && ret == kCCSuccess)
            {
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
            else
            {
                printf("Failed to decrypt! Wrong key or type?\n");
                return 1;
            }
        }
        // ENCRYPT IT !!!!!
        else if (operation == OP_ENCRYPT)
        {
            // we will need to add the SHA1 hash so we increase size of input data
            inDataSize = [inData length];
            NSUInteger inDataPlusHashSize = [inData length]+CC_SHA1_DIGEST_LENGTH;
            // output buffer for CCCrypt()
            outDataSize = inDataPlusHashSize + kCCBlockSizeAES128;
            outData = calloc(1, outDataSize);

            // we need to hash the original unencrypted data
            unsigned char hashBuffer[CC_SHA1_DIGEST_LENGTH+1];
            CC_SHA1([inData bytes], (CC_LONG)inDataSize, hashBuffer);
#if DEBUG
            for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++)
            {
                printf("%02hhx", hashBuffer[i]);
            }
            printf("\n");
#endif

            // now we need to join the buffers
            unsigned char *bufferToEncrypt = malloc(inDataPlusHashSize);
            memcpy(bufferToEncrypt, [inData bytes], inDataSize);
            memcpy(bufferToEncrypt+inDataSize, hashBuffer, CC_SHA1_DIGEST_LENGTH);
            
            CCCryptorStatus ret = CCCrypt(kCCEncrypt,             // op
                                          kCCAlgorithmAES128,     // alg
                                          kCCOptionPKCS7Padding,  // options
                                          key,                    // key
                                          kCCKeySizeAES128,       // keyLength
                                          NULL,                   // iv
                                          bufferToEncrypt,        // dataIn
                                          inDataPlusHashSize,     // dataInLength
                                          outData,                // dataOut
                                          outDataSize,            // dataOutAvailable
                                          &processedSize);        // dataOutMoved

            if (processedSize > 0 && ret == kCCSuccess)
            {
                printf("Successfully encrypted %ld bytes!\n", processedSize);
                
                [fm createFileAtPath:[NSString stringWithFormat:@"%@.encrypted",targetFileName] 
                            contents:[NSData dataWithBytesNoCopy:outData length:processedSize]
                          attributes:nil];
            }
            else
            {
                printf("Failed to encrypt!\n");
            }
        }
    }
    return 0;
}

