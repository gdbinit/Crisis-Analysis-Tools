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
 * hashing.c
 *
 */

#include "hashing.h"
#include <stdio.h>
#include <string.h>

/*
 * the hashing algorithm, modify it to suit your needs
 * default is the one used by OS.X/Crisis malware
 */
int32_t
hash_string(char *string_to_hash)
{
    int32_t x = (uint32_t)strlen(string_to_hash);
	int32_t hash_value = 0;
    
	for (uint32_t i = 0; i < x; i++) 
    {
	    int32_t t1 = 0;
	    int t2 = 0;
	    uint8_t current_char = string_to_hash[i];
	    t1 = hash_value << 0x6;
	    t1 += current_char;
	    t2 = hash_value << 0x10;
	    t1 += t2;
	    t1 -= hash_value;
	    hash_value = t1;
	}
    return hash_value;
}

#define ROL(x, n) (((x) << (n)) | ((x) >> (32-(n))))
// http://encode.ru/threads/1160-Fastest-non-secure-hash-function

uint32_t 
FNV1A_Hash_Jesteress(const char *str, size_t wrdlen)
{
    const uint32_t PRIME = 709607;
    uint32_t hash32 = 2166136261;
    const char *p = str;
    
    // Idea comes from Igor Pavlov's 7zCRC, thanks.
    /*
     for(; wrdlen && ((unsigned)(ptrdiff_t)p&3); wrdlen -= 1, p++) {
     hash32 = (hash32 ^ *p) * PRIME;
     }
     */
    for(; wrdlen >= 2*sizeof(uint32_t); wrdlen -= 2*sizeof(uint32_t), p += 2*sizeof(uint32_t)) {
        hash32 = (hash32 ^ (ROL(*(uint32_t *)p,5)^*(uint32_t *)(p+4))) * PRIME;        
    }
    // Cases: 0,1,2,3,4,5,6,7
    if (wrdlen & sizeof(uint32_t)) {
        hash32 = (hash32 ^ *(uint32_t*)p) * PRIME;
        p += sizeof(uint32_t);
    }
    if (wrdlen & sizeof(uint16_t)) {
        hash32 = (hash32 ^ *(uint16_t*)p) * PRIME;
        p += sizeof(uint16_t);
    }
    if (wrdlen & 1) 
        hash32 = (hash32 ^ *p) * PRIME;
    
    return hash32 ^ (hash32 >> 16);
}

