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
 * file_operations.c
 *
 */

#include "file_operations.h"

#include <stdio.h>
#include <stdlib.h>

#include "structures.h"

/*
 * read the target file into a buffer
 */
uint32_t 
read_target(uint8_t **targetBuffer, const char *target)
{
    FILE *in_file;
	
    in_file = fopen(target, "r");
    if (!in_file)
    {
		printf("[ERROR] Could not open target file %s!\n", target);
        exit(1);
    }
    if (fseek(in_file, 0, SEEK_END))
    {
		printf("[ERROR] Fseek failed at %s\n", target);
        exit(1);
    }
    
    uint32_t fileSize = (uint32_t)ftell(in_file);
    
    if (fseek(in_file, 0, SEEK_SET))
    {
		printf("[ERROR] Fseek failed at %s\n", target);
        exit(1);
    }
    
    *targetBuffer = malloc(fileSize);
    if (*targetBuffer == NULL) 
    { 
        printf("[ERROR] Malloc failed! Exiting...\n"); 
        exit(1); 
    }
    
    fread(*targetBuffer, fileSize, 1, in_file);
	if (ferror(in_file))
	{
		printf("[ERROR] fread failed at %s\n", target);
        free(*targetBuffer);
		exit(1);
	}
    fclose(in_file);  
    return(fileSize);
}
