/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>//추가
#include <string.h>//추가
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt.h>

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_MYTA_UUID;
	uint32_t err_origin;
	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	int len=64;
	//추가
	FILE* fp;
	char* readBuf;
	int readLen = 0;
	int index = 0;
	//
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = len;

	
	if(!strcmp(argv[1], "-e")){
	
		printf("========================Encryption========================\n");
		
		fp = fopen(argv[2], "r");
		if (fp == NULL) {
			printf("파일열기 실패\n");	
		}
		else{
			fseek(fp, 0, SEEK_END);
			readLen = ftell(fp);
			
			readBuf = malloc(readLen+1);
			memset(readBuf, 0, readLen+1);
			
			fseek(fp, 0, SEEK_SET);
			fread(readBuf, readLen, 1, fp);
			strcpy(plaintext, readBuf);
			
			memcpy(op.params[0].tmpref.buffer, plaintext, len);
			printf("Plaintext : %s\n", plaintext);

			res = TEEC_InvokeCommand(&sess, TA_MYTA_CMD_ENC_VALUE, &op,
						 &err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
					res, err_origin);

			memcpy(ciphertext, op.params[0].tmpref.buffer, len);
			
			index = 0;			
			while(ciphertext[index]){
				index++;			
			}

			printf("Ciphertext : ");
			for(int i=0; i<index-1; i++){
				printf("%c", ciphertext[i]);
			}
			printf("\n");
			
		}

		free(readBuf);
		fclose(fp);

		fp = fopen("/root/Ciphertext.txt", "w");
		fputs(ciphertext, fp);
		fclose(fp);
 
		
	} else if(!strcmp(argv[1], "-d")){
	/*
	FILE* fp;
	char* readBuf;
	int readLen;
	*/
		printf("========================Decryption========================\n");
		fp = fopen(argv[2], "r");
		if (fp == NULL) {
			printf("파일열기 실패\n");	
		}
		else{
			fseek(fp, 0, SEEK_END);
			readLen = ftell(fp);
			
			readBuf = malloc(readLen+1);
			memset(readBuf, 0, readLen+1);
			fseek(fp, 0, SEEK_SET);
			fread(readBuf, readLen, 1, fp);
			strcpy(ciphertext, readBuf);
			
			memcpy(op.params[0].tmpref.buffer, ciphertext, len);
			//키부분 표시되지 않게함
			index = 0;
			while(ciphertext[index]){
				index++;
			}
			ciphertext[index-1] = '\0';
			//
			printf("Ciphertext : %s\n", ciphertext);
			
			res = TEEC_InvokeCommand(&sess, TA_MYTA_CMD_DEC_VALUE, &op,
					 &err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
					res, err_origin);
			memcpy(plaintext, op.params[0].tmpref.buffer, len);
			
			printf("Plaintext : %s\n", plaintext);
		
		}
		
		free(readBuf);
		fclose(fp);

		fp = fopen("/root/decryptedtext.txt", "w");
		fputs(plaintext, fp);
		fclose(fp);
	
	}
	


	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
