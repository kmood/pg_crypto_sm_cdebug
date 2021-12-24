/*************************************************************************
	   > File Name: SM4test.c
	   > Author:NEWPLAN
	   > E-mail:newplan001@163.com
	   > Created Time: Thu Apr 13 23:55:50 2017
	   > Quote : https://github.com/NEWPLAN/SMx
************************************************************************/

#include <string.h>
#include <stdio.h>
#include "sm4.h"
#include "pkcs7.h"

int main(int argc, char** argv)
{
	test_sm4_enc();
	return 0;
}

/*
编辑其中采用的gbk 编码，中文占用两个字节，所以在加密的时候会出现不一致，需要转为utf-8 编码，数据库正常
*/
int static test_sm4_enc() {
	char *k = "66787063323140313231350101010101";
	unsigned char input[] = "hello world! 我是 juneandgreen.";
	sm4_context ctx;
	unsigned long i;
	unsigned char key[16];
	long input_len = strlen(input);
	printf("加密数据十进制：---------\n");
	for (i = 0; i < input_len; i++)
		printf("%d ", input[i]);
	printf("-------------\n");
	HexStrToByte(k, key, 32);
	printf("加密数据十进制：---------\n");
	for (i = 0; i < 16; i++)
		printf(" %d ", key[i]);
	printf("-------------\n");
	PKCS7_Padding* data = addPadding(input, input_len, 16);

	printf("加密数据填充后十进制：---------\n");
	for (i = 0; i < data->dataLengthWithPadding; i++)
		printf("%d ", data->dataWithPadding[i]);
	printf("-------------\n");

	//decrypt testing
	sm4_setkey_enc(&ctx, key);
	sm4_crypt_ecb(&ctx, 0, data->dataLengthWithPadding, data->dataWithPadding, data->dataWithPadding);
	unsigned char * output = (unsigned char*)malloc(data->dataLengthWithPadding * 2 * sizeof(unsigned char));
	printf("\n--------加密后的长度：%d\n",strlen(output));
	for (i = 0; i < data->dataLengthWithPadding; i++)
		printf("%d ", data->dataWithPadding[i]);
	printf("-------------\n");
	ByteToHexStr(data->dataWithPadding, output, data->dataLengthWithPadding);	
	printf("\n--------转为16进制字符串后的值：\n");
	printf("%s ", output);
	printf("-------------\n");
	return 0;
}


void test_sm4_dec()
{
	char *k = "66787063323140313231350101010101";
	unsigned char key[16];
	unsigned char input1[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x00, 0x00, 0x00, 0x00 };
	sm4_context ctx;
	unsigned long i;
	unsigned char input[] = "c05eccc3a1a4add97af87ccd021228a771f872e3304f15b2b40db55d7718f8bff972af63919589a104ea86faaecf6f9b";
	long input_len = strlen(input);
	long length = input_len / 2;
	printf("\n-----------------------\n unsigned char 字节数：%d \n", sizeof(unsigned char));
	unsigned char *output_ = (unsigned char *)malloc(length);
	HexStrToByte(k, key, 32);
	printf("\n--------\n output_ 大小：%d \n", strlen(output_));
	printf("\n--------\n key 大小： %d \n", strlen(key));
	printf("\n--------output_初始化值：\n");
	for (i = 0; i < strlen(output_); i++)
		printf("%d ", output_[i]);
	printf("\n-----------------------\n");

	for (i = 0; i < sizeof(key); i++)
		printf("%d ", key[i]);
	printf("\n-----------------------\n");

	HexStrToByte(input, output_, input_len);
	//encrypt standard testing vector
	//sm4_setkey_enc(&ctx, key);
	//sm4_crypt_ecb(&ctx, 1, structWithPaddingResult->dataLengthWithPadding, structWithPaddingResult->dataWithPadding, output);
	//for (i = 0; i < structWithPaddingResult->dataLengthWithPadding; i++)
	//	printf("%02x ", output[i]);
	//printf("\n");
	printf("\n--------16进制字符串到16进制数组后的值：\n");
	for (i = 0; i < strlen(output_); i++)
		printf("%d ", output_[i]);

	//decrypt testing
	sm4_setkey_dec(&ctx, key);
	sm4_crypt_ecb(&ctx, 0, length, output_, output_);
	printf("\n--------解密后的值：\n");
	for (i = 0; i < strlen(output_); i++)
		printf("%d ", output_[i]);

	PKCS7_unPadding* data = removePadding(output_, length);
	printf("\n--------去除填充的值：\n");
	//for (i = 0; i < data->dataLengthWithoutPadding; i++)
	printf("---%s---", data->dataWithoutPadding);
	return 0;
}