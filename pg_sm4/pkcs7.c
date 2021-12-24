#include "pkcs7.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


PKCS7_Padding* addPadding(const uint8_t*  data, const uint64_t dataLength, const uint8_t BLOCK_SIZE)
{
	if (0 == BLOCK_SIZE)
	{
		puts("ERROR: block size value must be 0 < BLOCK_SIZE < 256");
		exit(-1);
	}

	PKCS7_Padding* paddingResult = (PKCS7_Padding*)malloc(sizeof(PKCS7_Padding));
	if (NULL == paddingResult)
	{
		perror("problem with PKCS7_Padding* paddingResult");    /* if memory allocation failed */
		exit(-1);
	}

	uint8_t paddingBytesAmount = BLOCK_SIZE - (dataLength % BLOCK_SIZE);  /* number of bytes to be appended */
	paddingResult->valueOfByteForPadding = paddingBytesAmount;                      /* according to the PKCS7 */
	paddingResult->dataLengthWithPadding = dataLength + paddingBytesAmount;         /* size of the final result */

	uint8_t* dataWithPadding = (uint8_t*)malloc(paddingResult->dataLengthWithPadding);
	if (NULL == paddingResult)
	{
		perror("problem with uint8_t* dataWithPadding");  /* if memory allocation failed */
		exit(-1);
	}

	memcpy(dataWithPadding, data, dataLength);  /* copying the original data for further adding padding */
	for (uint8_t i = 0; i < paddingBytesAmount; i++)
	{
		dataWithPadding[dataLength + i] = paddingResult->valueOfByteForPadding;   /* adding padding bytes */
	}
	paddingResult->dataWithPadding = dataWithPadding;

	return paddingResult;
}

PKCS7_unPadding* removePadding(const uint8_t* data, const uint64_t dataLength)
{
	PKCS7_unPadding* unpaddingResult = (PKCS7_unPadding*)malloc(sizeof(PKCS7_unPadding));
	if (NULL == unpaddingResult)
	{
		perror("problem with PKCS7_Padding* unpaddingResult");  /* if memory allocation failed */
		exit(-1);
	}
	printf("---------\n 去除填充的值 ");
	uint8_t paddingBytesAmount = data [dataLength - 1];  /* last byte contains length of data to be deleted */
	unpaddingResult->valueOfRemovedByteFromData = paddingBytesAmount;                   /* according to the PKCS7 */
	unpaddingResult->dataLengthWithoutPadding = dataLength - paddingBytesAmount;      /* size of the final result */
	printf("\npaddingBytesAmount ：%d \n", paddingBytesAmount);
	uint8_t* dataWithoutPadding = (uint8_t*)malloc(unpaddingResult->dataLengthWithoutPadding);
	printf("\strlen（dataWithoutPadding） ：%d \n", strlen(dataWithoutPadding));
	if (NULL == dataWithoutPadding)
	{
		perror("problem with uint8_t* dataWithoutPadding");   /* if memory allocation failed */
		exit(-1);
	}
	printf("\n dataWithoutPadding 前：\n ");
	for (int i = 0; i < strlen(dataWithoutPadding); i++)
		printf("%d ", (unsigned char *)dataWithoutPadding[i]);
	memcpy(dataWithoutPadding, data, unpaddingResult->dataLengthWithoutPadding);    /* taking data without bytes containing the padding value */
	unpaddingResult->dataWithoutPadding = dataWithoutPadding;


	printf("\n dataWithoutPadding 后：%d \n ",strlen(unpaddingResult->dataWithoutPadding));
	for (int i = 0; i < strlen(unpaddingResult->dataWithoutPadding); i++)
		printf("%d ", (unsigned char *)dataWithoutPadding[i]);
	return unpaddingResult;
}

void freePaddingResult(PKCS7_Padding* puddingResult)
{
	free(puddingResult->dataWithPadding);
	free(puddingResult);
}

void freeUnPaddingResult(PKCS7_unPadding* unPuddingResult)
{
	free(unPuddingResult->dataWithoutPadding);
	free(unPuddingResult);
}