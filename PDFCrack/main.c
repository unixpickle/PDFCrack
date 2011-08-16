//
//  main.c
//  PDFCrack
//
//  Created by Alex Nichol on 8/15/11.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/rc4.h>
#include "PDFReader.h"

void strTrim (char * buffer) {
	if (strlen(buffer) > 0) {
		if (buffer[strlen(buffer) - 1] == '\n') {
			buffer[strlen(buffer) - 1] = 0;
		}
	}
	if (strlen(buffer) > 0) {
		if (buffer[strlen(buffer) - 1] == '\r') {
			buffer[strlen(buffer) - 1] = 0;
		}
	}
}

const unsigned char AdobeEncString[32] = {0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41,
                                          0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
                                          0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80,
										  0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A};

void genEncKey (const char * userDec, const char * docID, int docIDLen, const unsigned char * ownerHash, int perms, unsigned char * theKey) {
	// assuming little endian
	char * intBuffer = (char *)&perms;
	unsigned char md5Buff[16];
	char * keyUnhash = (char *)malloc(32 + 32 + 4 + docIDLen);
	int i;
	for (i = (int)strlen(userDec); i < 32; i++) { keyUnhash[i] = AdobeEncString[i - (int)strlen(userDec)]; }
	for (i = 0; i < (int)strlen(userDec); i++) {
		keyUnhash[i] = userDec[i];
	}
	for (i = 32; i < 64; i++) {
		keyUnhash[i] = ownerHash[i - 32];
	}
	for (i = 64; i < 68; i++) {
		keyUnhash[i] = intBuffer[i - 64];
	}
	for (i = 68; i < 68 + docIDLen; i++) {
		keyUnhash[i] = docID[i - 68];
	}
	MD5((const unsigned char *)keyUnhash, 32 + 32 + 4 + docIDLen, md5Buff);
	free(keyUnhash);
	theKey[0] = md5Buff[0];
	theKey[1] = md5Buff[1];
	theKey[2] = md5Buff[2];
	theKey[3] = md5Buff[3];
	theKey[4] = md5Buff[4];
}

bool checkPassword (const char * userPass, const unsigned char * userHash, const char * docID, int docIDLen, unsigned char * ownerHash, int perms) {
	unsigned char theKey[5];
	unsigned char destination[32];
	int i;
	genEncKey(userPass, docID, docIDLen, ownerHash, perms, theKey);
	RC4_KEY key;
	RC4_set_key(&key, 5, theKey);
	RC4(&key, 32, userHash, destination);
	for (i = 0; i < 32; i++) {
		if (destination[i] != AdobeEncString[i]) return false;
	}
	return true;
}

int main (int argc, const char * argv[]) {
	const char * pdfPath = NULL;
	char pathBuffer[512];
	PDFReader reader;
	unsigned char docID[512];
	unsigned char userPassword[32];
	unsigned char ownerPassword[32];
	unsigned char encKey[5];
	unsigned char decPassword[32];
	int docIDLength = 0, permissions = 0;
	
	if (argc == 2) {
		pdfPath = argv[1];
	} else {
		printf("Enter path: ");
		fgets(pathBuffer, 512, stdin);
		pdfPath = pathBuffer;
		strTrim(pathBuffer);
	}
	
	if (!pdfPath) {
		fprintf(stderr, "Please specify a PDF file.\n");
		fflush(stderr);
		return 1;
	}
	if (!PDFReaderNew(&reader, pdfPath)) {
		fprintf(stderr, "Failed to open: %s\n", pdfPath);
		fflush(stderr);
		return 1;
	}
	
	docID[0] = 0;
	if ((docIDLength = PDFReaderGetID(reader, docID, 512)) == 0) {
		fprintf(stderr, "Failed to get document ID\n");
		fflush(stderr);
		return 1;
	}
	printf("Got ID of %d bytes: ", docIDLength);
	for (int i = 0; i < docIDLength; i++) {
		printf("%02x", docID[i]);
	}
	printf("\n");
	
	if (!PDFReaderGetFlags(reader, &permissions)) {
		fprintf(stderr, "Failed to get flags\n");
		fflush(stderr);
		return 1;
	}
	printf("Permissions: %d\n", permissions);
	
	if (!PDFReaderGetUserPass(reader, userPassword)) {
		fprintf(stderr, "Failed to get user password hash\n");
		fflush(stderr);
		return 1;
	}
	printf("Got user hash: ");
	for (int i = 0; i < 32; i++) {
		printf("%02x", userPassword[i]);
	}
	printf("\n");
	
	if (!PDFReaderGetOwnerPass(reader, ownerPassword)) {
		fprintf(stderr, "Failed to get owner password hash\n");
		fflush(stderr);
		return 1;
	}
	printf("Got owner hash: ");
	for (int i = 0; i < 32; i++) {
		printf("%02x", ownerPassword[i]);
	}
	printf("\n");
	
	PDFReaderClose(reader);
	
	if (checkPassword("12345", userPassword, (const char *)docID, docIDLength, ownerPassword, permissions)) {
		printf("Wow, the password is 12345.\n");
	} else {
		printf("The password definitely isn't 12345... or maybe it is?\n");
	}
	
	
	
    return 0;
}

