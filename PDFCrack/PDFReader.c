//
//  PDFReader.c
//  PDFCrack
//
//  Created by Alex Nichol on 8/15/11.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#include "PDFReader.h"

/**
 * Read the ID string from the documents trailer.
 */
static int _PDFReaderReadID (PDFReader reader, char * destination, unsigned long trailer);

/**
 * Convert a two-byte hex string into a character.
 */
static unsigned char _PDFReaderFromHex (const char * hexBuff);

/**
 * Get to the encryption dictionary.
 */
static bool _PDFReaderSeekEncryption (PDFReader reader);


bool PDFReaderNew (PDFReader * reader, const char * filePath) {
	FILE * fp = fopen(filePath, "r");
	if (!fp) {
		return false;
	}
	fseek(fp, 0, SEEK_END);
	reader->fileLength = ftell(fp);
	reader->pdfFile = fp;
	fseek(fp, 0, SEEK_SET);
	return true;
}

int PDFReaderGetID (PDFReader reader, unsigned char * destination, int maxLength) {
	// WIP
	char hexString[512];
	int hexLength = 0;
	
	unsigned long trailerStart = 0;
	int lineOff = 0;
	for (trailerStart = 0; trailerStart < reader.fileLength; trailerStart++) {
		int startChar = fgetc(reader.pdfFile);
		if (startChar == EOF) {
			return 0;
		}
		if (startChar == '\n') {
			// check this part
			char lineBuff[16];
			lineBuff[0] = 0;
			for (lineOff = 0; lineOff < 15; lineOff++) {
				int nextChar = fgetc(reader.pdfFile);
				if (nextChar == EOF) return 0;
				if (nextChar == '\n' || nextChar == '\r') break;
				lineBuff[lineOff] = (char)nextChar;
				lineBuff[lineOff + 1] = 0;
			}
			if (strcmp(lineBuff, "trailer") == 0) {
				trailerStart += 8;
				break;
			}
		}
	}
	if (trailerStart + 1 >= reader.fileLength) {
		return 0;
	}
	// now we need to read the /ID section.
	// return _PDFReaderReadID(reader, destination, trailerStart);
	hexLength = _PDFReaderReadID(reader, hexString, trailerStart);
	if (hexLength == 0) return 0;
	for (int i = 0; i < hexLength - 1; i += 2) {
		destination[i / 2] = _PDFReaderFromHex(&hexString[i]);
	}
	return (int)(hexLength / 2);
}

bool PDFReaderGetFlags (PDFReader reader, int * flags) {
	if (_PDFReaderSeekEncryption(reader)) {
		char value[512];
		char key[512];
		int keyLen = 0;
		int valLen = 0;
		bool isFinished;
		while (PDFReaderGetDictKey(reader, key, &keyLen, value, &valLen, 512, &isFinished)) {
			if (strcmp(key, "P") == 0) {
				value[valLen] = 0;
				*flags = atoi(value);
				return true;
			}
			if (isFinished) break;
		}
	}
	return false;
}

bool PDFReaderGetUserPass (PDFReader reader, unsigned char * hash) {
	if (_PDFReaderSeekEncryption(reader)) {
		char value[512];
		char key[512];
		int keyLen = 0;
		int valLen = 0;
		bool isFinished;
		while (PDFReaderGetDictKey(reader, key, &keyLen, value, &valLen, 512, &isFinished)) {
			if (strcmp(key, "U") == 0) {
				char hexString[64];
				int hexIndex = 0;
				value[valLen] = 0; // null terminate it.
				bool isInside = false;
				for (int i = 0; i < valLen; i++) {
					if (value[i] == '<') {
						isInside = true;
					} else if (value[i] == '>') {
						isInside = false;
					} else if (isInside) {
						if (hexIndex < 64) {
							hexString[hexIndex++] = value[i];
						}
					}
				}
				if (hexIndex != 64) return false;
				for (int i = 0; i < hexIndex - 1; i += 2) {
					hash[i / 2] = _PDFReaderFromHex(&hexString[i]);
				}
				return true;
			}
			if (isFinished) break;
		}
	}
	return false;
}

bool PDFReaderGetOwnerPass (PDFReader reader, unsigned char * hash) {
	if (_PDFReaderSeekEncryption(reader)) {
		char value[512];
		char key[512];
		int keyLen = 0;
		int valLen = 0;
		bool isFinished;
		while (PDFReaderGetDictKey(reader, key, &keyLen, value, &valLen, 512, &isFinished)) {
			if (strcmp(key, "O") == 0) {
				char hexString[64];
				int hexIndex = 0;
				value[valLen] = 0; // null terminate it.
				bool isInside = false;
				for (int i = 0; i < valLen; i++) {
					if (value[i] == '<') {
						isInside = true;
					} else if (value[i] == '>') {
						isInside = false;
					} else if (isInside) {
						if (hexIndex < 64) {
							hexString[hexIndex++] = value[i];
						}
					}
				}
				if (hexIndex != 64) return false;
				for (int i = 0; i < hexIndex - 1; i += 2) {
					hash[i / 2] = _PDFReaderFromHex(&hexString[i]);
				}
				return true;
			}
			if (isFinished) break;
		}
	}
	return false;
}

void PDFReaderClose (PDFReader reader) {
	fclose(reader.pdfFile);
}

bool PDFReaderSeekDict (PDFReader reader) {
	char backlog[4];
	backlog[3] = 0;
	while (!feof(reader.pdfFile)) {
		// shift backleft left
		int aChar = fgetc(reader.pdfFile);
		if (aChar == EOF) return false;
		for (int i = 0; i < 3; i++) {
			backlog[i] = backlog[i + 1];
		}
		backlog[2] = (char)aChar;
		if (strcmp(backlog, "\n<<") == 0) {
			// we have found our next dictionary
			return true;
		}
	}
	return false;
}

bool PDFReaderGetDictKey (PDFReader reader, char * keyDest, int * keyLen, char * valDest, int * valLen, int keyValMax, bool * isLast) {
	int stage = 0;
	// 0 = no key
	// 1 = reading key
	// 2 = reading value
	int keyLength = 0;
	int valueLength = 0;
	int lChar = -1;
	while (!feof(reader.pdfFile)) {
		int aChar = fgetc(reader.pdfFile);
		if (aChar == EOF) return false;
		if (stage == 0) {
			if (aChar == '/') stage = 1;
		} else if (stage == 1) {
			if (isspace(aChar)) {
				stage = 2;
			} else {
				if (keyLength < keyValMax - 1) {
					keyDest[keyLength++] = (char)aChar;
					keyDest[keyLength] = 0; // NULL terminate that bad-boy
				}
			}
		} else if (stage == 2) {
			if (aChar == '/' || (aChar == '>' && lChar == '>')) {
				// throw it back a character
				if (aChar == '>') {
					valDest[--valueLength] = 0; // clear '>' character.
					// trim whitespace
					for (int i = valueLength - 1; i > 0; i--) {
						if (!isspace(valDest[i])) break;
						valDest[i] = 0;
					}
					*isLast = true;
				} else *isLast = false;
				fseek(reader.pdfFile, ftell(reader.pdfFile) - 1, SEEK_SET);
				*keyLen = keyLength;
				*valLen = valueLength;
				return true;
			} else {
				if (valueLength > 0 || (valueLength == 0 && !isspace(aChar))) {
					if (valueLength < keyValMax) {
						valDest[valueLength++] = (char)aChar;
					}
				}
			}
		}
		lChar = aChar;
	}
	return false;
}


/*******************
 * Private methods *
 *******************/

static int _PDFReaderReadID (PDFReader reader, char * destination, unsigned long trailer) {
	fseek(reader.pdfFile, trailer, SEEK_SET);
	// backBuff is a log of the last 11 characters read, followed by
	// a NULL byte.
	bool hasFoundID = false;
	char backBuff[12];
	backBuff[11] = 0;
	for (unsigned long i = trailer; i < reader.fileLength; i++) {
		int readChar = fgetc(reader.pdfFile);
		if (readChar == EOF) return 0;
		// shift the array to the left.
		for (int j = 0; j < 10; j++) {
			backBuff[j] = backBuff[j + 1];
		}
		backBuff[10] = (char)readChar;
		// check if the backlog is /ID.
		if (strcmp(&backBuff[8], "/ID") == 0) {
			hasFoundID = true;
		}
		// if we have hit a < then this is the ID buffer.
		if (backBuff[10] == '<' && hasFoundID) {
			for (unsigned long buffIndex = 0; buffIndex < (reader.fileLength - i); buffIndex++) {
				if (buffIndex > 64) abort(); // this is a buffer overflow attack.
				readChar = fgetc(reader.pdfFile);
				if (readChar == EOF) return 0;
				if ((char)readChar == '>') return (int)buffIndex;
				destination[buffIndex] = (char)readChar;
			}
			return 0;
		}
	}
	return 0;
}

static unsigned char _PDFReaderFromHex (const char * hexBuff) {
	unsigned char ch1 = toupper(hexBuff[0]);
	unsigned char ch2 = toupper(hexBuff[1]);
	unsigned char val1 = ch1 - 0x30;
	unsigned char val2 = ch2 - 0x30;
	if (val1 > 9) val1 -= 7;
	if (val2 > 9) val2 -= 7;
	return ((val1 << 4) | val2);
}

static bool _PDFReaderSeekEncryption (PDFReader reader) {
	fseek(reader.pdfFile, 0, SEEK_SET);
	while (PDFReaderSeekDict(reader)) {
		long offset = ftell(reader.pdfFile);
		char value[512];
		char key[512];
		int keyLen = 0;
		int valLen = 0;
		bool isFinished;
		while (PDFReaderGetDictKey(reader, key, &keyLen, value, &valLen, 512, &isFinished)) {
			if (strcmp(key, "O") == 0) {
				fseek(reader.pdfFile, offset, SEEK_SET);
				return true;
			}
			if (isFinished) break;
		}
	}
	return false;
}
