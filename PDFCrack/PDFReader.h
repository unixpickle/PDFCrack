//
//  PDFReader.h
//  PDFCrack
//
//  Created by Alex Nichol on 8/15/11.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>

typedef struct {
	FILE * pdfFile;
	long fileLength;
} PDFReader;

bool PDFReaderNew (PDFReader * reader, const char * filePath);
int PDFReaderGetID (PDFReader reader, unsigned char * destination, int maxLength);
bool PDFReaderGetFlags (PDFReader reader, int * flags);
bool PDFReaderGetUserPass (PDFReader reader, unsigned char * hash);
bool PDFReaderGetOwnerPass (PDFReader reader, unsigned char * hash);
void PDFReaderClose (PDFReader reader);

/**
 * Seek up to the next dictionary object in the file.
 */
bool PDFReaderSeekDict (PDFReader reader);

/**
 * Read the next key and value from the current dictionary.
 */
bool PDFReaderGetDictKey (PDFReader reader, char * keyDest, int * keyLen, char * valDest, int * valLen, int keyValMax, bool * isLast);
