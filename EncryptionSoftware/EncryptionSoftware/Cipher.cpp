#include "Cipher.h"

#include <aes.h>
#include <filters.h>
#include <modes.h>
#include <osrng.h> //Operating system random generation used for AutoSeededRandomPool


Cipher::Cipher(const char* password)
{
}

Cipher::~Cipher()
{
}

bool Cipher::encryptFile(const char* inputFileName, const char* outputFileName)
{
	return false;
}

bool Cipher::decryptFile(const char* inputFileName, const char* outputFileName)
{
	return false;
}

bool Cipher::generateRandomIV()
{
	return false;
}

bool Cipher::deriveKeyFromPassword(const char* password, size_t passwordLength)
{
	return false;
}
