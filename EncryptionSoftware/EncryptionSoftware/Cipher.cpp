#include "Cipher.h"

#include <aes.h>
#include <filters.h>
#include <modes.h>
#include <osrng.h> 


using namespace std;
using namespace CryptoPP;

Cipher::Cipher(const char* password)
{
	size_t passwordLength = strlen(password);
	storedPassword = new char[passwordLength + 1];		// Accounting for \0 char
	strcpy(storedPassword, password);
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
	iv.resize(AES::BLOCKSIZE);		//128 bits(default)
	prng.GenerateBlock(iv, iv.size());
	return true;
}

bool Cipher::deriveKeyFromPassword(const char* password, size_t passwordLength)
{
	return false;
}

Cipher::~Cipher()	//Avoding memory leaks
{
	delete[] storedPassword;
	//
}