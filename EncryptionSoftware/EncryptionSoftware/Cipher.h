#pragma once



#include <ostream>
#include <iostream>
#include <fstream>

#include "aes.h"
#include "filters.h"
#include "modes.h"
#include "osrng.h"
#include "secblock.h"
#include "pwdbased.h"
//#include "pkcs5.h"
//#include "evp.h"
#include "sha.h"
#include "files.h"



using namespace CryptoPP;

class Cipher
{
public:
	//const keywords since it is important that passwords and file names are immutable
	Cipher(const char* password);
	~Cipher();

	bool encryptFile(const char* inputFileName, const char* outputFileName);
	bool decryptFile(const char* inputFileName, const char* outputFileName);

	

private:
	char* storedPassword;

	bool generateRandomIV();
	bool deriveKeyFromPassword(const char* password, size_t passwordLength , const SecByteBlock& salt);
	
//From cryptlib library
	SecByteBlock key;	//Class able to hold cryptographic keys
	SecByteBlock iv;	//Same class able to hold an initilization vector(Random number)
	AutoSeededRandomPool prng;  //A class to generate a hilghy secure random number for the iv

	SecByteBlock generateRandomSalt();	//Function for a salt for KDF
	
	
};

