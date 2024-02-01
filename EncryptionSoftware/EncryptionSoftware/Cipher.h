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
	bool deriveKeyFromPassword(const char* password, size_t passwordLength , const CryptoPP::SecByteBlock& salt);
	
//From cryptlib library
	CryptoPP::SecByteBlock key;	//Class able to act as a cryptographic key
	CryptoPP::SecByteBlock iv;	//Same class able to act as an initilization vector(Random number)
	CryptoPP::SecByteBlock salt;	//Able to act as a salt
	CryptoPP::AutoSeededRandomPool prng;  //A class to generate a hilghy secure random number for the iv

	CryptoPP::SecByteBlock generateRandomSalt();	//Function for a salt for KDF
	
	
};

