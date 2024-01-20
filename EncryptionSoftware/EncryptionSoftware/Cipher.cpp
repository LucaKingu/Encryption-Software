#include "Cipher.h"

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

#include "hex.h"


using namespace std;
using namespace CryptoPP;

Cipher::Cipher(const char* password)
{
	size_t passwordLength = strlen(password);
	storedPassword = new char[passwordLength + 1];		// Accounting for \0 char
	strcpy_s(storedPassword, passwordLength + 1 , password);	//strcpy was unsafe
}

bool Cipher::encryptFile(const char* inputFileName, const char* outputFileName)
{

	SecByteBlock salt = generateRandomSalt();
	generateRandomIV();

	
	if (!deriveKeyFromPassword(storedPassword, strlen(storedPassword), salt))
	{
		cerr << "Key derivation failed" << endl;
		return false;
	}

	if (iv.size() == 0 || key.size() == 0)
	{
		cerr << "Failed to generate IV" << endl;
	}

	try
	{
		ofstream outputFile(outputFileName, ios::binary);		
		ifstream inputFile(inputFileName, ios::binary);		//Input / Output files for actual encryption
		

		if (!inputFile.is_open() || !outputFile.is_open())
		{
			cerr << "Error opening files" << endl;
			return false;
		}

		outputFile.write(reinterpret_cast<const char*>(salt.data()), salt.size());	//IV and salt saved to output file
		outputFile.write(reinterpret_cast<const char*>(iv.data()), iv.size());

		CBC_Mode<AES>::Encryption encryption(key, key.size(), iv);		//Choosing CBC algorithm with iv


		StreamTransformationFilter filter(encryption, new FileSink(outputFileName));	//Data is encrypted and passed to output file

		size_t fileSize = inputFile.tellg();  // Get the size of the file and reset the position to 0
		inputFile.seekg(0);

		vector<char> fileBuffer(fileSize);				//Input contents of inputFile into buffer
		inputFile.read(fileBuffer.data(), fileSize);	

		filter.Put(reinterpret_cast<const byte*>(fileBuffer.data()), fileSize);	  //Puts the fileBuffer content through the encryption filter
		filter.MessageEnd();	//Ends Processsing

		inputFile.close();
		outputFile.close();

		return true;

	}
	catch (const ifstream::failure& e) {
		cerr << "File I/O error: " << e.what() << endl;
		return false;
	}
	catch (const Exception& e) {
		cerr << "Encryption error: " << e.what() << endl;
		return false;

	}
}

bool Cipher::decryptFile(const char* inputFileName, const char* outputFileName)
{
	return false;
}


bool Cipher::deriveKeyFromPassword(const char* password, size_t passwordLength, const SecByteBlock& salt)
{
	const int iterations = 10000;

	try {
		key.resize(AES::DEFAULT_KEYLENGTH);

		PKCS5_PBKDF2_HMAC<SHA256> PBKDF2;		//The password-based key derivation function
		PBKDF2.DeriveKey(key, key.size(), 0, reinterpret_cast<const byte*>(password), passwordLength, salt, salt.size(), iterations);

		//cerr << "Key size: " << key.size() << endl;


		//Check the derived key
		cerr << "Derived Key: ";
		StringSource(reinterpret_cast<const byte*>(key.data()), key.size(), true, new HexEncoder(new FileSink(cerr)));
		cerr << endl;

		return true;
	}
	catch (const Exception e)
	{
		cerr << "Key Derivation error: " << e.what() << endl;
		return false;
	}
}

SecByteBlock Cipher::generateRandomSalt()
{
	SecByteBlock salt(16); // 16 bytes
	prng.GenerateBlock(salt, salt.size());	//A single salt is generated(Function name may be misleading)
	cerr << "salt size: " << salt.size() << endl;
	return salt;
}

bool Cipher::generateRandomIV()
{
	iv.resize(AES::BLOCKSIZE);		//128 bits(default)
	prng.GenerateBlock(iv, iv.size());		//A single iv is generated(Function name may be misleading)
	cerr << "IV size: " << iv.size() << endl;
	return true;
}



Cipher::~Cipher()	//Avoding memory leaks
{
	delete[] storedPassword;
	//Crypto++ manages memory interally no need to clean up objects from library
} 