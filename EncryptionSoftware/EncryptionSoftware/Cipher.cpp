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
	if (key.size() == 0 || iv.size() == 0)
	{
		cerr << "Key or IV not derived" << endl;
		return false;
	}

	//SecByteBlock salt = generateRandomSalt();

	try
	{
		ifstream inputFile(inputFileName, ios::binary);
		ofstream outputFile(outputFileName, ios::binary);

		if (!inputFile.is_open() || !outputFile.is_open())
		{
			cerr << "Error opening files" << endl;
			return false;
		}

		//if (!deriveKeyFromPassword(storedPassword, strlen(storedPassword), salt))
		//{
			//cerr << "Key derivation failed" << endl;
			//return false;
		//}

		//generateRandomIV();
		CBC_Mode<AES>::Encryption encryption(key, key.size(), iv);		//Choosing CBC mode

		StreamTransformationFilter filter(encryption, new FileSink(outputFileName));

		size_t fileSize = inputFile.tellg();  // Get the size of the file
		inputFile.seekg(0);

		vector<char> fileBuffer(fileSize);
		inputFile.read(fileBuffer.data(), fileSize);

		filter.Put(reinterpret_cast<const byte*>(fileBuffer.data()), fileSize);
		filter.MessageEnd();

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

SecByteBlock Cipher::generateRandomSalt()
{
	SecByteBlock salt(16); // 16 bytes
	prng.GenerateBlock(salt, salt.size());
	return salt;
}

bool Cipher::generateRandomIV()
{
	iv.resize(AES::BLOCKSIZE);		//128 bits(default)
	prng.GenerateBlock(iv, iv.size());
	return true;
}

bool Cipher::deriveKeyFromPassword(const char* password, size_t passwordLength , const SecByteBlock& salt)
{
	const int iterations = 10000;

	try {
		if (key.size() == 0)
		{
			cerr << "key not allocated" << endl;
			return false;
		}

		PKCS5_PBKDF2_HMAC<SHA256> PBKDF2;//The password-based key derivation function
		PBKDF2.DeriveKey(key, key.size(), 0, reinterpret_cast<const byte*>(password), passwordLength, salt, salt.size(), iterations);

		return true;
	}
	catch (const Exception e)
	{
		cerr << "Key Derivation error: " << e.what() << endl;
		return false;
	}
}


Cipher::~Cipher()	//Avoding memory leaks
{
	delete[] storedPassword;
	//
} 