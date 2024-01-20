
#include "Cipher.h"

#include "cryptlib.h"
#include "rijndael.h"
#include "modes.h"
#include "files.h"
#include "osrng.h"
#include "hex.h"

#include <fstream>
#include <iostream>
#include <cstring>

#include <aes.h>
#include <filters.h>
#include <modes.h>
#include <osrng.h>

using namespace std;

int main()
{
    const char* inputFileName = R"(C:\Users\alfin\OneDrive\Desktop\EncrypTest.txt)";
    const char* otuputFileName = R"(C:\Users\alfin\OneDrive\Desktop\EncryptedText.txt)";
    const char* password = "test";

    Cipher cipher(password);

    if (cipher.encryptFile(inputFileName, otuputFileName))
    {
        cout << "Encryption successfull" << endl;
    }
    else
    {
        cerr << "Encryption failed" << endl;
    }

    return 0;
}