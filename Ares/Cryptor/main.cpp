/*
*	Project Ares Cryptor
*
*	AUTHOR: @Cerbersec - https://twitter.com/Cerbersec
*	VERSION: 1.0
*/

#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>

#define CBC 1

#include "aes.h"
#include "pkcs7_padding.c"
using namespace std;

int main(int argc, char* argv[])
{
    if (argc == 2) {
        ifstream inputfile(argv[1], ios::binary | ios::ate);
        streamsize size = inputfile.tellg();
        cout << "Size:" << size << endl;
        inputfile.seekg(0, ios::beg);

        std::vector<char> buffer(size);

        inputfile.read(buffer.data(), size);
        if (inputfile.good()) {

            //modify key with a 16-byte value
            char* key = (char*)"16-byte-key-here";
            const uint8_t iv[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
            int blen = buffer.size();
            int klen = strlen(key);

            int klenu = klen;
            int blenu = blen;
            if (klen % 16)
                klenu += 16 - (klen % 16);
            if (blen % 16)
                blenu += 16 - (blen % 16);

            cout << "Padding size: " << blenu << endl;

            uint8_t* keyarr = new uint8_t[klenu];
            uint8_t* bufarr = new uint8_t[blenu];
            ZeroMemory(keyarr, klenu);
            ZeroMemory(bufarr, blenu);
            memcpy(keyarr, key, klen);
            memcpy(bufarr, buffer.data(), blen);

            pkcs7_padding_pad_buffer(keyarr, klen, klenu, 16);
            pkcs7_padding_pad_buffer(bufarr, blen, blenu, 16);

            AES_ctx ctx;
            AES_init_ctx_iv(&ctx, keyarr, iv);
            AES_CBC_encrypt_buffer(&ctx, bufarr, blenu);

            ofstream outputfile("payload.bin", ios::binary);
            outputfile.write((char*)bufarr, blenu);

            outputfile.close();
            delete[] bufarr;
            delete[] keyarr;
        }

        inputfile.close();
        return 0;
    }
    else {
        printf("Usage: Cryptor.exe <filepath>\n");
        printf("Filepath: path to payload to encrypt\n");
        printf("Encrypted output is written to payload.bin\n");
        return 0;
    }
}