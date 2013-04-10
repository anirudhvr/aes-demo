//
//  aes.cpp
//  Youcrypt
//
//  Created by Anirudh Ramachandran <avr@nouvou.com> on 3/1/13.
//  Copyright (c) 2013 Nouvou Inc. All rights reserved.
//
//  Compile: g++ -o aes aes.cpp -lcrypto
//

#include <cstring>
#include <algorithm>
#include <fstream>
#include <iostream>

extern "C" {
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
}

#define AES_BLOCK_SIZE 256
const int BUFSIZE = 4096;

using namespace std;

const string default_encryption_cipher_ = "aes";
const int default_keysize_ = 256;
const int default_blocksize_ = 128;
const string default_encryption_mode_ = "cbc";
const unsigned   default_pbkdf2_iterations_ = 1000;
const unsigned   default_pbkdf2_saltlen_ = 8;

int
encrypt_file(const string &sourcefile, const string &destfile,
        const string &passphrase)
{
    int rc = 1;
    int i;
    EVP_CIPHER_CTX enc_ctx;
    char ciphername[100] = {0};
    const EVP_CIPHER *ciph;
    unsigned char inbuf[BUFSIZE], outbuf[BUFSIZE + AES_BLOCK_SIZE<<1]; // specific to AES
    ofstream ofile;
    ifstream ifile;
    int bytes_read, bytes_encrypted,
        total_bytes_read = 0, total_bytes_encrypted = 0;
    
    // 1. Open input file
    ifile.open(sourcefile.c_str(), ios::in | ios::binary);
    if (!ifile.is_open()) {
        cerr << "Cannot open input file " << sourcefile << endl;
        return rc;
    }
    
    // 2. Check that output file can be opened and written
    ofile.open(destfile.c_str(), ios::out | ios::binary | ios::trunc);
    if (!ofile.is_open()) {
        cerr << "Cannot open input file " << sourcefile << endl;
        return rc;
    }
    
    // 3. generate salt, key, IV from passphrase using pbkdf2
    unsigned char salt_value[default_pbkdf2_saltlen_];
    unsigned char *key = NULL, *iv = NULL; 
    
    iv = new unsigned char [default_keysize_ / 16];
    std::fill(iv, iv + default_keysize_/16, 0); //XXX using a zero IV for now
    
    std::fill(salt_value, salt_value + sizeof(salt_value), 's'); //XXX fixed salt
    key = new unsigned char [default_keysize_ / 8];
    if(!PKCS5_PBKDF2_HMAC(passphrase.c_str(), passphrase.length(), salt_value,
                              sizeof(salt_value), default_pbkdf2_iterations_,
                              EVP_sha256(),
                               default_keysize_ / 8, key)) {
        cerr << "Cannot derive key from password " << endl;
        goto free_data;
    }
    
    cerr << "key: ";
    for(i = 0; i < default_keysize_/8; ++i)
        fprintf(stderr, "%02x", key[i]);
    cerr << endl;
    
    // 4. Initialize encryption engine / context / etc.
    snprintf(ciphername, 99, "%s-%d-%s",
             default_encryption_cipher_.c_str(),
             default_keysize_, default_encryption_mode_.c_str()); // FIXME
    if (!(ciph = EVP_get_cipherbyname(ciphername))) {
        cerr << "Cannot find algorithm " << ciphername << endl;
        goto free_data;
    }
    EVP_CIPHER_CTX_init(&enc_ctx);
    if (!EVP_EncryptInit_ex(&enc_ctx, ciph, NULL, key, iv)) {
        // returns 0 for failure (wtf?)
        cerr << "Cannot initialize encryption cipher " << ciphername << endl;
        goto free_data;
    }
    
    // 5.2 Read source file block, encrypt, and write to output stream
    while (!ifile.eof()) {
        ifile.read((char*)inbuf, BUFSIZE);
        bytes_read = (int) ifile.gcount(); // cast okay because BUFSIZE < MAX_INT
        if (bytes_read > 0) {
            if (!EVP_EncryptUpdate(&enc_ctx, outbuf, &bytes_encrypted,
                                  inbuf, bytes_read)) {
                cerr << "Error encrypting chunk at byte "
                    << total_bytes_encrypted << endl;
                goto free_data;
            }
//            assert(bytes_encrypted > 0);
            if (bytes_encrypted > 0)
                ofile.write((char*)outbuf, bytes_encrypted);
            
            total_bytes_read += bytes_read;
            total_bytes_encrypted += bytes_encrypted;
        }
        bytes_read = bytes_encrypted = 0;
    }
    // 5.3 Encrypt and write final block of input
    EVP_EncryptFinal_ex(&enc_ctx, outbuf, &bytes_encrypted);
    if (bytes_encrypted > 0) {
        ofile.write((char*)outbuf, bytes_encrypted);
    }
    
    // 6. cleanup
    ifile.close();
    ofile.close();
    rc = 0;
    
free_data:
    delete [] key;
    delete [] iv;
    
    return rc;
}

int
decrypt_file(const string &sourcefile, const string &destfile,
        const string &passphrase)
{
    int rc = 1;
    EVP_CIPHER_CTX dec_ctx;
    char ciphername[100] = {0};
    const EVP_CIPHER *ciph;
    unsigned char inbuf[BUFSIZE], outbuf[BUFSIZE + AES_BLOCK_SIZE<<1]; // specific to AES
    ofstream ofile;
    ifstream ifile;
    int bytes_read, bytes_decrypted,
        total_bytes_read = 0, total_bytes_decrypted = 0;
    
    // 1. Open input file
    ifile.open(sourcefile.c_str(), ios::in | ios::binary);
    if (!ifile.is_open()) {
        cerr << "Cannot open input file " << sourcefile << endl;
        return rc;
    }
    
    // 2. Check that input file is of the type we expect
    //    by checking for magic string at header of file
    char magic[128] = {0};

    // 2. Check that output file can be opened and written to
    ofile.open(destfile.c_str(), ios::out | ios::binary | ios::trunc);
    if (!ofile.is_open()) {
        cerr << "Cannot open input file " << sourcefile << endl;
        return rc;
    }
    
    // 3. Derive key from passphrase, create salt and IV
    unsigned char salt_value[default_pbkdf2_saltlen_];
    unsigned char *key = NULL, *iv = NULL; 
    
    iv = new unsigned char [default_keysize_ / 16];
    std::fill(iv, iv + default_keysize_/16, 0); //XXX fixed all-zero IV
    std::fill(salt_value, salt_value + sizeof(salt_value), 's'); //XXX fixed salt
    key = new unsigned char [default_keysize_ / 8];
    if(!PKCS5_PBKDF2_HMAC(passphrase.c_str(), passphrase.length(), salt_value,
                              sizeof(salt_value), default_pbkdf2_iterations_,
                              EVP_sha256(),
                               default_keysize_ / 8, key)) {
        cerr << "Cannot derive key from password " << endl;
        goto free_data;
    }
    
    // 4. Initialize encryption engine / context / etc.
    snprintf(ciphername, 99, "%s-%d-%s",
             default_encryption_cipher_.c_str(),
             default_keysize_, default_encryption_mode_.c_str()); // FIXME
    if (!(ciph = EVP_get_cipherbyname(ciphername))) {
        cerr << "Cannot find algorithm " << ciphername << endl;
        goto free_data;
    }
    EVP_CIPHER_CTX_init(&dec_ctx);
    if (!EVP_DecryptInit_ex(&dec_ctx, ciph, NULL, key, iv)) {
        // returns 0 for failure (wtf?)
        cerr << "Cannot initialize decryption cipher " << ciphername << endl;
        goto free_data;
    }
    
    // 5.1 Read source blocks, decrypt, write to output stream
    while (!ifile.eof()) {
        ifile.read((char*) inbuf, BUFSIZE);
        bytes_read = (int) ifile.gcount();
        if (bytes_read > 0) {
            if (!EVP_DecryptUpdate(&dec_ctx, outbuf, &bytes_decrypted,
                                   inbuf, bytes_read)) {
                cerr << "Error decrypting chunk at byte " << total_bytes_decrypted <<
                endl;
                goto free_data;
            }
//            assert(bytes_decrypted > 0); // this is not necessarily true
            if (bytes_decrypted > 0)
                ofile.write((char*)outbuf, bytes_decrypted);
            
            total_bytes_read += bytes_read;
            total_bytes_decrypted = bytes_decrypted;
        }
        bytes_read = bytes_decrypted = 0;
    }
    // 5.2 Encrypt remaining data and write final block of output
    EVP_DecryptFinal_ex(&dec_ctx, outbuf, &bytes_decrypted);
    if (bytes_decrypted > 0) {
        ofile.write((char*)outbuf, bytes_decrypted);
    }
    
    //6. clean up
    ofile.close();
    ifile.close();
    rc = 0;
free_data:
    delete [] key;
    delete [] iv;
    return rc;
}

int usage(const char *programname) 
{
    cerr << "Usage: " << programname << " -e/-d <sourcefile> <destfile> <passphrase>" << endl;
    return 1;
}

int main(int argc, char *argv[]) 
{
    if (argc != 5) {
        return usage(argv[0]);
    }

    OpenSSL_add_all_algorithms();

    if (!strcmp(argv[1], "-e")) {
        return encrypt_file(argv[2], argv[3], argv[4]);
    } else if (!strcmp(argv[1], "-d")) { 
        return decrypt_file(argv[2], argv[3], argv[4]);
    } else {
        return usage(argv[0]);
    }

    return 0;
}

