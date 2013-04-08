//
//  aes-ccm.cpp
//  Youcrypt
//  Short example of how to use OpenSSL's AES CCM (Authenticated
//  encryption using Counter+CBC-MAC)
//
//
//  Created by Anirudh Ramachandran <avr@nouvou.com> on 4/5/13.
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
    EVP_CIPHER_CTX ctx;
    const EVP_CIPHER *ciph;
    unsigned char inbuf[BUFSIZE], outbuf[BUFSIZE + AES_BLOCK_SIZE<<1]; // specific to AES
    ofstream ofile;
    ifstream ifile;
    int bytes_read, bytes_encrypted, total_bytes_read = 0, total_bytes_encrypted = 0;
    int filesize;
    
    // 1. Open input file
    ifile.open(sourcefile.c_str(), ios::in | ios::binary | ios::ate);
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

    filesize = ifile.tellg();
    ifile.seekg(ios::beg);
    
    // 3. generate salt, key, IV from passphrase using pbkdf2
    unsigned char salt_value[default_pbkdf2_saltlen_];
    unsigned char *key = NULL, *iv = NULL;
    size_t keylen, ivlen;
    keylen = ivlen  = default_keysize_ / 8;

    // auth data
    unsigned char adata[8] = {0}, dummy_tag[16] = {0}, tag[16] = {0};
    size_t adata_len = 8, tag_len = 16;
    int outlen;

    iv = new unsigned char [ivlen];
    std::fill(iv, iv + ivlen, 0); //XXX using a zero IV for now
    
    std::fill(salt_value, salt_value + sizeof(salt_value), 's'); //XXX fixed salt
    key = new unsigned char [keylen];
    if(!PKCS5_PBKDF2_HMAC_SHA1(passphrase.c_str(), passphrase.length(), salt_value,
                              sizeof(salt_value), default_pbkdf2_iterations_,
                               keylen, key)) {
        cerr << "Cannot derive key from password " << endl;
        goto free_data;
    }
    
    // 4. Initialize encryption engine / context / etc.
    EVP_CIPHER_CTX_init(&ctx);
    if (!EVP_EncryptInit(&ctx, EVP_aes_256_ccm(), 0, 0)) {
        cerr << "Cannot initialize encryption cipher with ccm" << endl;
        goto free_data;
    }

    EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_IVLEN, ivlen, 0);
    EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_TAG, tag_len, 0);

    if (!EVP_EncryptInit(&ctx, 0, key, iv)) {
        // returns 0 for failure (wtf?)
        cerr << "Cannot initialize encryption cipher wtih key/iv" << endl;
        goto free_data;
    }

    // set total file size
    if (!EVP_EncryptUpdate(&ctx, 0, &outlen, 0, filesize)) {
        cerr << "Cannot set total file size of " << filesize << endl;
        goto free_data;
    }

    // set addl auth data
    if (!EVP_EncryptUpdate(&ctx, 0, &outlen, adata, adata_len)) {
        cerr << "Cannot set adata " << endl;
        goto free_data;
    }

    // write dummy tag to overwrite later
    ofile.write((char*)dummy_tag, tag_len);

    // 5.2 Read source file block, encrypt, and write to output stream
    while (!ifile.eof()) {
        ifile.read((char*)inbuf, BUFSIZE);
        bytes_read = (int) ifile.gcount(); // cast okay because BUFSIZE < MAX_INT
        if (bytes_read > 0) {
            if (!EVP_EncryptUpdate(&ctx, outbuf, &bytes_encrypted,
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
    EVP_EncryptFinal_ex(&ctx, outbuf, &bytes_encrypted);
    if (bytes_encrypted > 0) {
        ofile.write((char*)outbuf, bytes_encrypted);
    }

    // get tag 
    EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_GET_TAG, tag_len, dummy_tag);
    ofile.seekp(0);
    ofile.write((char*)dummy_tag, tag_len); // overwrite adata
    cerr << "tag written: ";
    for(i = 0; i < tag_len; ++i)
        fprintf(stderr, "%02x", dummy_tag[i]);
    cerr << endl;
    
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
    EVP_CIPHER_CTX ctx;
    const EVP_CIPHER *ciph;
    unsigned char inbuf[BUFSIZE], outbuf[BUFSIZE + AES_BLOCK_SIZE<<1]; // specific to AES
    ofstream ofile;
    ifstream ifile;
    int bytes_read, bytes_decrypted,
        total_bytes_read = 0, total_bytes_decrypted = 0;
    int filesize;
    
    // 1. Open input file
    ifile.open(sourcefile.c_str(), ios::in | ios::binary | ios::ate);
    if (!ifile.is_open()) {
        cerr << "Cannot open input file " << sourcefile << endl;
        return rc;
    }
    
    // 2. Check that output file can be opened and written to
    ofile.open(destfile.c_str(), ios::out | ios::binary | ios::trunc);
    if (!ofile.is_open()) {
        cerr << "Cannot open input file " << sourcefile << endl;
        return rc;
    }

    filesize = ifile.tellg();
    ifile.seekg(ios::beg);
    
    // 3. Derive key from passphrase, create salt and IV
    unsigned char salt_value[default_pbkdf2_saltlen_];
    unsigned char *key = NULL, *iv = NULL; 
    size_t keylen, ivlen;
    keylen = ivlen  = default_keysize_ / 8;

    // auth data
    unsigned char adata[8] = {0}, dummy_tag[16] = {0}, tag[16] = {0};
    size_t adata_len = 8, tag_len = 16;
    int outlen;
    
    iv = new unsigned char [ivlen];
    std::fill(iv, iv + ivlen, 0); //XXX fixed all-zero IV
    std::fill(salt_value, salt_value + sizeof(salt_value), 's'); //XXX fixed salt
    key = new unsigned char [keylen];
    if(!PKCS5_PBKDF2_HMAC_SHA1(passphrase.c_str(), passphrase.length(), salt_value,
                              sizeof(salt_value), default_pbkdf2_iterations_,
                               keylen, key)) {
        cerr << "Cannot derive key from password " << endl;
        goto free_data;
    }
    
    // 4. Initialize decryption engine / context / etc.
    EVP_CIPHER_CTX_init(&ctx);
    if (!EVP_DecryptInit(&ctx, EVP_aes_256_ccm(), 0, 0)) {
        cerr << "Cannot initialize decryption cipher with ccm" << endl;
        goto free_data;
    }

    EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_IVLEN, ivlen, 0);

    ifile.read((char*)tag, tag_len);

    cerr << "tag read: ";
    for(int i = 0; i < tag_len; ++i)
        fprintf(stderr, "%02x", tag[i]);
    cerr << endl;

    EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_TAG, tag_len, tag);

    if (!EVP_DecryptInit(&ctx, 0, key, iv)) {
        // returns 0 for failure (wtf?)
        cerr << "Cannot initialize decryption cipher wtih key/iv" << endl;
        goto free_data;
    }

    if (!EVP_DecryptUpdate(&ctx, 0, &outlen, 0, filesize - tag_len)) {
        cerr << "Cannot set total file size to decrypt : " << filesize -
            adata_len  << endl;
        goto free_data;
    }

    if (!EVP_DecryptUpdate(&ctx, 0, &outlen, adata, adata_len)) {
        cerr << "Cannot set adata " << endl;
        goto free_data;
    }

    // 5.1 Read source blocks, decrypt, write to output stream
    while (!ifile.eof()) {
        ifile.read((char*) inbuf, BUFSIZE);
        bytes_read = (int) ifile.gcount();
        if (bytes_read > 0) {
            if (!EVP_DecryptUpdate(&ctx, outbuf, &bytes_decrypted,
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
    EVP_DecryptFinal_ex(&ctx, outbuf, &bytes_decrypted);
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

