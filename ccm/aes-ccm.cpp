//
//  aes-ccm.cpp
//
//  Short example of how to use OpenSSL's AES CCM (Authenticated
//  encryption using Counter + CBC-MAC)
//  Created by Anirudh Ramachandran <avr@nouvou.com> on 4/5/13.
//  Copyright (c) 2013 Nouvou Inc. All rights reserved.
//
//  Compile: g++/clang++ -g -I /opt/local/include/ -L/opt/local/lib aes-ccm.cpp  -lcrypto -lssl -lboost_filesystem-mt -lboost_system-mt  -lboost_iostreams-mt
//

#include <cstring>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <boost/filesystem.hpp>
#include <boost/iostreams/device/mapped_file.hpp>
#include <boost/iostreams/stream.hpp>

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
namespace bf = boost::filesystem;
namespace bi = boost::iostreams;

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
    int bytes_read, bytes_encrypted, total_bytes_read = 0, total_bytes_encrypted = 0;
    int filesize = 0;

    // find filesize
    bf::path inpath(sourcefile);
    if (bf::exists(inpath)) {
        filesize = bf::file_size(inpath);
    } else {
        cerr << "Input file not openable" << endl;
        return rc;
    }
    
    bi::mapped_file_sink imapped_file;
    bi::mapped_file_source omapped_file;
    bi::mapped_file_params iparams, oparams;
    bi::mapped_file_source ifile;
    bi::mapped_file_sink  ofile;

    // generate salt, key, IV from passphrase using pbkdf2
    unsigned char salt_value[default_pbkdf2_saltlen_];
    unsigned char *key = NULL, *iv = NULL;
    size_t keylen, ivlen;
    keylen = default_keysize_ / 8;
    ivlen = keylen / 2; // half of default keysize

    // auth data
    const char *adata = "";
    unsigned char dummy_tag[16] = {0}, tag[16] = {0};
    size_t tag_len = 16;
    int outlen;

    char *output_ptr;
    const char *input_ptr;

    // Open input file
    iparams.path = sourcefile;
    iparams.length = filesize;
    ifile.open(iparams);
    if (!ifile.is_open()) {
        cerr << "Cannot mmap input file " << sourcefile << endl;
        return rc;
    }
    
    // Check that output file can be opened and written
    oparams.path = destfile;
    oparams.new_file_size = filesize + tag_len;
    ofile.open(oparams);
    if (!ofile.is_open()) {
        cerr << "Cannot mmap output file " << destfile << endl;
        return rc;
    }


    iv = new unsigned char [ivlen];
    std::fill(iv, iv + ivlen, 0); //XXX using a zero IV for now
    
    std::fill(salt_value, salt_value + sizeof(salt_value), 's'); //XXX fixed salt
    key = new unsigned char [keylen];
    if(!PKCS5_PBKDF2_HMAC(passphrase.c_str(), passphrase.length(), salt_value,
                              sizeof(salt_value), default_pbkdf2_iterations_, EVP_sha256(),
                               keylen, key)) {
        cerr << "Cannot derive key from password " << endl;
        goto free_data;
    }

    cerr << "PBKDF2 output for " << passphrase << ": ";
    for(i = 0; i < keylen; ++i)
        fprintf(stderr, "%02x", key[i]);
    cerr << endl;

    
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
    if (!EVP_EncryptUpdate(&ctx, 0, &outlen, (unsigned char*)adata, strlen(adata))) {
        cerr << "Cannot set adata " << endl;
        goto free_data;
    }

    output_ptr = ofile.data();
    input_ptr  = ifile.data();

    // 5.2 Read source file block, encrypt, and write to output stream
    if (!EVP_EncryptUpdate(&ctx, (unsigned char*) output_ptr, &bytes_encrypted,
                (const unsigned char*) input_ptr, filesize)) {
        cerr << "Error encrypting chunk " << endl;
        goto free_data;
    }
    cerr << bytes_encrypted << " bytes encrypted" << endl;
    output_ptr += bytes_encrypted;

    // 5.3 Encrypt and write final block of input
    EVP_EncryptFinal(&ctx, (unsigned char*) output_ptr, &bytes_encrypted);

    // get tag 
    EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_GET_TAG, tag_len, dummy_tag);
    // overwrite end of output with real tag
    memcpy((unsigned char *)output_ptr + bytes_encrypted, dummy_tag, tag_len);
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
    int bytes_read, bytes_decrypted, total_bytes_read = 0, total_bytes_decrypted = 0;
    int filesize;

    // find filesize
    bf::path inpath(sourcefile);
    if (bf::exists(inpath)) {
        filesize = bf::file_size(inpath);
    } else {
        cerr << "Input file not openable" << endl;
        return rc;
    }

    
    bi::mapped_file_sink imapped_file;
    bi::mapped_file_source omapped_file;
    bi::mapped_file_params iparams, oparams;
    bi::mapped_file_source ifile;
    bi::mapped_file_sink  ofile;

    // Derive key from passphrase, create salt and IV
    unsigned char salt_value[default_pbkdf2_saltlen_];
    unsigned char *key = NULL, *iv = NULL; 
    size_t keylen, ivlen;
    keylen = default_keysize_ / 8;
    ivlen = keylen / 2;

    // auth data
    const char *adata = "";
    unsigned char dummy_tag[16] = {0}, tag[16] = {0};
    size_t tag_len = 16;
    int outlen;

    char *output_ptr;
    const char *input_ptr;
    unsigned char *tag_begin;

    assert(filesize > tag_len);

    // 1. Open input file
    iparams.path = sourcefile;
    iparams.length = filesize;
    ifile.open(iparams);
    if (!ifile.is_open()) {
        cerr << "Cannot mmap input file " << sourcefile << endl;
        return rc;
    }
    
    // 2. Check that output file can be opened and written
    oparams.path = destfile;
    oparams.new_file_size = filesize - tag_len;
    ofile.open(oparams);
    if (!ofile.is_open()) {
        cerr << "Cannot mmap output file " << destfile << endl;
        return rc;
    }
    
    iv = new unsigned char [ivlen];
    std::fill(iv, iv + ivlen, 0); //XXX fixed all-zero IV
    std::fill(salt_value, salt_value + sizeof(salt_value), 's'); //XXX fixed salt
    key = new unsigned char [keylen];
    if(!PKCS5_PBKDF2_HMAC(passphrase.c_str(), passphrase.length(), salt_value,
                              sizeof(salt_value), default_pbkdf2_iterations_,
                              EVP_sha256(), keylen, key)) {
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

    input_ptr = ifile.data();
    output_ptr = ofile.data();

    cerr << "tag read: ";
    tag_begin = (unsigned char*)(input_ptr + filesize - tag_len);
    for(int i = 0; i < tag_len; ++i)
        fprintf(stderr, "%02x", (unsigned char)tag_begin[i]);
    cerr << endl;

    EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_TAG, tag_len, (void*)tag_begin);

    if (!EVP_DecryptInit(&ctx, 0, key, iv)) {
        // returns 0 for failure (wtf?)
        cerr << "Cannot initialize decryption cipher wtih key/iv" << endl;
        goto free_data;
    }

    if (!EVP_DecryptUpdate(&ctx, 0, &outlen, 0, filesize - tag_len)) {
        cerr << "Cannot set total file size to decrypt : " << filesize - tag_len  << endl;
        goto free_data;
    }

    if (!EVP_DecryptUpdate(&ctx, 0, &outlen, (unsigned char*)adata, strlen(adata))) {
        cerr << "Cannot set adata " << endl;
        goto free_data;
    }

    // input_ptr += tag_len;

    // 5.1 Read source blocks, decrypt, write to output stream
    if (!EVP_DecryptUpdate(&ctx, (unsigned char*) output_ptr, &bytes_decrypted,
                (const unsigned char*) input_ptr, filesize - tag_len)) {
        cerr << "Error decrypting chunk " << endl;
        goto free_data;
    }

    cerr << bytes_decrypted << " bytes decrytped" << endl;
    output_ptr += bytes_decrypted;
    // 5.2 Encrypt remaining data and write final block of output
    EVP_DecryptFinal(&ctx, (unsigned char*)output_ptr, &bytes_decrypted);
    
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
        //return encrypt_file("/tmp/foo", "/tmp/foo.enc", "asdfgh123");
        return encrypt_file(argv[2], argv[3], argv[4]);
    } else if (!strcmp(argv[1], "-d")) { 
        return decrypt_file(argv[2], argv[3], argv[4]);
    } else {
        return usage(argv[0]);
    }

    return 0;
}

