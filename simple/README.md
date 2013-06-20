aes-demo
========

AES encryption/decryption using OpenSSL / C++ and Javascript


1. Edit the C++ code to change encryption and key derivation parameters. Currently the PBKDF2 parameter has a low number of iterations. A minimum of 1000, and a max of many thousand is recommended. The setting is low because the JS library I've used (CryptoJS) doesn't do PBKDF2 very efficiently. 
2. Compile the C++ code using "$ g++/clang++ -o aes aes.cpp -lcrypto"
3. Encrypt a file using "$ aes -e file file.enc passphrase"
4. Decrypt it on the commandline as "$ aes -d file.enc file.dec passphrase"
5. Decrypt it on the browser by loading the encrypted file and entering the pass


Caveats:

1. HTML5 FileReader API may only be supported on Chrome
2. PBKDF2 is slow with CryptoJS. Some folks have reported much better performance with sjcl, so that may be an option.
3. JS crypto where unverified code is sent from the server is a bad idea™. Doing this in an extension would likely be better.
4. Although JS can decrypt a buffer on the page, it appears hard to trigger a file download of the decrypted buffer directly. Options include: (1) base64 encoding the decrypted buf and send it as a data URL; (2) use Downloadify which uses Flash

