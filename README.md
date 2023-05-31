# libacrypt - The Alan's Crypto Library

                             Version 0.1

    libacrypt is a library developed for the Embedded Systems Developer - Spain
    Technical Challenge, it cannot be used by any other purpose.

## Overview

    The libacrypt consists of a cryptography library and a command line program
    using the library to encrypt some user input data.

## Build Instructions

```
    $ make
    $ sudo make install
```

## Build options

    If you want to debug to encrypted byte and want to run again to decrypt
    the context, you can configure the "LIB_DEBUG" macro:

```
    $ make EXTRAFLAG=-DLIB_DEBUG
```

    In case you are compiling for some microprocessor without virtual memory,
    you can disable mmap() support this way:

```
    $ make EXTRAFLAG=-DNOMMAP
```

## Build test

    First you need to build and install Unity:
    http://www.throwtheswitch.org/home

    You can use my local copy:

```
    $ cd test/Unity
    $ mkdir build
    $ cd build
    $ cmake ..
    $ make
    $ sudo make install
```

    Now you can run the test:

```
    $ make test
    cc -o crypt.o -c -fPIC src/crypt.c
    cc -o libacrypt.so -shared crypt.o
    cc -o crypt_main.o -c src/crypt_main.c 
    cc -o crypt crypt_main.o -L. -lacrypt
    cc -o crypt_test.o -c src/crypt_test.c 
    cc -o cryptest crypt_test.o -L. -lacrypt -lunity
    ./cryptest
    libacrypt Version 0.0.1
    src/crypt_test.c:167:run_test_coded1:PASS
    src/crypt_test.c:168:run_test_coded2:PASS
    src/crypt_test.c:169:run_test_coded3:PASS
    src/crypt_test.c:170:run_test_coded4:PASS
    src/crypt_test.c:171:run_test_coded5:PASS

    -----------------------
    5 Tests 0 Failures 0 Ignored 
    OK
```

## Build documentation

```
    $ make doc
```

## Known issues and how to fix

```
    $ ./crypt
    ./crypt: error while loading shared libraries:
    libacrypt.so: cannot open shared object file: No such file or directory
```
    Please run:
```
    $ sudo make install
```

    or alternatively manually copy it and run ldconfig:
```
    $ sudo cp libacrypt.so /usr/local/lib/
    $ sudo ldconfig
```

## Usage examples

```
    $ ./cryp -k "This 1s the s3cr3t" -o /tmp/encrypted.bin

    $ ./cryp -f secret.bin -i /tmp/file.txt -o /tmp/encrypted.bin

    $ cat plain.txt | ./crypt -f /tmp/secret.bin -
    
    $ cat plain.txt | ./crypt -f /tmp/secret.bin - > /tmp/output.bin

    $ cat /tmp/output.bin | ./crypt -f /tmp/secret.bin -
```

## Contact

    See the file AUTHORS.
