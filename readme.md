# DiSE

This repository contains the reference implementation of [DiSE: Distributed Symmetric-key Encryption](https://eprint.iacr.org/2018/727). This is only a proof of concept implementation and should not be considered production grade. Use at your own risk. 

Threshold cryptography provides a mechanism for protecting secret keys by sharing them among multiple parties, who then jointly perform cryptographic operations. An attacker who corrupts upto a threshold number of parties cannot recover the secrets or violate security. Prior works in this space have mostly focused on definitions and constructions for public-key cryptography and digital signatures, and thus do not capture the security concerns and efficiency challenges of symmetric-key based applications which commonly use long-term (unprotected) master keys to protect data at rest, authenticate clients on enterprise networks, and secure data and payments on IoT devices.

We propose a generic construction of threshold authenticated encryption based on any distributed pseudorandom function (DPRF). When instantiated with the two different DPRF constructions proposed by Naor, Pinkas and Reingold (Eurocrypt 1999) and our enhanced versions, we obtain several efficient constructions meeting different security definitions. We implement these variants and provide extensive performance comparisons. Our most efficient instantiation uses only symmetric-key primitives and achieves a throughput of upto 1 million encryptions/decryptions per seconds, or alternatively a sub-millisecond latency with upto 18 participating parties.


## Build Instructions

### Part 1: clone the dependencies               
Set the parent directory that we will build in
```
git clone https://github.com/visa/dise.git
git clone https://github.com/relic-toolkit/relic.git
git clone https://github.com/ladnir/cryptoTools
```

We require the code has the following structure 
```
$BUILD_DIR/cryptoTools/
$BUILD_DIR/dise/
```

### Part 2: Build and install Relic              

```
cd relic

cmake . -D MULTI=PTHREAD
make -j
sudo make install
```

On windows you can build relic with `-D MULTI=OPENMP`.

Note, you can install to a non-sudo location by calling `make DESTDIR=<path/to/install> install`


### Part 3: build boost and cryptoTools          
```
cd ../cryptoTools/thirdparty/linux
bash boost.get
cd ../..
cmake . -D ENABLE_RELIC=ON 
make -j
```


### Part 4: build DiSE                           
```
cd ../dise
cmake .
make -j
```

Run the unit tests `./bin/dEncFrontent -u`.
