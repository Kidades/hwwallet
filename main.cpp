#include "uECC.h"
#include "TX.h"
#include "RLP.h"
#include <stdio.h>
#include <string.h>
#include "keccak256.h"
//#include <ESP8266WiFi.h>
//#include <FS.h>

using namespace std;

#define HASH_LENGTH 32
#define SIGNATURE_LENGTH 64

char* byteArrayToCharArray(uint8_t* bytes, uint8_t len);
uint8_t* charArrayToByteArray(char* string);
void splitArray(uint8_t src[], uint8_t dest[], uint8_t from, uint8_t to);
void keccak256(const uint8_t *data, uint16_t length, uint8_t* result);
void assignAttribute(int pos, string atr, TX* tx);
const char* receiveTransaction(string transaction);
uint8_t* getPublicKey(uint8_t* privatekey);
uint8_t* getAddress(uint8_t* publickey);
const char* signTransaction(TX tx);
void readPrivateKey();
string parseNewKey(string key);
void flashNewKey(string key);

uint8_t privatekey[] = { 0x00,0x31,0x50,0xbe,0x54,0xa8,0xc9,0x87,0xda,0xd7,0xd9,
0x99,0x33,0x9c,0x51,0xf7,0xc2,0x7d,0x47,0x90,0x58,0x9e,0xbe,0x6f,0xf9,0x58,0xd8,0x07,0x87,0xea,0xed,0x52 };
//privatni kljuc za testiranje, prebrisace ga onaj iz memorije

char* byteArrayToCharArray(uint8_t* bytes, uint8_t len) {

  char *ret = new char[len*2 + 1];
  char hexval[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  for(int j = 0; j < len; j++){
    ret[j*2] = hexval[((bytes[j] >> 4) & 0xF)];
    ret[(j*2) + 1] = hexval[(bytes[j]) & 0x0F];
  }
  ret[len*2] = '\0';
  return ret;
}

uint8_t* charArrayToByteArray(char* string) {

    if(string == NULL)
       return NULL;

    size_t slength = strlen(string);
    if((slength % 2) != 0)
       return NULL;

    size_t dlength = slength / 2;

    uint8_t* data = new uint8_t[dlength];
    memset(data, 0, dlength);

    size_t index = 0;
    while (index < slength) {
        char c = string[index];
        int value = 0;
        if(c >= '0' && c <= '9')
            value = (c - '0');
        else if (c >= 'A' && c <= 'F')
            value = (10 + (c - 'A'));
        else if (c >= 'a' && c <= 'f')
             value = (10 + (c - 'a'));
        else {
            delete[] data;
            return NULL;
        }

        data[(index/2)] += value << (((index + 1) % 2) * 4);

        index++;
    }

    return data;
}

void splitArray(uint8_t src[], uint8_t dest[], uint8_t from, uint8_t to)
{
    int i = 0;
	for(int ctr=from; ctr<to; ctr++)
	{
		dest[i]	=  src[ctr];
		i++;
	}
}

string parseNewKey(string key) {
    string delimiter = "|";
    size_t pos = 0;
    string token;
    bool processed = false;
    while ((pos = key.find(delimiter)) != string::npos) {
            token = key.substr(0, pos);
            key.erase(0, pos + delimiter.length());
            if (processed) return token;
            processed = true;
    }
}

/*
//Kod je komentarisan da bi program mogao da se pokrece na racunaru radi testiranja
//Potrebno je skinuti komentare ovde i za includove kada se program flashuje na uredjaj

void setup() {

    Serial.begin(115200);
    readPrivateKey();
}

void loop() {
  String s = Serial.readString();
  s.length();

  if(s.startsWith("ping")) {
    Serial.print("ping");
  }

  if(s.startsWith("TX|")) {
    Serial.print(receiveTransaction(s));
  }

  if(s.startsWith("getAddress")) {
    Serial.print(getAddress(getPublicKey(privatekey)));
  }

  if(s.startsWith("FLASH|")) {
    flashNewKey(parseNewKey(s));
    Serial.print("success");
  }

}

void readPrivateKey() {
    SPIFFS.begin();
    File f = SPIFFS.open("/privkey.txt", "r");

    if(f.available()) {
        f.readBytes((char*)privatekey, 32);
    }

    f.close();
    SPIFFS.end();
}


void flashNewKey(string key) {
    SPIFFS.begin();
    File f = SPIFFS.open("/privkey.txt", "w");
    f.write(charArrayToByteArray(key.c_str()), 32);
    f.close();
    SPIFFS.end();

    readPrivateKey();
}

*/


int main(int argc, char** argv) {
    printf("Public key: %s\n\n", byteArrayToCharArray(getPublicKey(privatekey), 64));
    printf("Address: %s\n\n", byteArrayToCharArray(getAddress(getPublicKey(privatekey)), 20));
    receiveTransaction("0x07|0x01a13b8600|0x5208|0x8f9ad0411a887c3243bcded341ed63f90b3e1417|0x11c37937e08000|0x");
    fgetc(stdin);
}

const char* signTransaction(TX tx) {
    RLP rlp;
    string enc = rlp.encode(tx, true);

    printf("Raw TX encode: %s\n\n", rlp.bytesToHex(enc).c_str());

    uint8_t *hashval = new uint8_t[HASH_LENGTH];
    keccak256((uint8_t*)(enc.c_str()), enc.size(), hashval);

    printf("Hash: %s\n\n", byteArrayToCharArray(hashval, HASH_LENGTH));

    uint8_t* signature = new uint8_t[SIGNATURE_LENGTH];

    uECC_sign(privatekey,hashval, HASH_LENGTH, signature, uECC_secp256k1());

    printf("Signature: %s\n", byteArrayToCharArray(signature, 64));

    uint8_t *r = new uint8_t[32];
    uint8_t *s = new uint8_t[32];
    splitArray(signature,r,0,32);
    splitArray(signature,s,32,64);

    tx.r = string("0x") + byteArrayToCharArray(r, 32);
    tx.s = string("0x") + byteArrayToCharArray(s, 32);
    tx.v = "0x1b"; //V moze da se izracuna na racunaru

    printf("\nR: %s", tx.r.c_str());
    printf("\nS: %s\n", tx.s.c_str());

    int result = uECC_verify(getPublicKey(privatekey), hashval, 32, charArrayToByteArray("04d2f052327b9f1ee027309f29a9d8118fcde92cdb9c5fb514132b5de8aee695d3a53155010b2779e5c956a24dd7e25c1a8ba3804494be5ad0953efc568764fe"), uECC_secp256k1());
    printf("\nSig match: %s", result ? "true" : "false");



    string encoded = rlp.bytesToHex(rlp.encode(tx, false));
    printf("\nTX length: %d\n\nTX: 0x%s\n",encoded.size(), encoded.c_str());
    return encoded.c_str();
}

//SHA-3
void keccak256(const uint8_t *data, uint16_t length, uint8_t* result) {

    SHA3_CTX context;
    keccak_init(&context);
    keccak_update(&context, (const unsigned char*)data, (size_t)length);
    keccak_final(&context, (unsigned char*)result);

    memset((char*)&context, 0, sizeof(SHA3_CTX));
}

uint8_t* getPublicKey(uint8_t* privatekey) {
    uint8_t *publickey = new uint8_t[64];
    uECC_compute_public_key(privatekey, publickey, uECC_secp256k1());

    return publickey;
}

uint8_t* getAddress(uint8_t* publickey) {

    uint8_t *address = new uint8_t[20];
    uint8_t *pubhash = new uint8_t[64];
    keccak256(publickey, 64, pubhash);
    memcpy(address, &pubhash[12], 20);
    return address;
}

const char* receiveTransaction(string s) {
    string delimiter = "|";

    TX* tx = new TX();

    size_t pos = 0;
    string token;
    int i = 0;
    while ((pos = s.find(delimiter)) != string::npos) {
        token = s.substr(0, pos);
        assignAttribute(i, token, tx);
        s.erase(0, pos + delimiter.length());
        i++;
    }
    assignAttribute(i, s, tx);

    return signTransaction(*tx);
}

void assignAttribute(int pos, string atr, TX* tx) {
    switch(pos) {
        case 1: tx->nonce = atr; break;
        case 2: tx->gasPrice = atr; break;
        case 3: tx->gasLimit = atr; break;
        case 4: tx->to = atr; break;
        case 5: tx->value = atr; break;
        case 6: tx->data = atr; break;
    }
}
