#ifndef AES_H
#define AES_H

#include <iostream>
using namespace std;

typedef unsigned char uint8_t;
#define BLOCKLEN 128;

class AES {
public:
	uint8_t cipher(uint8_t in[BLOCKLEN], uint8_t Nr, uint8_t w[BLOCKLEN]);
}

#endif
