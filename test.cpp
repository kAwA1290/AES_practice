#include "aes.h"
#include <assert.h>

int test_cipher(AES_TYPE type) {
	AES aes(type);
	state_t res;
	std::vector<uint32_t> key;
	state_t in = {{
		{0x32, 0x43, 0xf6, 0xa8},
		{0x88, 0x5a, 0x30, 0x8d},
		{0x31, 0x31, 0x98, 0xa2},
		{0xe0, 0x37, 0x07, 0x34}
	}};
	switch (type){
		case AES_128:
			key = {0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c};
			break;
		case AES_192:
			key = {0x8e73b0f7, 0xda0e6452, 0xc810f32b, 0x809079e5, 0x62f8ead2, 0x522c6b7b};
			break;
		case AES_256:
			key = {0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4};
	}
	std::vector<uint32_t> w = aes.keyExpansion(key);
	res = aes.cipherWithDebug(in, aes.Nr, w);
	std::cout << "Result: " << std::endl;
	for (int i = 0; i < STATE_ROWS; i++) {
		for (int j = 0; j < STATE_COLS; j++) {
			printf("%02x ", res[i][j]);
		}
		printf("\n");
	}
	return (0);
}

void test_rotWord(AES aes) {
	uint32_t word = 0x12345678;
	uint32_t result = aes.rotWord(word);
	assert(result == 0x34567812);
	result = aes.rotWord(result);
	assert(result == 0x56781234);
}

void test_subWord(AES aes) {
	uint32_t word = 0xcf4f3c09;
	uint32_t result = aes.subWord(word);
	assert(result == 0x8a84eb01);
}

void test_mixColumns(AES aes) {
	state_t state = {{
		{0xd4, 0xe0, 0xb8, 0x1e},
		{0xbf, 0xb4, 0x41, 0x27},
		{0x5d, 0x52, 0x11, 0x98},
		{0x30, 0xae, 0xf1, 0xe5}
	}};
	state_t result = {{
		{0x04, 0xe0, 0x48, 0x28},
		{0x66, 0xcb, 0xf8, 0x06},
		{0x81, 0x19, 0xd3, 0x26},
		{0xe5, 0x9a, 0x7a, 0x4c}
	}};
	aes.mixColumns(state);
	assert(state == result);
}

int main() {
	//test_mixColumns(aes);
	test_cipher(AES_256);
	//test_cipher(AES_192);
	
	//test_genSBox(aes);
	//test_rotWord(aes);
	//test_subWord(aes);
}
