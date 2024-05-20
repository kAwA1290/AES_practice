#include "aes.h"
#include <assert.h>

int test_cipher(AES_KeyLength len) {
	AES aes(len);
	std::vector<uint32_t> key;
	// in = 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16
	// state = 1 5 9 13
	//         2 6 10 14
	//         3 7 11 15
	//         4 8 12 16
	state_t in = {{
		{0x32, 0x88, 0x31, 0xe0},
		{0x43, 0x5a, 0x31, 0x37},
		{0xf6, 0x30, 0x98, 0x07},
		{0xa8, 0x8d, 0xa2, 0x34}
	}};
	state_t encrypted_128 = {{
		{0x39, 0x02, 0xdc, 0x19},
		{0x25, 0xdc, 0x11, 0x6a},
		{0x84, 0x09, 0x85, 0x0b},
		{0x1d, 0xfb, 0x97, 0x32}
	}};
	switch (len){
		case AES_128:
			key = {0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c};
			break;
		case AES_192:
			key = {0x8e73b0f7, 0xda0e6452, 0xc810f32b, 0x809079e5, 0x62f8ead2, 0x522c6b7b};
			break;
		case AES_256:
			key = {0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4};
	}
	state_t encrypted_res, decrypted_res;
	encrypted_res = aes.cipherWithDebug(in, aes.keyExpansion(key));
	std::cout << "EncryptResult: " << std::endl;
	aes.printState(encrypted_res);
	decrypted_res = aes.invCipherWithDebug(encrypted_res, aes.keyExpansion(key));
	std::cout << "DecryptResult: " << std::endl;
	aes.printState(decrypted_res);
	if (len == AES_128) assert(encrypted_128 == encrypted_res);
	assert(in == decrypted_res);
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

void test_cipherECB(AES aes) {
	std::string data = "1111111111111111";
	std::vector<uint32_t> key = {0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c};
	std::string result = aes.encryptECB(data, key);
	std::string result2 = aes.decryptECB(result, key);
	for (char c : result) {
		printf("%02x", c);
	}
	printf("\n");
	for (char c : result2) {
		printf("%c", c);
	}
	assert(data == result2);
}

int main() {
	AES aes(AES_128);
	test_cipherECB(aes);
	test_rotWord(aes);
	test_subWord(aes);
	test_mixColumns(aes);
	test_cipher(AES_128);
	test_cipher(AES_192);
	test_cipher(AES_256);
}
