#include "aes.h"

AES::AES(AES_TYPE type) {
	switch (type) {
		case (AES_128):
			Nk = 16;
			Nr = 10;
			break;
		case (AES_192):
			Nk = 24;
			Nr = 12;
			break;
		case (AES_256):
			Nk = 24;
			Nr = 14;
			break;
	}
}

AES::~AES() {}

state_t AES::cipher(const state_t in, uint8_t Nr, const vector<uint32_t> w) {
	state_t state;
	state = in;
	addRoundKey(state, w);
	for (uint8_t round = 1; round < this->Nr; round++) {
		subBytes(state);
		shiftRows(state);
		mixColumns(state);
		addRoundKey(state, w);
	}
	subBytes(state);
	shiftRows(state);
	addRoundKey(state, w);
}

void AES::subBytes(state_t& state) {
{
	for (int i = 0; i < STATE_ROWS; i++) {
		for (int j = 0; j < STATE_COLS; j++) {
			state[i][j] = sbox[(state[i][j] & 0xf0) >> 4][state[i][j] & 0x0f];
		}
	}
	return ;
}

void AES::shiftRows(state_t& state) {
	uint8_t tmp[STATE_COLS];
	for (int row = 1; row < STATE_ROWS; row++) {
		for (int i = 0; i < STATE_COLS; i++) {
			tmp[i] = state[row][(i + row) % STATE_COLS];
		}
		for (int i = 0; i < STATE_COLS; i++) {
			state[row][i] = tmp[i];
		}
	}
	return ;
}

void AES::mixColumns(state_t& state) {
	// 2 3 1 1
	// 1 2 3 1
	// 1 1 2 3
	// 3 1 1 2
	state_t
	return ;
}

//uint8_t mul2(uint8_t s) {
//	if (s > 0x80) {
//		return (val << 1);
//	} else {
//		// 既役多項式 x^8 + x^4 + x^3 + x^1 + 1
//		// 00011011
//		return (val << 1) ^ 0x1B;
//	}
//	
//}
//
//uint8_t mul3(uint8_t s) {
//	
//}


void AES::addRoundKey(uint8_t round, state_t& state, uint8_t w[Nb]) {
	return ;
}


vector<uint32_t> keyExpansion(vector<uint32_t> key);


int main(void) {
	AES aes(AES_128);
	//state_t 4byte * 4byte matrix
	state_t in = {{
		{0x32, 0x43, 0xf6, 0xa8},
		{0x88, 0x5a, 0x30, 0x8d},
		{0x31, 0x31, 0x98, 0xa2},
		{0xe0, 0x37, 0x07, 0x34}
	}};
	aes.shiftRows(in);
	for (int i = 0; i < STATE_ROWS; i++) {
		for (int j = 0; j < STATE_COLS; j++) {
			cout << in[i][j] << " ";
		}
		cout << endl;
	}

	return (0);
}

