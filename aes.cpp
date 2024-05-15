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

state_t AES::cipher(const state_t in, uint8_t Nr, const std::vector<uint32_t> w) {
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
			state[i][j] = SBOX[(state[i][j] & 0xf0) >> 4][state[i][j] & 0x0f];
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

uint8_t AES::xTimes(uint8_t x) {
	if (x & 0x80) {
		return (x << 1);
	} else {
		return ((x << 1) ^ 0x1B);
	}
}

// dot(x, y=3)
// mask = 0b00000001
// 		product + x
// 		x <- xtimes(x) <=> x <- x・2
// mask = 0b00000010
// 		product + x ・ 2
// return product = x・3
uint8_t AES::dot(uint8_t x, uint8_t y) {
	uint8_t product;

	for (uint8_t mask = 0x01; mask; mask <<= 1) {
		if (y & mask) {
			product ^= x;
		}
		x = xTimes(x);
	}
	return (x);
}

// 2 3 1 1
// 1 2 3 1
// 1 1 2 3
// 3 1 1 2
void AES::mixColumns(state_t& state) {
	std::array<uint8_t, STATE_ROWS> temp;

	for (uint8_t col = 0; col < STATE_COLS; col++) {
		for (uint8_t row = 0; row < STATE_ROWS; row++) {
			temp[row] = dot(state[0][col], MIXBOX[row][col])
						^ dot(state[1][col], MIXBOX[row][col])
						^ dot(state[2][col], MIXBOX[row][col])
						^ dot(state[3][col], MIXBOX[row][col]);
		}
		for (uint8_t row = 0; row < STATE_ROWS; row++) {
			state[row][col] = temp[row];
		}
	}
	return ;
}

void AES::addRoundKey(uint8_t round, state_t& state, const std::vector<uint32_t> w) {
	for (uint8_t col = 0; col < STATE_COLS; col++) {
		uint32_t word = w[STATE_COLS * round + col];
		state[0][col] ^= (uint8_t)((word & 0xff000000) >> 24);
		state[1][col] ^= (uint8_t)((word & 0x00ff0000) >> 16);
		state[2][col] ^= (uint8_t)((word & 0x0000ff00) >> 8);
		state[3][col] ^= (uint8_t)(word & 0x000000ff);
	}
	return ;
}

uint32_t rotWord(uint32_t word) {
	uint32_t head = ((word & 0xff000000) >> 24);
	word <<= 8;
	word &= head;
	return word;
}

// ポインタずらしで実装しようと思ったがエンディアンの問題があるので断念
uint32_t subWord(uint32_t word) {
	uint32_t result = 0;
	for (uint8_t i = 0; i < 4; i++) {
		uint8_t byte = (word >> (i * 8)) & 0xff;
		byte = SBOX[byte & 0xf0][byte & 0x0f];
		result |= (byte << (i * 8));
	}
	return result;
}


// vectorではなくarrayで、各キー用の長さの型を作り、それをtemplateでやるという
std::vector<uint32_t> keyExpansion128(std::vector<uint32_t> key) {
	std::vector<uint32_t> w;
	// 1Word = 4Bytes = 32bits
	// aes128 = 128bits = 16Bytes = 4Word
	int i = 0;
	while (i <= Nk - 1) {
		w.emplace_back(key[i]);
		i++;
	}
	uint32_t temp;
	while (i <= 4 * Nr + 3) {
		temp = w[i - 1];
		if (i % Nk == 0) {
			temp = subWord(rotWord((temp))) ^ RCON[i / Nk];
		}
		else if (Nk > 6 & (i % Nk) == 4) {
			temp = subWord(temp);
		}
		i++;
	}
	return w;
}

std::vector<uint32_t> keyExpansion192(std::vector<uint32_t> key) {
	std::vector<uint32_t> w;
	// 1Word = 4Bytes = 32bits
	// aes128 = 128bits = 16Bytes = 4Word
	int i = 0;
	while (i <= Nk - 1) {
		w.emplace_back(key[i]);
		i++;
	}
	uint32_t temp;
	while (i <= 4 * Nr + 3) {
		temp = w[i - 1];
		if (i % Nk == 0) {
			temp = subWord(rotWord((temp))) ^ RCON[i / Nk];
		}
		else if (Nk > 6 & (i % Nk) == 4) {
			temp = subWord(temp);
		}
		i++;
	}
	return w;
}

std::vector<uint32_t> keyExpansion256(std::vector<uint32_t> key) {
	std::vector<uint32_t> w;
	int i = 0;
	while (i <= Nk - 1) {
		w.emplace_back(key[i]);
		i++;
	}
	uint32_t temp;
	while (i <= 4 * Nr + 3) {
		temp = w[i - 1];
		if (i % Nk == 0) {
			temp = subWord(rotWord((temp))) ^ RCON[i / Nk];
		}
		else if (Nk > 6 & (i % Nk) == 4) {
			temp = subWord(temp);
		}
		i++;
	}
	return w;
}

std::vector<uint32_t> keyExpansion256(std::vector<uint32_t> key) {
	
}


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

