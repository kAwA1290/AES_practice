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
	uint8_t round = 0;
	state_t state;
	state = in;
	addRoundKey(round, state, w);
	while (round < this->Nr) {
		subBytes(state);
		shiftRows(state);
		mixColumns(state);
		addRoundKey(round, state, w);
		round++;
	}
	subBytes(state);
	shiftRows(state);
	addRoundKey(round, state, w);
	return state;
}

void AES::subBytes(state_t& state) {
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
		return ((x << 1) ^ irreducible);
	}
}

// mul(x, y=3)
// mask = 0b00000001
// 		product + x
// 		x <- xtimes(x) <=> x <- x・2
// mask = 0b00000010
// 		product + x ・ 2
// return product = x・3
uint8_t AES::mul(uint8_t x, uint8_t y) {
	uint8_t product = 0;

	for (uint8_t mask = 0x01; mask; mask <<= 1) {
		if (y & mask) {
			product ^= x;
		}
		x = xTimes(x);
	}
	return (product);
}


// 2 3 1 1
// 1 2 3 1
// 1 1 2 3
// 3 1 1 2
void AES::mixColumns(state_t& state) {
	std::array<uint8_t, STATE_ROWS> temp;

	for (uint8_t col = 0; col < STATE_COLS; col++) {
		for (uint8_t row = 0; row < STATE_ROWS; row++) {
			temp[row] = mul(state[0][col], MIXBOX[row][col])
						^ mul(state[1][col], MIXBOX[row][col])
						^ mul(state[2][col], MIXBOX[row][col])
						^ mul(state[3][col], MIXBOX[row][col]);
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

// vectorではなくarrayで、各キー用の長さの型を作り、それをtemplateでやることを目論む。
std::vector<uint32_t> AES::keyExpansion(std::vector<uint32_t> key) {
	std::vector<uint32_t> w(4 * (Nr + 1));
	// 1Word = 4Bytes = 32bits
	// aes128 = 128bits = 16Bytes = 4Word
	int i = 0;
	while (i <= Nk - 1) {
		w.emplace_back(key[i]);
		i++;
	}
	uint32_t temp;
	std::cout << i << std::endl;
	while (i <= 4 * Nr + 3) {
		temp = w[i - 1];
		std::cout << i << ": " << temp << std::endl;
		if (i % Nk == 0) {
			temp = subWord(rotWord((temp))) ^ RCON[i / Nk];
		}
		else if (Nk > 6 & (i % Nk) == 4) {
			temp = subWord(temp);
		}
		w[i] = w[i - Nk] ^ temp;
		i++;
		std::cout << i << ": " << temp << std::endl;
	}
	return w;
}

// mul関数の別種類の実装
uint8_t gfMul(uint8_t a, uint8_t b) {
	uint8_t result = 0;

	for (int i = 0; i < 8; i++) {
		if (b & 0x01) {
			result ^= a;
		}
		bool isover = (a & 0x80);
		a <<= 1;
		if (isover) a ^= irreducible;
		b >>= 1;
	}
	return (result);
}

// 拡張ユークリッド法による逆原計算
// example:
// 0x03 * 0x0b = 0x01
uint8_t gfInv(uint8_t byte) {
	if (!byte) {
		return (0);
	}
	uint8_t r0 = byte;
	uint8_t r1 = irreducible;
	uint8_t s0 = 1;
	uint8_t s1 = 0;

	while (r1 != 0) {
		uint8_t q = r0 / r1;
		uint8_t r = r0 % r1;
		r0 = r1;
		r1 = r;
		uint8_t s = s0 ^ gfMul(q, s1);
		s0 = s1;
		s1 = s;
	}
	return (0);
}

uint8_t affineTransform(uint8_t byte) {
    uint8_t result = byte;
    result ^= (byte << 1) ^ (byte << 2) ^ (byte << 3) ^ (byte << 4);
    result = (result ^ (result >> 8)) & 0xFF; // 8ビットに制限
    result ^= 0x63; // 固定値の加算
    return result;
}

std::array<std::array<uint8_t, 16>, 16> genSBox() {
	uint8_t inverse;
	uint8_t value;
	std::array<std::array<uint8_t, 16>, 16> sbox;
	for (int i = 0; i < 256; ++i) {
		inverse = gfInv(i);
		value = affineTransform(inverse);
		sbox[i / 16][i % 16] = value;
	}
	return sbox;
}

std::array<std::array<uint8_t, 16>, 16> genInvSBox() {
	uint8_t value;
	std::array<std::array<uint8_t, 16>, 16> sbox;
	sbox = genSBox();
	std::array<std::array<uint8_t, 16>, 16> invSbox;
	for (int i = 0; i < 256; ++i) {
		value = sbox[i / 16][i % 16];
		invSbox[value / 16][value % 16] = i;
	}
	return invSbox;
}

int main(void) {
	state_t res;
	AES aes(AES_128);
	//state_t 4byte * 4byte matrix
	state_t in = {{
		{0x32, 0x43, 0xf6, 0xa8},
		{0x88, 0x5a, 0x30, 0x8d},
		{0x31, 0x31, 0x98, 0xa2},
		{0xe0, 0x37, 0x07, 0x34}
	}};
	std::vector<uint32_t> key = {0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c};
	std::vector<uint32_t> w = aes.keyExpansion(key);
	for (int i = 0; i < 40; i++) {
		printf("%08x\n", w[i]);
	}
	res = aes.cipher(in, aes.Nr, w);
	for (int i = 0; i < STATE_ROWS; i++) {
		for (int j = 0; j < STATE_COLS; j++) {
			printf("%02x ", res[i][j]);
		}
		printf("\n");
	}
	return (0);
}

