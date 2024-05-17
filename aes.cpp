#include "aes.h"

AES::AES(AES_TYPE type) {
	changeType(type);
}

AES::~AES() {}

void AES::changeType(AES_TYPE type) {
	this->type = type;
	switch (type) {
		case (AES_128):
			Nk = 4;
			Nr = 10;
			break;
		case (AES_192):
			Nk = 6;
			Nr = 12;
			break;
		case (AES_256):
			Nk = 8;
			Nr = 14;
			break;
	}
}

state_t AES::cipherWithDebug(const state_t in, uint8_t Nr, const std::vector<uint32_t> w) {
	uint8_t round = 0;
	state_t state;
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			state[j][i] = in[i][j];
		}
	}
	std::cout << "------roundstart: " << (int)round << "------" << std::endl;
	printState(state);
	addRoundKey(round, state, w);
	round++;
	while (round < this->Nr) {
		std::cout << "------roundstart: " << (int)round << "------" << std::endl;
		subBytes(state);
		printState(state);
		shiftRows(state);
		printState(state);
		mixColumns(state);
		printState(state);
		addRoundKey(round, state, w);
		std::cout << "------roundend: " << (int)round << "------" << std::endl;
		printState(state);
		round++;
	}
	subBytes(state);
	printState(state);
	shiftRows(state);
	printState(state);
	addRoundKey(round, state, w);
	printState(state);
	return state;
}

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

uint8_t SBox(uint8_t byte) {
	byte = SBOX[(byte & 0xf0) >> 4][byte & 0x0f];
	return byte;
}

void AES::subBytes(state_t& state) {
	for (int i = 0; i < STATE_ROWS; i++) {
		for (int j = 0; j < STATE_COLS; j++) {
			state[i][j] = SBox(state[i][j]);
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
			temp[row] = mul(state[0][col], MIXBOX[row][0])
						^ mul(state[1][col], MIXBOX[row][1])
						^ mul(state[2][col], MIXBOX[row][2])
						^ mul(state[3][col], MIXBOX[row][3]);
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
		printf("word: %08x\n", word);
		state[0][col] ^= (uint8_t)((word & 0xff000000) >> 24);
		state[1][col] ^= (uint8_t)((word & 0x00ff0000) >> 16);
		state[2][col] ^= (uint8_t)((word & 0x0000ff00) >> 8);
		state[3][col] ^= (uint8_t)(word & 0x000000ff);
	}
	return ;
}

uint32_t AES::rotWord(uint32_t word) {
	uint32_t head = ((word & 0xff000000) >> 24);
	word <<= 8;
	word |= head;
	return word;
}

//// ポインタずらしで実装しようと思ったがエンディアンの問題があるので断念
//uint32_t AES::subWord(uint32_t word) {
//	uint32_t result = 0;
//	for (uint8_t i = 0; i < 4; i++) {
//		uint8_t byte = (word >> (i * 8)) & 0xff;
//		byte = SBOX[byte & 0xf0][byte & 0x0f];
//		result |= (byte << (i * 8));
//	}
//	return result;
//}

uint32_t AES::subWord(uint32_t word) {
    uint32_t result = 0;
    for (uint8_t i = 0; i < 4; i++) {
        uint8_t byte = (word >> (i * 8)) & 0xff;
		byte = SBox(byte);
        result |= (byte << (i * 8));
    }
    return result;
}


// vectorではなくarrayで、各キー用の長さの型を作り、それをtemplateでやることを目論む。
std::vector<uint32_t> AES::keyExpansion(std::vector<uint32_t> key) {
	std::vector<uint32_t> w(4 * (this->Nr + 1));
	std::cout << "size: " << w.size() << std::endl;

	// 1Word = 4Bytes = 32bits
	// aes128 = 128bits = 16Bytes = 4Word
	int i = 0;
	while (i <= this->Nk - 1) {
		w[i] = key[i];
		printf("%d %08x\n", i, w[i]);
		i++;
	}
	uint32_t temp;
	while (i <= 4 * this->Nr + 3) {
		temp = w[i - 1];
		printf("%d %08x\n", i, temp);
		// AES256に限った処理
		if (this->type == AES_256 && (i + 4) % 8 == 0) {
			w[i] = w[i - this->Nk] ^ subWord(w[i - 1]);
			i++;
			continue;
		}
		else if (i % this->Nk == 0) {
			printf("%d rotword() %08x\n", i, rotWord(temp));
			printf("%d subword() %08x\n", i, subWord(rotWord(temp)));
			printf("%d rcon() %08x\n", i, RCON[i / this->Nk]);
			printf("%d xor with rcon %08x\n", i, subWord(rotWord(temp)) ^ RCON[i / this->Nk]);
			temp = subWord(rotWord((temp))) ^ RCON[i / this->Nk];
		}
		else if (this->Nk > 6 & (i % this->Nk) == 4) {
			temp = subWord(temp);
		}
		w[i] = w[i - this->Nk] ^ temp;
		printf("%d %08x\n", i, temp);
		i++;
	}
	return w;
}

//std::array<std::array<uint8_t, 16>, 16> genInvSBox() {
//	uint8_t value;
//	std::array<std::array<uint8_t, 16>, 16> sbox;
//	sbox = genSBox();
//	std::array<std::array<uint8_t, 16>, 16> invSbox;
//	for (int i = 0; i < 256; ++i) {
//		value = sbox[i / 16][i % 16];
//		invSbox[value / 16][value % 16] = i;
//	}
//	return invSbox;
//}

void AES::printState(state_t state) {
	for (uint8_t i = 0; i < STATE_ROWS; i++) {
		for (uint8_t j = 0; j < STATE_COLS; j++) {
			//print as hex
			printf("%02x ", state[i][j]);
		}
		std::cout << std::endl;
	}
}

