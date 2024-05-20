#include "aes.h"

AES::AES(AES_KeyLength len) {
	changeType(len);
}

AES::~AES() {}

void AES::changeType(AES_KeyLength len) {
	this->keyLen = len;
	switch (len) {
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

state_t AES::cipher(state_t state, const std::vector<uint32_t> w) {
	uint8_t round = 0;
	addRoundKey(round, state, w);
	round++;
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

state_t AES::cipherWithDebug(state_t state, const std::vector<uint32_t> w) {
	uint8_t round = 0;
	std::cout<<"#######CIPHERSTART#######"<<std::endl;
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
	std::cout<<"#######CIPHEREND#######"<<std::endl;
	return state;
}

state_t AES::invCipher(state_t state, const std::vector<uint32_t> w) {
	uint8_t round = this->Nr;
	addRoundKey(round, state, w);
	round--;
	while (round > 0) {
		shiftRows(state, true);
		subBytes(state, true);
		// addRoundKeyとmixColumnsが、cipherとは逆であることに注意
		addRoundKey(round, state, w);
		mixColumns(state, true);
		round--;
	}
	shiftRows(state, true);
	subBytes(state, true);
	addRoundKey(round, state, w);
	return state;
}

state_t AES::invCipherWithDebug(state_t state, const std::vector<uint32_t> w) {
	std::cout<<"#######INVCIPHERSTART#######"<<std::endl;
	uint8_t round = this->Nr;
	std::cout << "------roundstart: " << (int)round << "------" << std::endl;
	printState(state);
	addRoundKey(round, state, w);
	round--;
	while (round >= 1) {
		std::cout << "------roundstart: " << (int)round << "------" << std::endl;
		printState(state);
		shiftRows(state, true);
		printState(state);
		subBytes(state, true);
		printState(state);
		addRoundKey(round, state, w);
		printState(state);
		mixColumns(state, true);
		std::cout << "------roundend: " << (int)round << "------" << std::endl;
		printState(state);
		round--;
	}
	shiftRows(state, true);
	printState(state);
	subBytes(state, true);
	printState(state);
	addRoundKey(round, state, w);
	printState(state);
	std::cout<<"#######INVCIPHEREND#######"<<std::endl;
	return state;
}

uint8_t AES::SBox(uint8_t byte, bool inverse/* = false*/) {
	if (inverse) {
		byte = INV_SBOX[(byte & 0xf0) >> 4][byte & 0x0f];
	}
	else {
		byte = SBOX[(byte & 0xf0) >> 4][byte & 0x0f];
	}
	return byte;
}

void AES::subBytes(state_t& state, bool inverse/* = false*/) {
	for (int i = 0; i < STATE_ROWS; i++) {
		for (int j = 0; j < STATE_COLS; j++) {
			if (inverse) {
				state[i][j] = SBox(state[i][j], true);
			}
			else {
				state[i][j] = SBox(state[i][j]);
			}
		}
	}
	return ;
}

void AES::shiftRows(state_t& state, bool inverse/* = false*/) {
	std::array<uint8_t, STATE_COLS> tmp;
	for (int row = 1; row < STATE_ROWS; row++) {
		for (int col = 0; col < STATE_COLS; col++) {
			if (inverse) {
				// shift to the right
				tmp[(col + row) % STATE_COLS] = state[row][col];
			}
			else {
				// shift to the left
				tmp[col] = state[row][(col + row) % STATE_COLS];
			}
		}
		for (int col = 0; col < STATE_COLS; col++) {
			state[row][col] = tmp[col];
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
void AES::mixColumns(state_t& state, bool inverse/* = false()*/) {
	std::array<uint8_t, STATE_ROWS> temp;

	for (uint8_t col = 0; col < STATE_COLS; col++) {
		for (uint8_t row = 0; row < STATE_ROWS; row++) {
			if (inverse) {
				temp[row] = mul(state[0][col], INV_MIXBOX[row][0])
							^ mul(state[1][col], INV_MIXBOX[row][1])
							^ mul(state[2][col], INV_MIXBOX[row][2])
							^ mul(state[3][col], INV_MIXBOX[row][3]);
			}
			else {
				temp[row] = mul(state[0][col], MIXBOX[row][0])
							^ mul(state[1][col], MIXBOX[row][1])
							^ mul(state[2][col], MIXBOX[row][2])
							^ mul(state[3][col], MIXBOX[row][3]);
			}
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
		//printf("round: %d col: %d roundkey: %08x\n", (int)round, (int)col, word);
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

uint32_t AES::subWord(uint32_t word) {
    uint32_t result = 0;
    for (uint8_t i = 0; i < 4; i++) {
        uint8_t byte = (word >> (i * 8)) & 0xff;
		byte = SBox(byte);
        result |= (byte << (i * 8));
    }
    return result;
}

std::vector<uint32_t> AES::keyExpansion(std::vector<uint32_t> key) {
	std::vector<uint32_t> w(4 * (this->Nr + 1));

	// 1Word = 4Bytes = 32bits
	// aes128 = 128bits = 16Bytes = 4Word
	int i = 0;
	while (i <= this->Nk - 1) {
		w[i] = key[i];
		i++;
	}
	uint32_t temp;
	while (i <= 4 * this->Nr + 3) {
		temp = w[i - 1];
		// AES256に限った処理
		if (this->keyLen == AES_256 && (i + 4) % 8 == 0) {
			w[i] = w[i - this->Nk] ^ subWord(w[i - 1]);
			i++;
			continue;
		}
		else if (i % this->Nk == 0) {
			temp = subWord(rotWord((temp))) ^ RCON[i / this->Nk];
		}
		else if (this->Nk > 6 & (i % this->Nk) == 4) {
			temp = subWord(temp);
		}
		w[i] = w[i - this->Nk] ^ temp;
		i++;
	}
	return w;
}

void AES::printState(state_t state) {
	for (uint8_t i = 0; i < STATE_ROWS; i++) {
		for (uint8_t j = 0; j < STATE_COLS; j++) {
			printf("%02x ", state[i][j]);
		}
		std::cout << std::endl;
	}
	return ;
}

bool AES::keyIsValid(std::vector<uint32_t> key) {
	return key.size() == this->Nk;
}

// PKCS
void AES::padding(state_t& state, uint8_t row, uint8_t col) {
	uint8_t padding = 0x10 - (row * STATE_COLS + col);
	uint8_t cnt = row * STATE_COLS + col;
	while (cnt < STATE_ROWS * STATE_COLS) {
		state[cnt / STATE_COLS][cnt % STATE_COLS] = padding;
		cnt++;
	}
	return ;
}

std::pair<uint8_t, uint8_t> AES::findPadding(state_t& state) {
	std::pair<uint8_t, uint8_t> padding;
	uint8_t size = state[STATE_ROWS - 1][STATE_COLS - 1];
	uint8_t cnt = size;
	for (int row = STATE_ROWS - 1; row >= 0; row--) {
		for (int col = STATE_COLS - 1; col >= 0; col--) {
			// paddingの値がsizeと一致しない場合、paddingが不正であると判断
			if (state[row][col] != size) {
				throw std::runtime_error("Error: invalid padding type!");
			}
			cnt--;
			// paddingの値がsizeと一致した場合、paddingの終端と判断
			if (cnt == 0) {
				padding = std::make_pair(row, col);
				return padding;
			}
		}
	}
	// unreachable
	return padding;
}

// string or vector<uint8_t> to vector<state_t>
template<typename T>
typename std::enable_if<std::is_same<T, std::string>::value || std::is_same<T, std::vector<uint8_t>>::value, std::vector<state_t>>::type
AES::toBlocks(T data, bool paddingEnabled/* = true*/) {
	std::vector<state_t> blocks;
	state_t block;
	size_t len = data.size();
	size_t i = 0;
	while (i < len) {
		for (uint8_t row = 0; row < STATE_ROWS; row++) {
			for (uint8_t col = 0; col < STATE_COLS; col++) {
				block[row][col] = data[i];
				if (i == len - 1 && paddingEnabled) {
					// もしpaddingする余地がない場合、0x10で埋めた終端blockを追加
					if (row == STATE_ROWS - 1 && col == STATE_COLS - 1) {
						blocks.push_back(block);
						padding(block, 0, 0);
						blocks.push_back(block);
					} else {
						padding(block, row, col);
						blocks.push_back(block);
					}
					return blocks;
				}
				i++;
			}
		}
		blocks.push_back(block);
	}
	// unreachable
	return blocks;
}


std::string AES::encryptECB(std::string data, std::vector<uint32_t> key) {
	if (!keyIsValid(key)) {
		throw std::runtime_error("Error: encryptECB called with invalid key!");
	}
	std::vector<state_t> blocks = toBlocks(data);
	std::vector<uint32_t> w = keyExpansion(key);
	std::string result;
	state_t encrypted;
	for (state_t block : blocks) {
		encrypted = cipher(block, w);
		for (uint8_t i = 0; i < STATE_ROWS; i++) {
			for (uint8_t j = 0; j < STATE_COLS; j++) {
				result.push_back(encrypted[i][j]);
			}
		}
	}
	return result;
}

std::string AES::decryptECB(std::string data, std::vector<uint32_t> key) {
	if (!keyIsValid(key)) {
		throw std::runtime_error("Error: decryptECB called with invalid key!");
	} else if (data.size() % 16 != 0) {
		throw std::runtime_error("Error: decryptECB called with invalid data!");
	}
	std::vector<state_t> blocks = toBlocks(data, false);
	std::vector<uint32_t> w = keyExpansion(key);
	std::string result;
	state_t decrypted;
	std::pair<uint8_t, uint8_t> padding;
	uint8_t cnt = 0;
	for (state_t block : blocks) {
		decrypted = invCipher(block, w);
		// もし、最後のblockの場合
		if (block == blocks.back()) {
			padding = findPadding(decrypted);
			while (true) {
				if (cnt / STATE_ROWS == padding.first && cnt % STATE_COLS == padding.second) {
					return result;
				}
				result.push_back(decrypted[cnt / STATE_ROWS][cnt % STATE_COLS]);
				cnt++;
			}
		}	
		for (uint8_t i = 0; i < STATE_ROWS; i++) {
			for (uint8_t j = 0; j < STATE_COLS; j++) {
				result.push_back(decrypted[i][j]);
			}
		}
	}
	return result;
}
