#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>

/*
 * Simple MD5 implementation
 *
 * Compile with: gcc -o md5 md5.c
 */

// Constants are the integer part of the sines of integers (in radians) * 2^32.
const uint32_t k[64] = { 0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
		0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af,
		0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
		0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453,
		0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
		0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681,
		0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
		0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5,
		0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
		0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0,
		0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };

// r specifies the per-round shift amounts
const uint32_t r[] = { 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17,
		22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16,
		23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10,
		15, 21, 6, 10, 15, 21, 6, 10, 15, 21 };

// leftrotate function definition
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

void to_bytes(uint32_t val, uint8_t *bytes) {
	bytes[0] = (uint8_t) val;
	bytes[1] = (uint8_t) (val >> 8);
	bytes[2] = (uint8_t) (val >> 16);
	bytes[3] = (uint8_t) (val >> 24);
}

uint32_t to_int32(const uint8_t *bytes) {
	return (uint32_t) bytes[0] | ((uint32_t) bytes[1] << 8)
			| ((uint32_t) bytes[2] << 16) | ((uint32_t) bytes[3] << 24);
}

void md5(const uint8_t *initial_msg, size_t initial_len, uint8_t *digest) {

	// These vars will contain the hash
	uint32_t h0, h1, h2, h3;

	// Message (to prepare)
	uint8_t *msg = NULL;

	size_t new_len, offset;
	uint32_t w[16];
	uint32_t a, b, c, d, i, f, g, temp;

	// Initialize variables - simple count in nibbles:
	h0 = 0x67452301;
	h1 = 0xefcdab89;
	h2 = 0x98badcfe;
	h3 = 0x10325476;

	//Pre-processing:
	//append "1" bit to message
	//append "0" bits until message length in bits ≡ 448 (mod 512)
	//append length mod (2^64) to message

	for (new_len = initial_len + 1; new_len % (512 / 8) != 448 / 8; new_len++)
		;

	msg = (uint8_t*) malloc(new_len + 8);
	memcpy(msg, initial_msg, initial_len);
	msg[initial_len] = 0x80; // append the "1" bit; most significant bit is "first"
	for (offset = initial_len + 1; offset < new_len; offset++)
		msg[offset] = 0; // append "0" bits

	// append the len in bits at the end of the buffer.
	to_bytes(initial_len * 8, msg + new_len);
	// initial_len>>29 == initial_len*8>>32, but avoids overflow.
	to_bytes(initial_len >> 29, msg + new_len + 4);

	// Process the message in successive 512-bit chunks:
	//for each 512-bit chunk of message:
	for (offset = 0; offset < new_len; offset += (512 / 8)) {

		// break chunk into sixteen 32-bit words w[j], 0 ≤ j ≤ 15
		for (i = 0; i < 16; i++)
			w[i] = to_int32(msg + offset + i * 4);

		// Initialize hash value for this chunk:
		a = h0;
		b = h1;
		c = h2;
		d = h3;

		// Main loop:
		for (i = 0; i < 64; i++) {

			if (i < 16) {
				f = (b & c) | ((~b) & d);
				g = i;
			} else if (i < 32) {
				f = (d & b) | ((~d) & c);
				g = (5 * i + 1) % 16;
			} else if (i < 48) {
				f = b ^ c ^ d;
				g = (3 * i + 5) % 16;
			} else {
				f = c ^ (b | (~d));
				g = (7 * i) % 16;
			}

			temp = d;
			d = c;
			c = b;
			b = b + LEFTROTATE((a + f + k[i] + w[g]), r[i]);
			a = temp;

		}

		// Add this chunk's hash to result so far:
		h0 += a;
		h1 += b;
		h2 += c;
		h3 += d;

	}

	// cleanup
	free(msg);

	//var char digest[16] := h0 append h1 append h2 append h3 //(Output is in little-endian)
	to_bytes(h0, digest);
	to_bytes(h1, digest + 4);
	to_bytes(h2, digest + 8);
	to_bytes(h3, digest + 12);
}

void hash_md5(char* input, uint8_t* result) {
	// benchmark
	for (int i = 0; i < 1000000; i++) {
		md5((uint8_t*) input, (size_t) strlen(input), result);
	}
}

void parse_input_data(char *input, uint8_t *output) {

	char current[2];
	int j = 0;

	for (int i = 0; i < 32; i += 2) {
		current[0] = input[i];
		current[1] = input[i + 1];

		uint8_t value = (uint8_t) strtol(current, NULL, 16);
		output[j++] = value;
	}

}

void generate_alphabet(char* input) {
	int i = 0;

	for (char c = 'a'; c <= 'z'; c++) {
		input[i++] = c;
	}
}

void generate_short_alphabet(char *input, const int len, const int offset) {
	int i = 0;

	char start_symbol = 'a' + offset;
	char end_symbol = start_symbol + len;

	for (; start_symbol < end_symbol; start_symbol++) {
		input[i++] = start_symbol;
	}
	input[i] = '\0';
}

char *choose_alphabet(char **short_alphabets, int i) {

	switch (i) {
	case 1:
	case 2:
	case 3:
	case 4:
	case 5:
	case 6:
	case 7:
	case 8:
		return short_alphabets[i - 1];
	default:
		printf("error choosing alphabet");
		exit(-1);
	}
}

void show_hash(uint8_t* input) {
	// display result
	for (int i = 0; i < 16; i++)
		printf("%2.2x", input[i]);

//	puts("\n");
}

int equals_array(uint8_t* array_1, uint8_t* array_2) {
	for (int i = 0; i < 16; i++) {
		if (array_1[i] != array_2[i]) {
			return 0;
		}
	}
	return 1;
}

void guess(char *prefix, int max_depth, char *alphabet, int *found, int level,
		char *short_alphabet, int len_short_alphabet, uint8_t* input,
		char *process_name) {

	if (found) {
		return;
	}

	uint8_t current_hash[16];
	char word[max_depth];

	level += 1;

	if (level == 1) {

		for (int i = 0; i < len_short_alphabet; i++) {
			strcpy(word, "");
			strcat(word, prefix);
			strncat(word, &short_alphabet[i], 1);

			hash_md5(word, current_hash);

			printf("%s: Trying %s... ", process_name, word);
			show_hash(current_hash);
			printf("\n");

			if (equals_array(input, current_hash)) {
				printf("\nInput string found: %s\n", word);
				*found = 1;
//				return;
			}

			if (level < max_depth) {
				guess(word, max_depth, alphabet, found, level, short_alphabet,
						len_short_alphabet, input, process_name);
			}
		}

	} else {

		for (int i = 0; i < 26; i++) {
			strcpy(word, "");
			strcat(word, prefix);
			strncat(word, &alphabet[i], 1);

			hash_md5(word, current_hash);

			printf("%s: Trying %s... ", process_name, word);
			show_hash(current_hash);
			printf("\n");

			if (equals_array(input, current_hash)) {
				printf("\nInput string found: %s\n", word);
				*found = 1;
//				return;
			}

			if (level < max_depth) {
				guess(word, max_depth, alphabet, found, level, short_alphabet,
						len_short_alphabet, input, process_name);
			}
		}
	}

}

// input: "bc"
// 5360af35bde9ebd8f01f492dc059593c
int main(int argc, char **argv) {

	if (argc < 3) {
		printf("usage: %s <hash>, <count of letter>\n", argv[0]);
		return 1;
	}

	char *input_data = argv[1];

	if (strlen(input_data) != 32) {
		printf("input hash must have 32 character length");
		return 1;
	}

	int len;
	len = atoi(argv[2]);

	printf("Input hash: %s \n", input_data);
	printf("Count of character: %d \n", len);

	uint8_t input_data_hexa[16];
	parse_input_data(input_data, input_data_hexa);

	char alphabet[26];
	generate_alphabet(alphabet);

	int ALPHABET_3 = 3;
	int ALPHABET_5 = 5;

	char alphabet_1[ALPHABET_3];
	char alphabet_2[ALPHABET_3];
	char alphabet_3[ALPHABET_3];
	char alphabet_4[ALPHABET_3];
	char alphabet_5[ALPHABET_3];
	char alphabet_6[ALPHABET_3];
	char alphabet_7[ALPHABET_3];
	char alphabet_8[ALPHABET_5];

	generate_short_alphabet(alphabet_1, ALPHABET_3, 0);
	generate_short_alphabet(alphabet_2, ALPHABET_3, 1 * ALPHABET_3);
	generate_short_alphabet(alphabet_3, ALPHABET_3, 2 * ALPHABET_3);
	generate_short_alphabet(alphabet_4, ALPHABET_3, 3 * ALPHABET_3);
	generate_short_alphabet(alphabet_5, ALPHABET_3, 4 * ALPHABET_3);
	generate_short_alphabet(alphabet_6, ALPHABET_3, 5 * ALPHABET_3);
	generate_short_alphabet(alphabet_7, ALPHABET_3, 6 * ALPHABET_3);
	generate_short_alphabet(alphabet_8, ALPHABET_5, 7 * ALPHABET_3);

	char *short_alphabets[8] = { alphabet_1, alphabet_2, alphabet_3, alphabet_4,
			alphabet_5, alphabet_6, alphabet_7, alphabet_8 };

//	for (int i = 0; i < 8; i++) {
//		printf(" %s ", short_alphabets[i]);
//	}

	int i = 0;
	int *found = 0;

//	guess("", 2, alphabet, found, 0,alphabet_1, ALPHABET_6, "");
//	printf("\n ------------------------------ \n");
//	guess("", 2, alphabet, found, 0,alphabet_2, ALPHABET_6, "");

	for (int kid = 0; kid < 4; ++kid) {
		pid_t pid = fork();
		++i;

		if (pid < 0) {
			exit(EXIT_FAILURE);
		} else if (pid > 0) {
			/* Parent processes */

			int id = i * 2 - 1;
			char name[3];
			sprintf(name, "pp%d", id);

//			for (int i = 0; i < 9; i++) {
//				printf(" %s ", short_alphabets[i]);
//			}

			char *current_alphabet = choose_alphabet(short_alphabets, id);
//			printf("%s: %s size = %d\n", name, current_alphabet, strlen(current_alphabet));

			guess("", 2, alphabet, found, 0, current_alphabet,
					strlen(current_alphabet), input_data_hexa, name);

		} else {
			/* Child processes */
			int id = i * 2;
			char name[3];
			sprintf(name, "cp%d", id);

			char *current_alphabet = choose_alphabet(short_alphabets, id);
//			printf("%s: %s size = %d\n", name, current_alphabet, strlen(current_alphabet));

			guess("", 2, alphabet, found, 0, current_alphabet,
					strlen(current_alphabet), input_data_hexa, name);

			exit(EXIT_SUCCESS);
		}
	}

	for (int i = 0; i < 9; i++) {
		short_alphabets[i] = NULL;
		free(short_alphabets[i]);
	}
	*short_alphabets = NULL;
	free(*short_alphabets);

	for (int kid = 0; kid < 8; ++kid) {
		int status;
		pid_t pid = wait(&status);

		return 0;
	}
}

