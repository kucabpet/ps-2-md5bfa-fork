/*
 * Simple MD5 implementation
 *
 * Compile with: gcc -o md5 md5.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>

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
}

void guess(char *prefix, int level, uint8_t* input, int max_depth,
		char *alphabet, int *found) {

	if (found) {
		return;
	}

	uint8_t current_hash[16];
	char tmp[max_depth];

	level += 1;

	for (int i = 0; i < 26; i++) {
		strcpy(tmp, "");
		strcat(tmp, prefix);
		strncat(tmp, &alphabet[i], 1);

//		hash_md5(tmp, current_hash);

		printf("Trying %s... \n", tmp);

//		if (equals_array(input, current_hash)) {
//			printf("\nInput string found: %s\n", tmp);
//			*found = 1;
//		}

		if (level < max_depth) {
			guess(tmp, level, input, max_depth, alphabet, found);
		}
	}

}

int main(int argc, char **argv) {

	const int ALPHABET_LEN = 26;

	char alphabet[ALPHABET_LEN];
	generate_alphabet(alphabet);

	const int ALPHABET_6 = 6;
	const int ALPHABET_8 = 8;

	char alphabet_1[ALPHABET_6];
	char alphabet_2[ALPHABET_6];
	char alphabet_3[ALPHABET_6];
	char alphabet_4[ALPHABET_8];

	generate_short_alphabet(alphabet_1, ALPHABET_6, 0);
	generate_short_alphabet(alphabet_2, ALPHABET_6, 1*ALPHABET_6);
	generate_short_alphabet(alphabet_3, ALPHABET_6, 2*ALPHABET_6);
	generate_short_alphabet(alphabet_4, ALPHABET_8, 3*ALPHABET_6);

	int i = 0;

//	for (int kid = 0; kid < 2; ++kid) {
//		pid_t pid = fork();
//
//		if (pid < 0) {
//			exit(EXIT_FAILURE);
//		} else if (pid > 0) {
//
//			/* Parent process */
//			printf("parent process %d \n", ++i);
//		} else {
//
//			printf("child process %d \n", ++i);
//			/* Child process */
//			exit(EXIT_SUCCESS);
//		}
//	}
//
//	for (int kid = 0; kid < 4; ++kid) {
//		int status;
//		pid_t pid = wait(&status);
//
//		return 0;
//	}


}

