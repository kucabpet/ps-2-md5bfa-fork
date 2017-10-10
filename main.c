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

void guess(char *prefix, int max_depth, char *alphabet, int *found, int level,
		char *short_alphabet, int len_short_alphabet, uint8_t* input,
		char *process_name) {

	if (found) {
		return;
	}

//	uint8_t current_hash[16];
	char word[max_depth];

	level += 1;

	if (level == 1) {

		for (int i = 0; i < len_short_alphabet; i++) {
			strcpy(word, "");
			strcat(word, prefix);
			strncat(word, &short_alphabet[i], 1);

			printf("%s: Trying %s... \n", process_name, word);

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

//		hash_md5(tmp, current_hash);

//		if (equals_array(input, current_hash)) {
//			printf("\nInput string found: %s\n", tmp);
//			*found = 1;
//		}
			printf("%s: Trying %s... \n", process_name, word);

			if (level < max_depth) {
				guess(word, max_depth, alphabet, found, level, short_alphabet,
						len_short_alphabet, input, process_name);
			}
		}
	}

}

char *choose_alphabet(char *alphabet_1, char *alphabet_2, char *alphabet_3,
		char *alphabet_4, int i) {

	switch (i) {
	case 1:
		return alphabet_1;
		break;
	case 2:
		return alphabet_2;
		break;
	case 3:
		return alphabet_3;
		break;
	case 4:
		return alphabet_4;
		break;
	default:
		printf("error choosing alphabet");
		exit(-1);
	}
}

int main(int argc, char **argv) {

	const int ALPHABET_LEN = 26;

	char alphabet[ALPHABET_LEN];
	generate_alphabet(alphabet);

	const int ALPHABET_3 = 3;
	const int ALPHABET_2 = 2;

	char alphabet_1[ALPHABET_3];
	char alphabet_2[ALPHABET_3];
	char alphabet_3[ALPHABET_3];
	char alphabet_4[ALPHABET_3];
	char alphabet_5[ALPHABET_3];
	char alphabet_6[ALPHABET_3];
	char alphabet_7[ALPHABET_3];
	char alphabet_8[ALPHABET_3];
	char alphabet_9[ALPHABET_2];

	generate_short_alphabet(alphabet_1, ALPHABET_3, 0);
	generate_short_alphabet(alphabet_2, ALPHABET_3, 1 * ALPHABET_3);
	generate_short_alphabet(alphabet_3, ALPHABET_3, 2 * ALPHABET_3);
	generate_short_alphabet(alphabet_4, ALPHABET_3, 3 * ALPHABET_3);
	generate_short_alphabet(alphabet_5, ALPHABET_3, 4 * ALPHABET_3);
	generate_short_alphabet(alphabet_6, ALPHABET_3, 5 * ALPHABET_3);
	generate_short_alphabet(alphabet_7, ALPHABET_3, 6 * ALPHABET_3);
	generate_short_alphabet(alphabet_8, ALPHABET_3, 7 * ALPHABET_3);
	generate_short_alphabet(alphabet_9, ALPHABET_2, 8 * ALPHABET_3);

//	char **short_alphabets[8];
//	short_alphabets[1] = alphabet_1;
//	short_alphabets[2] = alphabet_2;
//	short_alphabets[3] = alphabet_3;

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
			/* Parent process */

			char name[3];
			sprintf(name, "pp%d", i * 2 - 1);
			printf("%s\n", name);

//			guess("", 2, alphabet, found, 0,alphabet_2, ALPHABET_6, "");

//			printf("%s \n",
//					choose_alphabet(alphabet_1, alphabet_2, alphabet_3,
//							alphabet_4, i));

		} else {
			/* Child process */

			char name[3];
			sprintf(name, "cp%d", i * 2);
			printf("%s\n", name);

//			printf("%s \n", choose_alphabet(alphabet_1, alphabet_2, alphabet_3, alphabet_4, i));

//			printf("%s \n",
//					choose_alphabet(alphabet_1, alphabet_2, alphabet_3,
//							alphabet_4, i));

			exit(EXIT_SUCCESS);
		}
	}

	for (int kid = 0; kid < 8; ++kid) {
		int status;
		pid_t pid = wait(&status);

		return 0;
	}

}

