#include <sys/types.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include "md5.h"


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

	uint8_t current_hash[16];
	char word[max_depth];

	level += 1;

	if (level == 1) {

		for (int i = 0; i < len_short_alphabet; i++) {
			strcpy(word, "");
			strcat(word, prefix);
			strncat(word, &short_alphabet[i], 1);

			hash_md5(word, current_hash);

			if (*found) {
				return;
			}

			if (!*found) {
				printf("%s: Trying %s... ", process_name, word);
				show_hash(current_hash);
				printf("\n");
			}

			if (equals_array(input, current_hash)) {
				printf("\nInput string found: %s\n", word);
				*found = 1;
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

			if (*found) {
				return;
			}

			if (!*found) {
				printf("%s: Trying %s... ", process_name, word);
				show_hash(current_hash);
				printf("\n");
			}

			if (equals_array(input, current_hash)) {
				printf("\nInput string found: %s\n", word);
				*found = 1;
			}

			if (level < max_depth) {
				guess(word, max_depth, alphabet, found, level, short_alphabet,
						len_short_alphabet, input, process_name);
			}
		}
	}

}

static int *found;

/*
 * Need compile with: gcc -std=gnu99 -o main main.c
 */
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

	int i = 0;

	found = mmap(NULL, sizeof *found, PROT_READ | PROT_WRITE,
	MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	*found = 0;

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

			char *current_alphabet = choose_alphabet(short_alphabets, id);

			guess("", 2, alphabet, found, 0, current_alphabet,
					strlen(current_alphabet), input_data_hexa, name);

		} else {
			/* Child processes */

			int id = i * 2;
			char name[3];
			sprintf(name, "cp%d", id);

			char *current_alphabet = choose_alphabet(short_alphabets, id);

			guess("", 2, alphabet, found, 0, current_alphabet,
					strlen(current_alphabet), input_data_hexa, name);

			exit(EXIT_SUCCESS);
		}
	}

	for (int kid = 0; kid < 8; ++kid) {
		int status;
		pid_t pid = wait(&status);
	}

	for (int i = 0; i < 9; i++) {
		short_alphabets[i] = NULL;
		free(short_alphabets[i]);
	}

	*short_alphabets = NULL;
	free(*short_alphabets);

	munmap(found, sizeof *found);

	printf("\n program finish... \n");

	return 0;
}

