/***
This program only able to find AES-256-ECB key from libUE4.so that pak file used
it's not support custom version pak file or modify unreal engine encryption 
***/

#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <elf.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include "AES_256_ECB.h"

// Pak Header
typedef struct {
	uint8_t encrypted;
	uint32_t magic;
	uint32_t version;
	uint64_t offset;
	uint64_t size;
	uint8_t hash[20];
} __attribute__((packed)) PakInfo;

void DecryptData(const uint8_t InData[16], uint8_t OutData[16], const uint8_t *key) {
	AES_CTX ctx;
	AES_DecryptInit(&ctx, key);
	AES_Decrypt(&ctx, InData, OutData);
	AES_CTX_Free(&ctx);
}

long get_rodata_offset(const char *filename) {
	int file = open(filename, O_RDONLY);
	
	if (file == -1) {
		return -1;
	}
	
	Elf64_Ehdr elf_header;
	
	if (read(file, &elf_header, sizeof(Elf64_Ehdr)) != sizeof(Elf64_Ehdr)) {
		close(file);
		return -1;
	}
	
	Elf64_Shdr section_header;
	off_t offset = elf_header.e_shoff + elf_header.e_shstrndx * elf_header.e_shentsize;
	
	if (pread(file, &section_header, sizeof(Elf64_Shdr), offset) != sizeof(Elf64_Shdr)) {
		close(file);
		return -1;
	}
	
	char *section_names = malloc(section_header.sh_size);
	
	if (!section_names) {
		perror("Error allocating memory");
		close(file);
		return 1;
	}
	
	if (pread(file, section_names, section_header.sh_size, section_header.sh_offset) != section_header.sh_size) {
		free(section_names);
		close(file);
		return -1;
	}
	
	for (int i = 0; i < elf_header.e_shnum; i++) {
		if (pread(file, &section_header, sizeof(Elf64_Shdr), elf_header.e_shoff + i * elf_header.e_shentsize) != sizeof(Elf64_Shdr)) {
			free(section_names);
			close(file);
			return -1;
		}
		
		if (strcmp(section_names + section_header.sh_name, ".rodata") == 0) {
			free(section_names);
			close(file);
			return section_header.sh_offset;
		}
	}
	
	close(file);
	free(section_names);
	return -1;
}

int main(int argc, const char *argv[]) {
	PakInfo info;
	
	if (argc != 3) {
		printf("Usage ./program <pak_file> <libUE4.so>\n");
		return EXIT_FAILURE;
	}
	
	if (access(argv[1], F_OK) != 0) {
		fprintf(stderr, "input pak file not found!\n");
		return EXIT_FAILURE;
	}
	
	if (access(argv[2], F_OK) != 0) {
		fprintf(stderr, "input libUE4.so file not found!\n");
		return EXIT_FAILURE;
	}
	
	// open input pak file read-only 
	int fpak = open(argv[1], O_RDONLY);
	
	if (fpak == -1) {
		printf("Can't open pak file!\n");
		return 1;
	}
	
	if (lseek(fpak, -sizeof(info), SEEK_END) == -1) {
		fprintf(stderr, "Can't seek file!\n");
		return EXIT_FAILURE;
	}
	
	if (read(fpak, &info, sizeof(info)) != sizeof(info)) {
		fprintf(stderr, "Can't read pak header!\n");
		return EXIT_FAILURE;
	}
	
	if (info.magic != 0x5A6F12E1) {
		fprintf(stderr, "Incorrect pak magic!\n");
		return EXIT_FAILURE;
	}
	
	uint8_t data[16];
	
	if (pread(fpak, data, 16, info.offset) != 16) {
		fprintf(stderr, "Can't read index data!\n");
		return EXIT_FAILURE;
	}
	
	close(fpak);
	
	long addr = get_rodata_offset(argv[2]);
	
	if (addr == -1) {
		return 1;
	}
	
	int libUE4 = open(argv[2], O_RDONLY);
	
	if (libUE4 == -1) {
		fprintf(stderr, "Can't open libUE4.so!\n");
		return 1;
	}
	
	bool key_found = false;
	uint8_t temp[16];
	uint8_t key[32];
	
	while (pread(libUE4, key, 32, addr) > 0) {
		DecryptData(data, temp, key);
		
		if (memcmp(temp + 4, "../../../", 9) == 0) {
			printf("[%p] Found AES-256 decryption key: 0x", (void*)addr);
			for (int i = 0; i < sizeof(key); i++) {
				printf("%02X", key[i]);
			}
			printf("\n");
			key_found = true;
			break;
		}
		addr++;
	}
	
	if (!key_found) {
		printf("Can't find decryption key!\n");
	}
	
	close(libUE4);
	return 0;
}
