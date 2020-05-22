#include <stdio.h>
#include <stdlib.h>
// for the pipe
#include <unistd.h>
// for wait
#include <sys/types.h>
#include <sys/wait.h>
// for open
#include <sys/stat.h>
#include <fcntl.h>
// for mmap
#include <sys/mman.h>
// for sha512
#include <openssl/evp.h>
#include <string.h>

void child_proces(void);
void father_proces(void);

#define HANDLE_ERROR(msg) { fprintf(stderr, "%s\n", msg); exit(EXIT_FAILURE); }
#define HANDLE_ERROR2(msg, mdctx) { fprintf(stderr, "%s\n", msg); EVP_MD_CTX_destroy(mdctx); exit(EXIT_FAILURE); }

#define BUFFER_SIZE 1024
#define MAP_SIZE 64

int pfd[2];
// pfd[0]: file descriptor for READING from PIPE
// pfd[1]: file descriptor for WRITING from PIPE

char * addr;
char * file = "/home/andrea/Scrivania/test";

int main(int argc, char *argv[])
{
	// create pipe
	if (pipe(pfd) == -1) {
		perror("problema con pipe");
		exit(EXIT_FAILURE);
	}


	// create memory map
	addr = mmap(NULL, // NULL: è il kernel a scegliere l'indirizzo
			MAP_SIZE, // dimensione della memory map
			PROT_READ | PROT_WRITE, // memory map leggibile e scrivibile
			MAP_SHARED | MAP_ANONYMOUS, // memory map condivisibile con altri processi
			-1,
			0); // offset nel file
	if (addr == MAP_FAILED) {
		printf("ciao3");
		perror("mmap()");
		exit(EXIT_FAILURE);
	}



    if(argc >= 2){
    	file = argv[1];
    	printf("%s\n", file);
    }else{
    	printf("in this program you can spec a file to calculate sha_512, just pass a file name as argument\n");
    }


	pid_t child = fork();

	switch(child){
		case -1:
			perror("fork()\n");
			exit(1);
		case 0:
			child_proces();
			exit(0);
		default :
		{
			father_proces();

			// wait the child
			if(wait(NULL) == -1){
				perror("wait()\n");
				exit(1);
			}
		}
	} // end of switch

	printf("SHA3_512 del file %s è il seguente:\n", file);
	for (int i = 0; i < MAP_SIZE; i++) {
		printf("%02x", addr[i] & 0xFF);
	}
	printf("\n");

    exit(0);
}

void child_proces(void){

	close(pfd[1]); // close write part of the pipe

    ssize_t bytesRead;
    char * buffer;

    // from sha512
    EVP_MD_CTX * mdctx;
	int val;
	unsigned char * digest;
	unsigned int digest_len;
	EVP_MD * algo = NULL;

	algo = EVP_sha3_512();

	if ((mdctx = EVP_MD_CTX_create()) == NULL) {
		HANDLE_ERROR("EVP_MD_CTX_create() error")
	}

	// initialize digest engine
	if (EVP_DigestInit_ex(mdctx, algo, NULL) != 1) { // returns 1 if successful
		HANDLE_ERROR2("EVP_DigestInit_ex() error", mdctx)
	}

	while ((bytesRead = read(pfd[0], buffer, BUFFER_SIZE)) > 0) {
		// TEST
		for(int i=0 ; i< bytesRead ; i++){
			printf("%c", buffer[i]);
		}

		// provide data to digest engine
		if (EVP_DigestUpdate(mdctx, buffer, bytesRead) != 1) { // returns 1 if successful
			HANDLE_ERROR2("EVP_DigestUpdate() error", mdctx)
		}

		// buffer for next read
		buffer = malloc(BUFFER_SIZE * sizeof(char));
	    if(buffer == NULL){
	    	perror("malloc()\n");
	    	exit(1);
	    }
	}

	close(pfd[0]);

	digest_len = EVP_MD_size(algo); // sha3_512 returns a 512 bit hash

	if ((digest = (unsigned char *)OPENSSL_malloc(digest_len)) == NULL) {
		HANDLE_ERROR2("OPENSSL_malloc() error", mdctx);
	}

	// produce digest
	if (EVP_DigestFinal_ex(mdctx, digest, &digest_len) != 1) { // returns 1 if successful
		OPENSSL_free(digest);
		HANDLE_ERROR2("EVP_DigestFinal_ex() error", mdctx)
	}

	memcpy(addr, digest, digest_len);

	OPENSSL_free(digest);
	EVP_MD_CTX_destroy(mdctx);

	printf("SHA3_512 del file %s è il seguente:\n", file);
	for (int i = 0; i < MAP_SIZE; i++) {
		printf("%02x", addr[i] & 0xFF);
	}
	printf("\n");
}


void father_proces(void){
	close(pfd[0]); // close the reading pipe

    char * buffer = malloc(BUFFER_SIZE * sizeof(char));
    if(buffer == NULL){
    	perror("malloc()\n");
    	exit(1);
    }
    ssize_t bytesRead;

    int fd = open(file, O_RDONLY);

	while ((bytesRead = read(fd, buffer, BUFFER_SIZE)) > 0) {
		write(pfd[1], buffer, bytesRead);

		// buffer for next read
		buffer = malloc(BUFFER_SIZE * sizeof(char));
	    if(buffer == NULL){
	    	perror("malloc()\n");
	    	exit(1);
	    }
	}
	close(pfd[1]);
	free(buffer);
}
