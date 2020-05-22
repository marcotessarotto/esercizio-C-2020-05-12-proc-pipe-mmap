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
char * addr;

int main(int argc, char *argv[])
{
	// pfd[0]: file descriptor for READING from PIPE
	// pfd[1]: file descriptor for WRITING from PIPE

	// create pipe
	if (pipe(pfd) == -1) {
		perror("problema con pipe");
		exit(EXIT_FAILURE);
	}

	size_t size = 64;
	// create memory map
	addr = mmap(NULL, // NULL: è il kernel a scegliere l'indirizzo
			size, // dimensione della memory map
			PROT_READ | PROT_WRITE, // memory map leggibile e scrivibile
			MAP_SHARED | MAP_ANONYMOUS, // memory map condivisibile con altri processi
			-1,
			0); // offset nel file
	if (addr == MAP_FAILED) {
		printf("ciao3");
		perror("mmap()");
		exit(EXIT_FAILURE);
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

	printf("father: %s\n", addr);

    exit(0);
}

void child_proces(void){
	// child
	close(pfd[1]); // close write part of the pipe
	/*
	if (dup2(pfd[0], STDIN_FILENO) == -1) {
		perror("problema con dup2");
		exit(EXIT_FAILURE);
	}
	*/
	//close(pfd[0]);

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

	digest_len = EVP_MD_size(algo); // sha3_512 returns a 512 bit hash

	if ((digest = (unsigned char *)OPENSSL_malloc(digest_len)) == NULL) {
		HANDLE_ERROR2("OPENSSL_malloc() error", mdctx);
	}

	// produce digest
	if (EVP_DigestFinal_ex(mdctx, digest, &digest_len) != 1) { // returns 1 if successful
		OPENSSL_free(digest);
		HANDLE_ERROR2("EVP_DigestFinal_ex() error", mdctx)
	}

	char * result = malloc(digest_len);
	if (result == NULL) {
		perror("malloc()");
		exit(EXIT_FAILURE);
	}

	memcpy(result, digest, digest_len);
	memcpy(addr, digest, digest_len);

	OPENSSL_free(digest);
	EVP_MD_CTX_destroy(mdctx);
	printf("child: %s\n", addr);

}


void father_proces(void){
	close(pfd[0]); // close the reading pipe

	/*
	if (dup2(pfd[1], STDOUT_FILENO) == -1) {
		perror("dup2()\n");
		exit(EXIT_FAILURE);
	}
	*/
	//close(pfd[1]);

    char * file = "/home/andrea/Scrivania/test";
    /*
    if(argc >= 2){
    	file = argv[1];
    }else{
    	perror("this program need a file name as argument\n");
    	exit(1);
    }
    */

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
	free(buffer);

}
