// Diaa Nehme  IN0500345  esercizio20200422

#include<unistd.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#include<sys/types.h>
#include<sys/wait.h>
#include<sys/stat.h>
#include<fcntl.h>
#include<sys/mman.h>

#include<openssl/evp.h>
#include<errno.h>

#define CHECK_ERR(a, msg) {if(a == -1){perror(msg); exit(EXIT_FAILURE);}}
#define CHECK_ALLOC(a, msg) {if(a == NULL){perror(msg); exit(EXIT_FAILURE);}}
#define CHECK_ERR_MAP(a, msg) {if(a == MAP_FAILED){perror(msg); exit(EXIT_FAILURE);}}

#define BUF_SIZE 4096
#define CHILD_PROC_ESULT_SIZE 64

#define HANDLE_ERROR(msg) { fprintf(stderr, "%s\n", msg); exit(EXIT_FAILURE); }
#define HANDLE_ERROR2(msg, mdctx) { fprintf(stderr, "%s\n", msg); EVP_MD_CTX_destroy(mdctx); exit(EXIT_FAILURE); }


int pipe_fd[2];
char * child_proc_result;
char * buffer;

void child_process(){

	EVP_MD_CTX * mdctx;
	unsigned char * digest;
	unsigned int digest_len;
	EVP_MD * algo = NULL;
	int res;

	close(pipe_fd[1]);

	algo = EVP_sha3_512();

	if ((mdctx = EVP_MD_CTX_create()) == NULL) {
		HANDLE_ERROR("EVP_MD_CTX_create() error")
	}

	// initialize digest engine
	if (EVP_DigestInit_ex(mdctx, algo, NULL) != 1) { // returns 1 if successful
		HANDLE_ERROR2("EVP_DigestInit_ex() error", mdctx)
	}

	while((res = read(pipe_fd[0], buffer, BUF_SIZE)) > 0){
		// provide data to digest engine
		if (EVP_DigestUpdate(mdctx, buffer, res) != 1) { // returns 1 if successful
			HANDLE_ERROR2("EVP_DigestUpdate() error", mdctx)
		}
	}
	if(res == 0)
		printf("Child pipe closed\n");

	digest_len = EVP_MD_size(algo); // sha3_512 returns a 512 bit hash

	if ((digest = (unsigned char *)OPENSSL_malloc(digest_len)) == NULL) {
		HANDLE_ERROR2("OPENSSL_malloc() error", mdctx)
	}

	// produce digest
	if (EVP_DigestFinal_ex(mdctx, digest, &digest_len) != 1) { // returns 1 if successful
		OPENSSL_free(digest);
		HANDLE_ERROR2("EVP_DigestFinal_ex() error", mdctx)
	}

	memcpy(child_proc_result, digest, digest_len);


	OPENSSL_free(digest);
	EVP_MD_CTX_destroy(mdctx);

}

int main(int argc, char * argv[]){
	
	int res;

	char * file_name;
	int fd;

	if(argc == 1){
		printf("Parametro: nome del file!");
		exit(EXIT_FAILURE);
	}

	file_name = argv[1];

	child_proc_result = mmap(NULL, CHILD_PROC_ESULT_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	CHECK_ERR_MAP(child_proc_result, "mmap")

	res = pipe(pipe_fd);
	CHECK_ERR(res, "pipe")

	buffer = malloc(BUF_SIZE);
	CHECK_ALLOC(buffer, "malloc")

	switch(fork()){
		case 0:
			child_process();
			exit(EXIT_SUCCESS);
		case -1:
			perror("fork");
			exit(EXIT_FAILURE);
		default:
    return 0;
			
	}

	close(pipe_fd[0]);

	fd = open(file_name, O_RDONLY);
	CHECK_ERR(fd, "open")

	while((res = read(fd, buffer, BUF_SIZE)) > 0){
		res = write(pipe_fd[1], buffer, res);
		CHECK_ERR(res, "write")
	}
	CHECK_ERR(res, "read")

	close(pipe_fd[1]);

	close(fd);

	res = wait(NULL);
	CHECK_ERR(res, "wait")

	printf("SHA3_512 del file %s e' il seguente: ", file_name);
	for(int i = 0; i < CHILD_PROC_ESULT_SIZE; i++){
		
	}

	return 0;
}
