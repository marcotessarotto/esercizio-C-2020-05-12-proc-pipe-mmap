#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/stat.h>



#define MEM_SIZE 64
#define HANDLE_ERROR(msg) { fprintf(stderr, "%s\n", msg); exit(EXIT_FAILURE); }
#define HANDLE_ERROR2(msg, mdctx) { fprintf(stderr, "%s\n", msg); EVP_MD_CTX_destroy(mdctx); exit(EXIT_FAILURE); }


unsigned char * sha3_512(char * addr, unsigned int size, int * result_len_ptr);

unsigned long get_file_size(char *fname);


int main(int argc, char *argv[]) {

	//ottemgo nome e dimensioni del file
	char *file_name;

	unsigned long file_size;

	if (argc == 1) {
		printf(
				"[parent]: specificare come parametro il nome del file da cui ottenere il digest\n");
		exit(EXIT_FAILURE);
	}

	file_name = argv[1];

	file_size = get_file_size(file_name);

	if (file_size == -1) {
		perror("get_file_size");
		exit(EXIT_FAILURE);
	}

	printf("[parent]: hai scelto il file %s di dimensione %lu\n", file_name,
			file_size);

	//preparo la pipe
	int pfd[2];

	if (pipe(pfd) == -1) {
		perror("pipe");

		exit(EXIT_FAILURE);
	}

	printf("[parent]: ho preparato la pipe\n");

	printf("[parent]: l'estremità di lettura ha il fd: %d\n", pfd[0]);

	printf("[parent]: l'estremità di scrittura ha il fd: %d\n", pfd[1]);

	//preparo la memorymap
	char *addr;

	addr = mmap(NULL, // NULL: è il kernel a scegliere l'indirizzo
			MEM_SIZE, // dimensione della memory map per il digest
			PROT_READ | PROT_WRITE, // memory map leggibile e scrivibile
			MAP_SHARED | MAP_ANONYMOUS, // memory map condivisibile con altri processi e senza file di appoggio
			-1,
			0); // offset nel file

	if (addr == MAP_FAILED) {
		perror("mmap()");
		exit(EXIT_FAILURE);
	}

	printf("[parent]: ho preparato la memoria condivisa\n");

	printf("[parent]: ora mi divido\n");

	switch (fork()) {
	case -1:
		perror("fork");

		exit(EXIT_FAILURE);
	case 0: //figlio

		// chiudo l'estremità di scrittura
		if (close(pfd[1]) == -1) {
			perror("close");
			exit(EXIT_FAILURE);
		}

		//leggo dalla pipe
		char *c_buffer = malloc(sizeof(char) * file_size);

		if (c_buffer == NULL) {
			perror("malloc");
			exit(EXIT_FAILURE);
		}

		while (1) {

			int numRead = read(pfd[0], c_buffer, file_size);

			if (numRead == -1) {
				perror("errore in read");
				exit(EXIT_FAILURE);
			}

			if (numRead == 0)
				break; // EOF: la pipe è stata chiusa dal lato di scrittura

		}

		printf("[child]: ho finito di leggere dalla pipe\n");

		//chiudo l'estremità di lettura: non mi serve più
		if (close(pfd[0]) == -1) {
			perror("close");
			exit(EXIT_FAILURE);
		}

		//calcolo il digest e lo passo nella memorymap
		unsigned char * digest;
		int digest_len;

		digest = sha3_512(c_buffer, file_size, &digest_len);

		memcpy(addr, digest, digest_len);

		printf("[child]: ho portato a termine il mio compito: ora termino\n");

		exit(EXIT_SUCCESS);

	default: //il padre che passa i dati attraverso la pipe

		// chiudo l'estremità di lettura
		if (close(pfd[0]) == -1) {
			perror("close");
			exit(EXIT_FAILURE);
		}

		//passo il contenuto del file nella pipe

		int fd = open(file_name, O_RDONLY);

		if (fd == -1) {
			perror("open");
			exit(EXIT_FAILURE);
		}

		char *p_buffer = malloc(sizeof(char) * file_size);

		if (p_buffer == NULL) {
			perror("malloc");
			exit(EXIT_FAILURE);
		}

		if ((read(fd, p_buffer, file_size)) == -1) {
			perror("read");
			exit(EXIT_FAILURE);
		}

		if ((write(pfd[1], p_buffer, file_size)) == -1) {
			perror("write");
			exit(EXIT_FAILURE);
		}

		//libero le risorse
		if (close(fd) == -1) {
			perror("close");
			exit(EXIT_FAILURE);
		}

		free(p_buffer);

		if (close(pfd[1]) == -1) {
			perror("close");
			exit(EXIT_FAILURE);
		}

		printf("[parent]: aspetto il figlio\n");

		//aspetto il figlio
		if (wait(NULL) == -1) {
			perror("wait()");
			exit(EXIT_FAILURE);
		}

		printf("[parent]: SHA3_512 del file %s è il seguente:", file_name);
		for (int i = 0; i < 512 / 8; i++) {
			printf("%02x", addr[i] & 0xFF);
		}

		printf("\n[parent]bye!\n");

		exit(EXIT_SUCCESS);

	}

}


unsigned char * sha3_512(char * addr, unsigned int size, int * result_len_ptr) {

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

	// provide data to digest engine
	if (EVP_DigestUpdate(mdctx, addr, size) != 1) { // returns 1 if successful
		HANDLE_ERROR2("EVP_DigestUpdate() error", mdctx)
	}

	digest_len = EVP_MD_size(algo); // sha3_512 returns a 512 bit hash

	if ((digest = (unsigned char *)OPENSSL_malloc(digest_len)) == NULL) {
		HANDLE_ERROR2("OPENSSL_malloc() error", mdctx)
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

	*result_len_ptr = digest_len;

	OPENSSL_free(digest);
	EVP_MD_CTX_destroy(mdctx);

	return result;
}


//per ottenere le dimensioni di un file
unsigned long get_file_size(char *fname) {

	struct stat st;

	int res = stat(fname, &st);

	if (res == -1) {
		perror("stat error");
		return -1;
	} else
		return st.st_size;
}
