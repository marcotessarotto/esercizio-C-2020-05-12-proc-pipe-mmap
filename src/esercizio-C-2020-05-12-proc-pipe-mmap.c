#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include <errno.h>

#include <openssl/evp.h>

/*
 *
il processo padre per comunicare con il processo figlio prepara:
- una pipe
- una memory map condivisa

il processo padre manda i dati al processo figlio attraverso la pipe

il processo figlio restituisce il risultato attraverso la memory map convidisa
(che può essere anonima o basata su file).
esempio:
https://github.com/marcotessarotto/exOpSys/blob/7ce5b8f75782f2de0cb7f65bb7ce62dd143220e6/010files/mmap_anon.c#L18

il processo padre prende come argomento a linea di comando un nome di file.
il processo padre legge il file e manda i contenuti attraverso la pipe al processo figlio.

il processo figlio riceve attraverso la pipe i contenuti del file e calcola SHA3_512.

quando la pipe raggiunge EOF, il processo figlio produce il digest di SHA3_512 e
lo scrive nella memory map condivisa, poi il processo figlio termina.

quando al processo padre viene notificato che il processo figlio ha terminato,
prende il digest dalla memory map condivisa e lo scrive a video
("SHA3_512 del file %s è il seguente: " <segue digest in formato esadecimale>).
 */
/***************TESTO ESERCIZIO***************
il processo padre per comunicare con il processo figlio prepara:
- una pipe
- una memory map condivisa

il processo padre manda i dati al processo figlio attraverso la pipe

il processo figlio restituisce il risultato attraverso la memory map convidisa

il processo padre prende come argomento a linea di comando un nome di file.
il processo padre legge il file e manda i contenuti attraverso la pipe al processo figlio.

il processo figlio riceve attraverso la pipe i contenuti del file e calcola SHA3_512.

quando la pipe raggiunge EOF, il processo figlio produce il digest di SHA3_512 e lo scrive
nella memory map condivisa, poi il processo figlio termina.

quando al processo padre viene notificato che il processo figlio ha terminato, prende il digest
dalla memory map condivisa e lo scrive a video ("SHA3_512 del file %s è il seguente: " <segue digest in formato esadecimale>).
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/mman.h>

#include <errno.h>

#include <openssl/evp.h>

#define HANDLE_ERROR(msg) { fprintf(stderr, "%s\n", msg); exit(EXIT_FAILURE); }
#define HANDLE_ERROR2(msg, mdctx) { fprintf(stderr, "%s\n", msg); EVP_MD_CTX_destroy(mdctx); exit(EXIT_FAILURE); }

#define READ_BUFFER_SIZE 4096

#define WRITE_BUFFER_SIZE 4096*16*4

unsigned char * sha3_512(char * addr, unsigned int size, int * result_len_ptr);

int main(int argc, char * argv[]) {

	int pipe_fd[2], fd;
	int res;
	char * buffer;
	char * file;
	char * file_name;
	char * addr;
	int bytes_read = 0;

	unsigned char * digest;
	int digest_len;

	if (argc == 1) {
		printf("specificare come parametro il nome del file da leggere\n");
		exit(EXIT_FAILURE);
	}

	addr = mmap(NULL, // NULL: è il kernel a scegliere l'indirizzo
			64, // dimensione della memory map (il digest di SHA3_512 è di 64 byte)
			PROT_READ | PROT_WRITE, // memory map leggibile e scrivibile
			MAP_SHARED | MAP_ANONYMOUS, // memory map condivisibile con altri processi
			-1,
			0); // offset nel file

	if (addr == MAP_FAILED) {
		perror("mmap()");
		exit(EXIT_FAILURE);
	}

	if (pipe(pipe_fd) == -1) {
		perror("pipe()");

		exit(EXIT_FAILURE);
	}

	// pipe_fd[0] : estremità di lettura della pipe
	// pipe_fd[1] : estremità di scrittura della pipe

	switch (fork()) {
		case -1:
			perror("problema con fork");

			exit(EXIT_FAILURE);

		case 0: // processo FIGLIO: legge dalla PIPE

			close(pipe_fd[1]); // chiudiamo l'estremità di scrittura della pipe

			buffer = malloc(READ_BUFFER_SIZE);
			if (buffer == NULL) {
				perror("malloc()");
				exit(EXIT_FAILURE);
			}

			file = malloc(1);
			file[0] = '\0';
			// pipe vuota: read() si blocca in attesa di dati
			while ((res = read(pipe_fd[0], buffer, READ_BUFFER_SIZE)) > 0) {
				//printf("[child] received %d bytes from pipe\n", res);
				bytes_read += res;
				file = realloc(file, bytes_read);
				strcat(file, buffer);
			}

			digest = sha3_512(file, bytes_read, &digest_len);
			/*printf("[child] SHA3_512 on %u bytes: ", bytes_read);

			for (int i = 0; i < digest_len; i++) {
				printf("%02x", digest[i]);
			}*/
			// copy hash to memory map
			memcpy(addr, digest, digest_len);

			//printf("[child] bye\n");

			close(pipe_fd[0]);

			exit(EXIT_SUCCESS);

		default: // processo PADRE: scrive nella PIPE

			close(pipe_fd[0]); // chiudiamo l'estremità di lettura della pipe

			buffer = malloc(WRITE_BUFFER_SIZE);
			memset(buffer, 'Z', WRITE_BUFFER_SIZE);

			file_name = argv[1];
			if ((fd = open(file_name, O_RDONLY)) == -1) { // errore!
				perror("open()");
				exit(EXIT_FAILURE);
			}
			while ((bytes_read = read(fd, buffer, WRITE_BUFFER_SIZE)) > 0) {
				// se pipe piena (capacità: 16 pages) allora write() si blocca
				res = write(pipe_fd[1], buffer, WRITE_BUFFER_SIZE);
				if (res == -1) {
					perror("write()");
				}

				//printf("[parent] %d bytes written to pipe\n", res);
			}

			close(fd);

			close(pipe_fd[1]); // chiudiamo estremità di scrittura della pipe
			// dall'altra parte verrà segnalato EOF

			//printf("[parent] before wait()\n");

			wait(NULL);

			printf("SHA3_512 del file %s è il seguente: ", file_name);
			for (int i = 0; i < 512 / 8; i++) {
				printf("%02x", addr[i] & 0xFF);
			}

			//printf("\n[parent] bye\n");

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

#define HANDLE_ERROR(msg) { fprintf(stderr, "%s\n", msg); exit(EXIT_FAILURE); }
#define HANDLE_ERROR2(msg, mdctx) { fprintf(stderr, "%s\n", msg); EVP_MD_CTX_destroy(mdctx); exit(EXIT_FAILURE); }


#define CHECK_ERR(a,msg) {if ((a) == -1) { perror((msg)); exit(EXIT_FAILURE); } }

#define CHECK_ALLOC(a,msg) {if ((a) == NULL) { perror((msg)); exit(EXIT_FAILURE); } }

#define CHECK_ERR_MMAP(a,msg) {if ((a) == MAP_FAILED) { perror((msg)); exit(EXIT_FAILURE); } }

#define BUF_SIZE 4096
#define CHILD_PROC_RESULT_SIZE 64

void child_process(void);

int pipe_fd[2];
char * child_proc_result; // memory map per il risultato
char * buffer; // è usata da entrambi i processi

int main(int argc, char * argv[]) {
	int res;

	char * file_name;
	int fd;

	if (argc == 1) {
		printf("parametro: nome del file");
		exit(EXIT_FAILURE);
	}

	file_name = argv[1];

	child_proc_result = mmap(NULL, // NULL: è il kernel a scegliere l'indirizzo
			CHILD_PROC_RESULT_SIZE, // dimensione della memory map
			PROT_READ | PROT_WRITE, // memory map leggibile e scrivibile
			MAP_SHARED | MAP_ANONYMOUS, // memory map condivisibile con altri processi e senza file di appoggio
			-1,
			0);
	CHECK_ERR_MMAP(child_proc_result,"mmap")

	res = pipe(pipe_fd);
	CHECK_ERR(res, "pipe")

	buffer = malloc(BUF_SIZE);
	CHECK_ALLOC(buffer, "malloc")

	switch(fork()) {
		case 0: // child process
			child_process();
			exit(EXIT_SUCCESS);
		case -1:
			perror("fork()");
			exit(EXIT_FAILURE);
		default:
			;
	}

	close(pipe_fd[0]); // chiudiamo l'estremità di lettura della pipe

	fd = open(file_name, O_RDONLY);
	CHECK_ERR(fd, "open")


	while ((res = read(fd, buffer, BUF_SIZE)) > 0) {
		res = write(pipe_fd[1], buffer, res);
		CHECK_ERR(res, "write")
	}
	CHECK_ERR(res, "read")

	close(pipe_fd[1]); // chiudiamo l'estremità di scrittura della pipe

	close(fd);

	res = wait(NULL); // aspetto la conclusione del processo figlio
	CHECK_ERR(res, "wait")

	printf("SHA3_512 del file %s è il seguente:\n", file_name);
	for (int i = 0; i < CHILD_PROC_RESULT_SIZE; i++) {
		printf("%02x", child_proc_result[i] & 0xFF);
	}
	printf("\n");

	return 0;
}


void child_process(void) {

	EVP_MD_CTX * mdctx;
	unsigned char * digest;
	unsigned int digest_len;
	EVP_MD * algo = NULL;
	int res;

	close(pipe_fd[1]); // chiudiamo l'estremità di scrittura della pipe

	algo = EVP_sha3_512();

	if ((mdctx = EVP_MD_CTX_create()) == NULL) {
		HANDLE_ERROR("EVP_MD_CTX_create() error")
	}

	// initialize digest engine
	if (EVP_DigestInit_ex(mdctx, algo, NULL) != 1) { // returns 1 if successful
		HANDLE_ERROR2("EVP_DigestInit_ex() error", mdctx)
	}

	while ((res = read(pipe_fd[0], buffer, BUF_SIZE)) > 0) {
		// provide data to digest engine
		if (EVP_DigestUpdate(mdctx, buffer, res) != 1) { // returns 1 if successful
			HANDLE_ERROR2("EVP_DigestUpdate() error", mdctx)
		}
	}
	if (res == 0)
		printf("[child] pipe closed\n");

	close(pipe_fd[0]);


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
