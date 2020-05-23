#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <openssl/evp.h>

#define BUF_SIZE 1024

int pfd[2];
char *sha;

void err_exit(char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

void child()
{
	close(pfd[1]);
	char buf[BUF_SIZE];
	int rbytes;

	EVP_MD_CTX *mdctx;
	unsigned char *digest;
	const EVP_MD *algo = EVP_sha3_512();

	if ((mdctx = EVP_MD_CTX_create()) == NULL)
		err_exit("EVP_MD_CTX_create() error");

	if (EVP_DigestInit_ex(mdctx, algo, NULL) != 1)
		err_exit("EVP_DigestInit_ex() error");

	while ((rbytes = read(pfd[0], &buf, BUF_SIZE)) > 0) {
		if (rbytes == -1)
			err_exit("read() error");
		if (EVP_DigestUpdate(mdctx, &buf, rbytes) != 1)
			err_exit("EVP_DigestUpdate() error");
	}
	close(pfd[0]);

	if ((digest = (unsigned char *)OPENSSL_malloc(64)) == NULL)
		err_exit("OPENSSL_malloc() error");

	if (EVP_DigestFinal_ex(mdctx, digest, NULL) != 1) {
		OPENSSL_free(digest);
		err_exit("EVP_DigestFinal_ex() error");
	}

	memcpy(sha, digest, 64);

	OPENSSL_free(digest);
	EVP_MD_CTX_destroy(mdctx);
}

void parent(char *file)
{
	close(pfd[0]);
	int fd = open(file, O_RDONLY);
	if (fd == -1)
		err_exit("open() error");

	char buf[BUF_SIZE];
	int rbytes, n, wbytes = 0;
	while ((rbytes = read(fd, &buf, BUF_SIZE)) > 0) {
		if (rbytes == -1)
			err_exit("read() error");
		n = write(pfd[1], &buf, rbytes);
		if (n == -1)
			err_exit("write() error");
		wbytes += n;
	}
	close(fd);
	close(pfd[1]);

	if (wait(NULL) == -1)
		err_exit("wait() error");

	for (int i = 0; i < 64; i++)
		printf("%02x", sha[i] & 0xFF);
}

int main(int argc, char *argv[])
{
	if (pipe(pfd))
		err_exit("pipe() error");

	sha = mmap(NULL, 64, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (sha == MAP_FAILED)
		err_exit("mmap() failed");

	switch (fork()) {
	case 0:
		child();
		break;
	case -1:
		break;
	default:
		parent(argv[1]);
		break;
	}
	return 0;
}
