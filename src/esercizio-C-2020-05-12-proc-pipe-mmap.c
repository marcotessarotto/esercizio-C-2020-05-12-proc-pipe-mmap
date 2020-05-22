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


void child_proces(void);
void father_proces(void);

#define BUFFER_SIZE 1024
int pfd[2];

int main(int argc, char *argv[])
{
	// pfd[0]: file descriptor for READING from PIPE
	// pfd[1]: file descriptor for WRITING from PIPE

	// create pipe
	if (pipe(pfd) == -1) {
		perror("problema con pipe");
		exit(EXIT_FAILURE);
	}

	char * addr = mmap(NULL, // NULL: è il kernel a scegliere l'indirizzo
			file_size, // dimensione della memory map
			PROT_READ | PROT_WRITE, // memory map leggibile e scrivibile
			MAP_SHARED, // memory map condivisibile con altri processi
			fd,
			0); // offset nel file

	pid_t child = fork();

	switch(child){
		case -1:
			perror("fork()\n");
			exit(1);
		case 0:
			child_proces();
			break;

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



	while ((bytesRead = read(pfd[0], buffer, BUFFER_SIZE)) > 0) {
		// TEST
		for(int i=0 ; i< bytesRead ; i++){
			printf("%c", buffer[i]);
		}

		// buffer for next read
		buffer = malloc(BUFFER_SIZE * sizeof(char));
	    if(buffer == NULL){
	    	perror("malloc()\n");
	    	exit(1);
	    }
	}
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
