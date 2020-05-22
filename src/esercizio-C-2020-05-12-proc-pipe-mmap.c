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



#define BUFFER_SIZE 1024


int main(int argc, char *argv[])
{
	int pfd[2];
	// pfd[0]: file descriptor for READING from PIPE
	// pfd[1]: file descriptor for WRITING from PIPE

	// create pipe
	if (pipe(pfd) == -1) {
		perror("problema con pipe");
		exit(EXIT_FAILURE);
	}

	pid_t child = fork();

	switch(child){
		case -1:
			perror("fork()\n");
			exit(1);
		case 0:
		{
			// child
		}
		default :
		{
			// father

			close(pfd[0]); // close the reading pipe

			if (dup2(pfd[1], STDOUT_FILENO) == -1) {
				perror("dup2()\n");
				exit(EXIT_FAILURE);
			}

			close(pfd[1]);

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

		    int fd = open();

			while ((bytesRead = read(STDIN_FILENO, buffer, BUFFER_SIZE)) > 0) {

				append_item(head, buffer, bytesRead);

				fprintf(stdout,"read %ld bytes from file\n", bytesRead);

				totalBytesRead += bytesRead;

				// buffer for next read
				buffer = malloc(BUFFER_SIZE * sizeof(char));

			}

			free(buffer);









			// wait the child
			if(wait(NULL) == -1){
				perror("wait()\n");
				exit(1);
			}

		}
	}

    exit(0);
}
