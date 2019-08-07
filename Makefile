all:
	gcc -fPIC -fno-stack-protector -c pam_decrypt.c
	sudo ld -x --shared -o /lib/x86_64-linux-gnu/security/pam_decrypt.so pam_decrypt.o
