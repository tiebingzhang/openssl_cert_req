gencert:main.c
	gcc -o $@ $^ -lcrypto -g
clean:
	rm -f gencert
