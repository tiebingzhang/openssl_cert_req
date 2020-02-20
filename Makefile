gencert:main.cpp
	gcc -o $@ $^ -lcrypto -g
clean:
	rm -f gencert
