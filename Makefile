all: icedemo ssdp-test 

icedemo: icedemo.c
	$(CC) -o $@ $< `pkg-config --cflags --libs libpjproject`

ssdp-test: ssdp-test.c
	$(CC) -o $@ $< -lpthread

clean:
	rm -f icedemo.o icedemo ssdp-test.o ssdp-test
