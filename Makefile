all: icedemo

icedemo: icedemo.c
	$(CC) -o $@ $< `pkg-config --cflags --libs libpjproject`

clean:
	rm -f icedemo.o icedemo
