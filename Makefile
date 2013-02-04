all: icetunnel ssdp-test 

icetunnel: icetunnel.c
	$(CC) -o $@ $< `pkg-config --cflags --libs libpjproject`

clean:
	rm -f icetunnel.o icetunnel
