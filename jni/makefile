target=libSSLClientBT.so
CFLAGS=-I. -I/usr/lib/jvm/java-11-openjdk-amd64/include -I/usr/lib/jvm/java-11-openjdk-amd64/include/linux
CFLAGS +=-I./mbedtls-2.13.0/include
MBEDLIBDIR=./mbedtls-2.13.0/library/
src=$(wildcard *.c)
obj=$(src:.c=.o)

all:$(target)
	
$(target):SSLClientBT.h mbedlib $(obj)	
	gcc -shared $(CFLAGS) -o $@ -Wl,--whole-archive $(MBEDLIBDIR)*.a -Wl,--no-whole-archive $(obj)

SSLClientBT.h:
	javac -h . ../src/sslBT/SSLClientBT.java

mbedlib:
	$(MAKE) -C mbedtls-2.13.0/
	
%.o:%.c
	gcc -c -fPIC $(CFLAGS) -o $@ $^ 
	
clean:
	rm -f *.o *.so *.so.* *.a SSLClientBT.h
	$(MAKE) -C mbedtls-2.13.0/ clean
	
