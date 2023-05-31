LIBCRYPT  = libacrypt.so
EXECRYPT  = crypt
LIBOBJS   = crypt.o
LIBFILES  = src/crypt.c
EXEOBJS   = crypt_main.o
EXEFILES  = src/crypt_main.c
TSTCRYPT  = cryptest
TSTOBJS   = crypt_test.o
TSTFILES  = src/crypt_test.c
CFLAGS    = -c
LDFLAGS   = -shared

all: $(LIBCRYPT) $(EXECRYPT)

$(LIBCRYPT): $(LIBOBJS)
	$(CC) -o $@ $(LDFLAGS) $<

$(LIBOBJS): $(LIBFILES)
	$(CC) -o $@ $(CFLAGS) -fPIC $<

$(EXECRYPT): $(EXEOBJS)
	$(CC) -o $@ $(EXEOBJS) -L. -lacrypt

$(EXEOBJS): $(EXEFILES)
	$(CC) -o $@ $(CFLAGS) $< $(EXTRAFLAG)

$(TSTCRYPT): $(TSTOBJS)
	$(CC) -o $@ $(TSTOBJS) -L. -lacrypt -lunity

$(TSTOBJS): $(TSTFILES)
	$(CC) -o $@ $(CFLAGS) $< $(EXTRAFLAG)

test: all $(TSTCRYPT)
	./$(TSTCRYPT)

doc: all
	doxygen

install: all
	cp libacrypt.so /usr/local/lib
	cp crypt /usr/local/bin
	ldconfig

clean:
	rm -rf *.[oa] $(LIBCRYPT) $(EXECRYPT) $(TSTCRYPT)
	rm -rf doc/*
