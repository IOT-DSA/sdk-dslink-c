#

openssl-fips-2.0.1.tar.gz:
	wget http://www.openssl.org/source/openssl-fips-2.0.1.tar.gz
	gunzip -c openssl-fips-2.0.1.tar.gz | tar xf -

openssl-1.0.1c.tar.gz:
	wget http://www.openssl.org/source/openssl-1.0.1c.tar.gz
	gunzip  -c openssl-1.0.1c.tar.gz | tar xf -



ssl/:	
	mkdir $(OPENSSL_DIR)

openssl-fips-2.0.1/.built:	ssl/
	cd openssl-fips-2.0.1; \
	export FIPSDIR=$(FIPS_DIR); \
	./config; \
	make; \
	make install; \
	touch .built

openssl-1.0.1c/.built:	openssl-fips-2.0.1/.built
	cd openssl-1.0.1c; \
	./config fips shared --openssldir=$(OPENSSL_DIR) --with-fipsdir=$(FIPS_DIR); \
	make depend; \
	make; \
	make install_sw; \
	touch .built

all:	openssl-1.0.1c/.built

test:	
	#openssl-1.0.1c/.built
	OPENSSL_FIPS=1 LD_LIBRARY_PATH=$(OPENSSL_DIR)/lib $(OPENSSL_DIR)/bin/openssl version
	# this should work:
	LD_LIBRARY_PATH=$(OPENSSL_DIR)/lib $(OPENSSL_DIR)/bin/openssl md5 Makefile
	# should get errors for this:
	OPENSSL_FIPS=1 LD_LIBRARY_PATH=$(OPENSSL_DIR)/lib $(OPENSSL_DIR)/bin/openssl md5 Makefile


get:	openssl-fips-2.0.1.tar.gz openssl-1.0.1c.tar.gz

clean:
	rm -rf $(OPENSSL_DIR)

distclean:
	rm -rf openssl-fips-2.0.1 openssl-1.0.1c $(OPENSSL_DIR) openssl-fips-2.0.1.tar.gz openssl-1.0.1c.tar.gz

