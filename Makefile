# Detect platform
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    PLATFORM := macos
else ifeq ($(UNAME_S),Linux)
    PLATFORM := linux
else
    PLATFORM := unknown
endif

.PHONY: all logger tun secure_channel crypto client server tests executables clean install uninstall linux-only macos-only

# Default target - build all modules
all: logger macos-only linux-only tests executables

# Build individual modules
logger:
	$(MAKE) -C logger

# Platform-specific builds
macos-only:
	@echo "Building macOS-compatible modules..."
	@echo "Note: Crypto module requires OpenSSL - skipping on macOS"
	@echo "Use 'brew install openssl' to install OpenSSL on macOS"

linux-only:
	@echo "Building Linux-specific modules..."
ifeq ($(PLATFORM),linux)
	$(MAKE) -C tun
	$(MAKE) -C secure_channel
	$(MAKE) -C client
	$(MAKE) -C server
	$(MAKE) -C executables
else
	@echo "Skipping Linux-specific modules on $(PLATFORM)"
endif

tun:
ifeq ($(PLATFORM),linux)
	$(MAKE) -C tun
else
	@echo "TUN module requires Linux - skipping on $(PLATFORM)"
endif

secure_channel:
ifeq ($(PLATFORM),linux)
	$(MAKE) -C secure_channel
else
	@echo "Secure channel module requires Linux - skipping on $(PLATFORM)"
endif

crypto:
ifeq ($(PLATFORM),linux)
	$(MAKE) -C crypto
else
	@echo "Crypto module requires OpenSSL - skipping on $(PLATFORM)"
	@echo "Use 'brew install openssl' to install OpenSSL on macOS"
endif

client:
ifeq ($(PLATFORM),linux)
	$(MAKE) -C client
else
	@echo "Client module requires Linux - skipping on $(PLATFORM)"
endif

server:
ifeq ($(PLATFORM),linux)
	$(MAKE) -C server
else
	@echo "Server module requires Linux - skipping on $(PLATFORM)"
endif

tests:
	$(MAKE) -C tests

executables:
ifeq ($(PLATFORM),linux)
	$(MAKE) -C executables
else
	@echo "Executables require Linux - skipping on $(PLATFORM)"
endif

# Clean all modules
clean:
	$(MAKE) -C logger clean
ifeq ($(PLATFORM),linux)
	$(MAKE) -C tun clean
	$(MAKE) -C secure_channel clean
	$(MAKE) -C client clean
	$(MAKE) -C server clean
	$(MAKE) -C executables clean
	$(MAKE) -C crypto clean
endif
	$(MAKE) -C tests clean
	rm -rf build/

# Install all modules
install:
	$(MAKE) -C logger install
ifeq ($(PLATFORM),linux)
	$(MAKE) -C tun install
	$(MAKE) -C secure_channel install
	$(MAKE) -C client install
	$(MAKE) -C server install
	$(MAKE) -C executables install
endif
	$(MAKE) -C crypto install

# Uninstall all modules
uninstall:
	$(MAKE) -C logger uninstall
ifeq ($(PLATFORM),linux)
	$(MAKE) -C tun uninstall
	$(MAKE) -C secure_channel uninstall
	$(MAKE) -C client uninstall
	$(MAKE) -C server uninstall
	$(MAKE) -C executables uninstall
endif
	$(MAKE) -C crypto uninstall

# Run all tests
test: tests
	$(MAKE) -C tests test

# Build shared libraries only
shared: logger
ifeq ($(PLATFORM),linux)
shared: shared crypto tun secure_channel client server
endif

# Build static libraries only
static:
	$(MAKE) -C logger liblogger.a
ifeq ($(PLATFORM),linux)
	$(MAKE) -C crypto libcrypto.a
	$(MAKE) -C tun libtun_utils.a
	$(MAKE) -C secure_channel libsecure_channel.a
	$(MAKE) -C client libclient.a
	$(MAKE) -C server libserver.a
endif
