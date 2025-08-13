.PHONY: all tun logger clean

all: tun

tun:
	$(MAKE) -C tun

logger:
	@echo "Logger is a library and built as part of tun."

clean:
	$(MAKE) -C tun clean
