EBPF_TARGET = bpfel-unknown-none
EBPF_BIN = target/$(EBPF_TARGET)/release/vigil
VIGIL_BIN = target/release/vigil
PREFIX ?= /usr
BINDIR = $(PREFIX)/bin
LIBDIR = $(PREFIX)/lib/vigil
CONFDIR = /etc/vigil
LOGDIR = /var/log

.PHONY: all build build-ebpf build-vigil install uninstall clean

all: build

build: build-ebpf build-vigil

build-ebpf:
	cargo +nightly build -p vigil-ebpf --target $(EBPF_TARGET) -Z build-std=core --release

build-vigil:
	cargo build -p vigil --release

install: build
	install -Dm755 $(VIGIL_BIN) $(DESTDIR)$(BINDIR)/vigil
	install -Dm644 $(EBPF_BIN) $(DESTDIR)$(LIBDIR)/vigil.ebpf
	install -dm755 $(DESTDIR)$(CONFDIR)
	install -dm755 $(DESTDIR)$(LOGDIR)
	@echo "Run 'vigil init' to create default config files"
	@echo "Run 'rc-service vigil start' or 'systemctl start vigil' to start"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/vigil
	rm -rf $(DESTDIR)$(LIBDIR)
	@echo "Config files in $(CONFDIR) were preserved"

clean:
	cargo clean
