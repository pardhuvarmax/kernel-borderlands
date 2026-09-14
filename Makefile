PREFIX  ?= /usr/local
DESTDIR ?=

.PHONY: build install

build:
	$(MAKE) -C kb-core
	$(MAKE) -C kb-control-plane build
	cd kb-checker && cargo build --release
	cd kb-op/kbctl && go build -o kbctl .
	cd kb-op/kb-tui && cargo build --release

install: build
	install -Dm755 kb-core/build/kbd_sensor              $(DESTDIR)$(PREFIX)/bin/kbd_sensor
	install -Dm755 kb-control-plane/bin/kbd               $(DESTDIR)$(PREFIX)/bin/kbd
	install -Dm755 kb-checker/target/release/kb-checker   $(DESTDIR)$(PREFIX)/bin/kb-checker
	install -Dm755 kb-op/kbctl/kbctl                       $(DESTDIR)$(PREFIX)/bin/kbctl
	install -Dm755 kb-op/kb-tui/target/release/kb-tui      $(DESTDIR)$(PREFIX)/bin/kb-tui
