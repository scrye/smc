.PHONY: all

all:
	$(MAKE) -C smkex
	$(MAKE) -C demo
	$(MAKE) -C apps

.PHONY: clean

clean:
	$(MAKE) -C smkex clean
	$(MAKE) -C apps clean
	$(MAKE) -C demo clean
