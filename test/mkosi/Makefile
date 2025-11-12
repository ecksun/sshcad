.PHONY: boot
boot: build/sshcad-test.raw
	sudo mkosi boot

build/trees/build/usr/local/bin/sshcad:
	mkdir -p build/trees/build/usr/local/bin
	cd ../.. && CGO_ENABLED=1 go build -o test/mkosi/$@ ./cmd/sshcad

build/trees/build/etc/systemd/system/sshcad.service: ../../systemd/sshcad.service
	mkdir -p build/trees/build/etc/systemd/system
	cp $< $@

build/trees/build/etc/systemd/system/multi-user.target.wants/sshcad.service: | build/trees/build/etc/systemd/system/multi-user.target.wants/
	ln -sf ../sshcad.service $@

build/trees/build/usr/lib/sysusers.d/sshcad.conf: ../../systemd/sshcad-sysusers.conf
	mkdir -p build/trees/build/usr/lib/sysusers.d
	cp $< $@

build/trees/build/etc/systemd/system/multi-user.target.wants/ build/trees/test/etc/credstore.encrypted/ build/trees/test/var/lib/sshcad/:
	mkdir -p $@

build/trees/test/etc/sshcad/:
	mkdir -p $@
	chmod 755 $@

build/trees/test/%: ../fixtures/trees/test/%
	mkdir -p $(dir $@)
	cp -P $< $@

FIXTURE_FILES := $(shell find ../fixtures/trees/test/ -type f -o -type l)
TEST_TREE_FILES := $(patsubst ../fixtures/trees/test/%,build/trees/test/%,$(FIXTURE_FILES))
build/sshcad-test.raw: \
	build/trees/build/usr/local/bin/sshcad \
	build/trees/build/etc/systemd/system/sshcad.service \
	build/trees/build/etc/systemd/system/multi-user.target.wants/sshcad.service \
	build/trees/build/usr/lib/sysusers.d/sshcad.conf \
	$(TEST_TREE_FILES) \
	mkosi.conf \
	mkosi.repart/10-root.conf \
	| build/trees/test/etc/credstore.encrypted/ \
	build/trees/test/etc/sshcad/ \
	build/trees/test/var/lib/sshcad/
	mkosi build

.PHONY: clean
clean:
	rm -rf build
