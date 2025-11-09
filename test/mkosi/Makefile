.PHONY: boot
boot: build/sshcad-test.raw
	sudo mkosi boot

trees/build/usr/local/bin/sshcad:
	mkdir -p trees/build/usr/local/bin
	cd ../.. && CGO_ENABLED=1 go build -o test/mkosi/$@ ./cmd/sshcad

trees/build/etc/systemd/system/sshcad.service: ../../systemd/sshcad.service
	mkdir -p trees/build/etc/systemd/system
	cp $< $@

trees/build/etc/systemd/system/multi-user.target.wants/sshcad.service: | trees/build/etc/systemd/system/multi-user.target.wants/
	ln -sf ../sshcad.service $@

trees/build/usr/lib/sysusers.d/sshcad.conf: ../../systemd/sshcad-sysusers.conf
	mkdir -p trees/build/usr/lib/sysusers.d
	cp $< $@

trees/build/etc/systemd/system/multi-user.target.wants/ trees/test/etc/credstore.encrypted/ trees/test/var/lib/sshcad/:
	mkdir -p $@

trees/test/etc/sshcad/:
	mkdir -p $@
	chmod 755 $@

TREE_FILES := $(shell find trees -type f)
build/sshcad-test.raw: \
	trees/build/usr/local/bin/sshcad \
	trees/build/etc/systemd/system/sshcad.service \
	trees/build/etc/systemd/system/multi-user.target.wants/sshcad.service \
	trees/build/usr/lib/sysusers.d/sshcad.conf \
	$(TREE_FILES) \
	mkosi.conf \
	mkosi.repart/10-root.conf \
	| trees/test/etc/credstore.encrypted/ \
	trees/test/etc/sshcad/ \
	trees/test/var/lib/sshcad/
	mkosi build

.PHONY: clean
clean:
	rm -rf build
	rm -rf trees/build
