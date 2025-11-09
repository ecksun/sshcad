.PHONY: boot
boot: build/sshca-serv-test.raw
	sudo mkosi boot

trees/build/usr/local/bin/sshca-serv:
	mkdir -p trees/build/usr/local/bin
	cd ../.. && CGO_ENABLED=1 go build -o test/mkosi/$@ ./cmd/sshca-serv

trees/build/etc/systemd/system/sshca-serv.service: ../../systemd/sshca-serv.service
	mkdir -p trees/build/etc/systemd/system
	cp $< $@

trees/build/etc/systemd/system/multi-user.target.wants/sshca-serv.service: | trees/build/etc/systemd/system/multi-user.target.wants/
	ln -sf ../sshca-serv.service $@

trees/build/usr/lib/sysusers.d/sshca-serv.conf: ../../systemd/sshca-serv-sysusers.conf
	mkdir -p trees/build/usr/lib/sysusers.d
	cp $< $@

trees/build/etc/systemd/system/multi-user.target.wants/ trees/test/etc/credstore.encrypted/ trees/test/var/lib/sshca-serv/:
	mkdir -p $@

trees/test/etc/sshca-serv/:
	mkdir -p $@
	chmod 755 $@

TREE_FILES := $(shell find trees -type f)
build/sshca-serv-test.raw: \
	trees/build/usr/local/bin/sshca-serv \
	trees/build/etc/systemd/system/sshca-serv.service \
	trees/build/etc/systemd/system/multi-user.target.wants/sshca-serv.service \
	trees/build/usr/lib/sysusers.d/sshca-serv.conf \
	$(TREE_FILES) \
	mkosi.conf \
	mkosi.repart/10-root.conf \
	| trees/test/etc/credstore.encrypted/ \
	trees/test/etc/sshca-serv/ \
	trees/test/var/lib/sshca-serv/
	mkosi build

.PHONY: clean
clean:
	rm -rf build
	rm -rf trees/build
