.PHONY: test
test: build/container
	podman run --rm --detach --publish 8443:8443 --name sshcad-test sshcad-test
	go test ../ -server https://localhost:8443
	podman stop "sshcad-test" 

build/sshcad: | build/
	cd ../.. && CGO_ENABLED=1 go build -o test/podman/$@ ./cmd/sshcad

TEST_TREE_FILES := $(shell find ../fixtures/trees/test/ -type f -o -type l)
BUILD_TEST_TREE_FILES := $(patsubst ../fixtures/trees/test/%,build/trees/test/%,$(TEST_TREE_FILES))
build/container: Containerfile \
	build/sshcad \
	build/systemd/sshcad.service \
	build/systemd/sshcad-sysusers.conf \
	$(BUILD_TEST_TREE_FILES) \
	| build/
	podman build -f Containerfile -t sshcad-test ./build/
	touch $@

build/systemd/%: ../../systemd/% | build/systemd/
	cp $< $@

build/trees/test/%: ../fixtures/trees/test/%
	mkdir -p $(dir $@)
	cp -P $< $@

build/ build/systemd/ build/trees/:
	mkdir -p $@

.PHONY: clean
clean:
	rm -rf build/
	-podman stop sshcad-test
