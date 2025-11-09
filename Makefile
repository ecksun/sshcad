.PHONY: lint
lint: bin/golangci-lint
	$< run

.PHONY: clean
clean:
	rm -rf bin/ tmp/

.PHONY: test-mkosi
start-vm:
	$(MAKE) -C ./test/mkosi

GOLANGCI_LINT_VERSION := 2.5.0
bin/golangci-lint: bin/golangci-lint-$(GOLANGCI_LINT_VERSION)
	cp --link $< $@

bin/golangci-lint-$(GOLANGCI_LINT_VERSION): tmp/golangci-lint-$(GOLANGCI_LINT_VERSION)-linux-amd64.tar.gz | bin/
	tar -xzf $< -C tmp/ --strip-components=1 golangci-lint-$(GOLANGCI_LINT_VERSION)-linux-amd64/golangci-lint
	mv tmp/golangci-lint $@
	chmod +x $@
	touch $@

tmp/golangci-lint-$(GOLANGCI_LINT_VERSION)-linux-amd64.tar.gz: | tmp/
	curl -L -o $@ https://github.com/golangci/golangci-lint/releases/download/v$(GOLANGCI_LINT_VERSION)/golangci-lint-$(GOLANGCI_LINT_VERSION)-linux-amd64.tar.gz

bin/ tmp/:
	mkdir -p $@
