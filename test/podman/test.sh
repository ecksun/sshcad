#!/bin/bash
set -e

repo_root=$(git rev-parse --show-toplevel)

CGO_ENABLED=1 go build -o "$repo_root/test/podman/sshcad" "$repo_root/cmd/sshcad"
podman build -f test/podman/Containerfile -t sshcad-test "$repo_root"
podman run --rm --detach --publish 8443:8443 --name sshcad-test sshcad-test 

(
    cd "$repo_root/test/mkosi"
    go test -server https://localhost:8443
)

podman stop "sshcad-test" 
