default: test

.common.makefile:
	curl -fsSL -o $@ https://gitlab.com/bsm/misc/raw/master/make/go/common.makefile

include .common.makefile

# go get -u github.com/dave/rebecca/cmd/becca
README.md: README.md.tpl
	becca -package github.com/bsm/macdaddy
