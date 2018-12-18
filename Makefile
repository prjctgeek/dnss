.PHONY: all clean install uninstall deps

PREFIX = /usr/local
SHELL =/bin/bash
BUILD = build

ifeq ($(GOROOT),)
GOBUILD = go build
GOGET = go get -d -v
GOGET_UPDATE = go get -d -u -v
GOTEST = go test
else
GOBUILD = $(GOROOT)/bin/go build
GOGET = $(GOROOT)/bin/go get -d -v
GOGET_UPDATE = $(GOROOT)/bin/go get -d -u -v
GOTEST = $(GOROOT)/bin/go test
endif


all: build test
test:
	$(GOTEST)
build:
	$(GOBUILD)

$(BUILD)/:
	mkdir -p $@

lambda: $(BUILD)
	{ set -e ;\
	env GOOS=linux GOARCH=amd64 $(GOBUILD) -o ./build/main  ;\
	cd build ;\
	zip -j lambda-upload.zip * ;\
	}

clean:
	rm -f $(BUILD)/*
