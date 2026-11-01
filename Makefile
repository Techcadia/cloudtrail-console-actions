ifndef ARCH
override ARCH = arm64
endif

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: default clean build zip release test vet

default: build

clean:
	rm -rf ./bin ./dist

test:
	go test ./...

vet:
	go vet ./...

build:
	@mkdir -p ./bin
	GOOS=linux \
	GOARCH=$(ARCH) \
	CGO_ENABLED=0 \
	go build \
	-tags lambda.norpc \
	-trimpath \
	-ldflags "-s -w -X main.version=$(VERSION)" \
	-o ./bin/bootstrap \
	./cmd/lambda

# zip packages one architecture. dist/ accumulates zips across ARCH values and
# sha256sums.txt is regenerated to cover all of them.
zip: build
	@mkdir -p ./dist
	rm -f ./dist/function_$(ARCH).zip
	zip ./dist/function_$(ARCH).zip \
	-j \
	./bin/bootstrap
	cd dist && sha256sum function_*.zip > sha256sums.txt

# release builds every published architecture from a clean tree.
release: clean
	$(MAKE) zip ARCH=arm64
	$(MAKE) zip ARCH=amd64
