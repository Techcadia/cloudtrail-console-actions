ifndef ARCH
override ARCH = arm64
endif

.PHONY: default clean build zip test vet

default: build

clean:
	@test -d "./bin" && rm -rf ./bin/* || true
	@test -d "./dist" && rm -rf ./dist/* || true
	@mkdir -p ./bin
	@mkdir -p ./dist

test:
	go test ./...

vet:
	go vet ./...

build: clean
	GOOS=linux \
	GOARCH=$(ARCH) \
	CGO_ENABLED=0 \
	go build \
	-tags lambda.norpc \
	-trimpath \
	-ldflags "-s -w" \
	-o ./bin/bootstrap \
	./cmd/lambda

zip: build
	zip ./dist/function_$(ARCH).zip \
	-j \
	./bin/bootstrap
	cd dist && find . -type f -name '*.zip' | xargs sha256sum >> sha256sums.txt
