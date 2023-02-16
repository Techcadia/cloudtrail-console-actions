ifndef ARCH
override ARCH = amd64
endif

.PHONY: clean, build, zip
default: build

clean:
	@test -d "./bin" && rm -rf ./bin/* || true
	@test -d "./dist" && rm -rf ./dist/* || true
	@mkdir -p ./bin
	@mkdir -p ./dist

build: clean
	GOOS=linux \
	GOARCH=$(ARCH) \
	go build \
	-o ./bin/main \
	main.go

zip: build
	zip ./dist/function.zip \
	-j \
	./bin/main
