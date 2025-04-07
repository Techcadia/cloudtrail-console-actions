ifndef ARCH
override ARCH = arm64
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
	-tags lambda.norpc \
	-o ./bin/main \
	main.go

zip: build
	zip ./dist/function_$(ARCH).zip \
	-j \
	./bin/main
	cd dist && find . -type f -name '*.zip' | xargs sha256sum >> sha256sums.txt
