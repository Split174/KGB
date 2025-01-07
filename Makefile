.PHONY: clean build

build:
	go build -o kgb

clean:
	rm -f kgb
