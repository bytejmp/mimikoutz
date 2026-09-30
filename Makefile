BINARY := mimikoutz
DIST := dist

.PHONY: build clean test test-all

build:
	docker build -t $(BINARY)-builder .
	mkdir -p $(DIST)
	docker run --rm -v $(PWD)/$(DIST):/output $(BINARY)-builder

clean:
	rm -rf $(DIST)

test:
	cat testdata/sample.txt | go run . -f table --stats

test-json:
	cat testdata/sample.txt | go run . -f json

test-csv:
	cat testdata/sample.txt | go run . -f csv

test-grep:
	cat testdata/sample.txt | go run . -f grep

test-hashcat:
	cat testdata/sample.txt | go run . -f hashcat

test-john:
	cat testdata/sample.txt | go run . -f john

test-secretsdump-in:
	go run . -i testdata/secretsdump.txt -f table --stats

test-pypykatz:
	go run . -i testdata/pypykatz.txt -f table --stats

test-cme:
	go run . -i testdata/crackmapexec.txt -f table

test-merge:
	go run . -i testdata/sample.txt -i testdata/secretsdump.txt -i testdata/pypykatz.txt --stats

test-diff:
	go run . -i testdata/secretsdump.txt --diff testdata/baseline.txt -f table

test-filters:
	cat testdata/sample.txt | go run . --has-password --no-machine
	cat testdata/sample.txt | go run . -u admin
	cat testdata/sample.txt | go run . -d TESTLAB --has-hash

test-all: test test-hashcat test-john test-secretsdump-in test-pypykatz test-cme test-merge test-diff
