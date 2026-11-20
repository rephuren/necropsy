.PHONY: all clean
all: vuln
vuln: vuln.c
	$(CC) -O0 -g -fno-stack-protector -fno-pie -no-pie -z noexecstack -o $@ $<
clean:
	rm -f vuln
