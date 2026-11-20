.PHONY: all clean
all: vuln
vuln: vuln.c
	$(CC) -O0 -g -fno-stack-protector -fno-pie -no-pie -Wno-format-security -o $@ $<
clean:
	rm -f vuln
