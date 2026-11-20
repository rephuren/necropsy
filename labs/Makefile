.PHONY: all clean test
all:
	$(MAKE) -C ret2win
	$(MAKE) -C fmt-leak

test: all
	python3 ret2win/exploit.py
	python3 fmt-leak/exploit.py

clean:
	$(MAKE) -C ret2win clean
	$(MAKE) -C fmt-leak clean
