all: Build/Debug/xcodeglut.app/Contents/MacOS/xcodeglut a2c
	lldb Build/Debug/xcodeglut.app/Contents/MacOS/xcodeglut \
		-source lldb.txt 
a2c: amd64_to_c.c
	cc -Wall -o a2c amd64_to_c.c

Build/Debug/xcodeglut.app/Contents/MacOS/xcodeglut:
	xcodebuild -target "xcodeglut (macOS)" -configuration  Debug

clean:
	rm -rf Build DerivedData
	rm -f log.txt
	rm -rf raw

