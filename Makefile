all: Build/Debug/xcodeglut.app/Contents/MacOS/xcodeglut a2c
	lldb Build/Debug/xcodeglut.app/Contents/MacOS/xcodeglut \
		-source lldb.txt 
a2c: amd64_to_c.c
	cc -Wall -o a2c amd64_to_c.c

Build/Debug/xcodeglut.app/Contents/MacOS/xcodeglut:
	xcodebuild -target "xcodeglut (macOS)" -configuration  Debug \
		BUILD_DIR=Build

clean:
	rm -rf Build DerivedData
	rm -f log.txt trace.txt trace.xml 
	rm -rf raw

decompile:
	rm -rf ghi ghi.*
	mkdir -p ghi
	../../Downloads/ghidra_9.2.3_PUBLIC/support/analyzeHeadless . ghi -import \
	raw/glutInit.bin \
	-postscript ./dec.py  \
	-loader BinaryLoader -loader-baseAddr 0x00007fff553191ac \
	-processor "x86:LE:64:default"  -cspec "gcc"

	#Build/Debug/xcodeglut.app/Contents/MacOS \
	#Build/Debug/xcodeglut.app/Contents/MacOS/xcodeglut \
	#-postscript dec.py
	#-postscript Decompile.java


