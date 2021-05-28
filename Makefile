all: Build/Debug/xcodeglut.app/Contents/MacOS/xcodeglut
	lldb Build/Debug/xcodeglut.app/Contents/MacOS/xcodeglut \
		-source lldb.txt 

Build/Debug/xcodeglut.app/Contents/MacOS/xcodeglut:
	xcodebuild -target "xcodeglut (macOS)" -configuration  Debug

clean:
	rm -rf Build DerivedData
	rm -f log.txt

