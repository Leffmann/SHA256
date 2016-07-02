
default:	build/sha256

clean:
		rm -rf build

dist:		build/sha256
		mkdir -p build/source
		cp sha256.c sha256acc.s build/source/
		cd build  &&  lha -a sha256.lha  sha256 source/sha256.c source/sha256acc.s

build/sha256:	sha256.c sha256acc.s
		mkdir -p build
		vasmm68k_mot -quiet -esc -spaces -nosym -Fhunk -o build/sha256acc.o  sha256acc.s
		vc -c99 -O1 -sc -sd -lvcs -o build/sha256  sha256.c build/sha256acc.o
