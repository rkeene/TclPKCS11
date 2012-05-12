#! /bin/sh

make distclean

rm -rf .tmp
mkdir .tmp

(
	cd .tmp || exit 1

	wget -O sdk.tar.gz "http://www.rkeene.org/devel/kitcreator/kitbuild/nightly/libtclkit-8.5.11-${SHORTTARGET}-kitdll-sdk.tar.gz" || \
		wget -O sdk.tar.gz "http://www.rkeene.org/devel/kitcreator/kitbuild/nightly/libtclkit-8.5.11-${SHORTTARGET}-kitdll-xcompile-sdk.tar.gz"

	tar --strip-components=1 -xf sdk.tar.gz

	rm -f sdk.tar.gz
) || exit 1

TCLKIT_SDK_DIR="$(pwd)/.tmp"
export TCLKIT_SDK_DIR

CCROOT="/home/rkeene/root/cross-compilers"
CC="${CCROOT}/${TARGET}/bin/${TARGET}-gcc" ./configure --host="${TARGET}" --with-tcl="$(pwd)/.tmp/lib"

# Replace version with the version
. build/makearch.info
sed "s/@@VERS@@/${VERS}/g" Makefile > Makefile.new && cat Makefile.new > Makefile
rm -f Makefile.new

gmake
"${CCROOT}/${TARGET}/bin/${TARGET}-strip" -x tclpkcs11.so

rm -rf .tmp
