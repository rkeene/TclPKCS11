#! /bin/sh

make distclean

CCROOT="/home/rkeene/root/cross-compilers"
CC="${CCROOT}/${TARGET}/bin/${TARGET}-gcc" ./configure --host="${TARGET}" --with-tcl="$(pwd)/build/${SHORTTARGET}"

# Replace version with the version
. build/makearch.info
sed "s/@@VERS@@/${VERS}/g" Makefile > Makefile.new && cat Makefile.new > Makefile
rm -f Makefile.new

gmake
"${CCROOT}/${TARGET}/bin/${TARGET}-strip" -x tclpkcs11.so
