#!/bin/sh

export SRCDIR=`dirname $0`
. `dirname $0`/setup-env.sh

for TEST_PKG in ${SRCDIR}/[0-9][0-9][0-9]-*.tpkg
do
	"${TPKG}" $* exe "${TEST_PKG}"
done
"${TPKG}" r
