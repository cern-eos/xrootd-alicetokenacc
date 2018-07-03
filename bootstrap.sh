#!/bin/sh

libtoolize --copy --force --install
aclocal
automake  --add-missing --copy --force-missing
autoconf

