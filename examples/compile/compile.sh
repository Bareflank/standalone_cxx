# !/bin/bash
#
# Copyright (C) 2019 Assured Information Security, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

payload=$1
filecmp=$2
compile=$3

addr_open=$(readelf -sW $filecmp | grep " open\$" | awk '{print $2}')
addr_filesize=$(readelf -sW $filecmp | grep " _Z8filesizei\$" | awk '{print $2}')
addr_filemmap=$(readelf -sW $filecmp | grep " _Z8filemmapim\$" | awk '{print $2}')
addr_exit=$(readelf -sW $filecmp | grep " exit\$" | awk '{print $2}')
addr_malloc=$(readelf -sW $filecmp | grep " malloc\$" | awk '{print $2}')
addr_write=$(readelf -sW $filecmp | grep " write\$" | awk '{print $2}')
addr_mprotect=$(readelf -sW $filecmp | grep " mprotect\$" | awk '{print $2}')
addr_fprintf=$(readelf -sW $filecmp | grep " fprintf\$" | awk '{print $2}')
addr_stderr=$(readelf -sW $filecmp | grep " _IO_2_1_stderr_\$" | awk '{print $2}')

eval "$compile $payload $filecmp $payload.bin $addr_open $addr_filesize $addr_filemmap $addr_exit $addr_malloc $addr_write $addr_mprotect $addr_fprintf $addr_stderr"
