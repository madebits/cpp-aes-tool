#/bin/bash -x

#set -e
#set -o pipefail

make

if [ "$?" != 0 ]; then
    exit 1
fi

COMMON="-c 1024"

test="0"
output=""
input=""
pass=""

function check()
{
    echo "I: [${input}] O: [${output}]"
    if [ "${input}" != "${output}" ] ; then
        echo "Failed: [${test}] with [${temp}]"
        exit 1
    else
        echo "OK: ${test}"
    fi
}

function checkfail()
{
    echo "I: [${input}] O: [${output}]"
    if [ "${input}" = "${output}" ] ; then
        echo "Failed: [${test}] with [${output}]"
        exit 1
    else
        echo "OK: ${test}"
    fi
}

function setdata()
{
    echo "preparing $1 ..."
    test="$1"
    input="$2"
    pass="$3"
}

# regression
setdata R01 "test" "t"
output=$(echo "5RaVj03ZmIoq4Ja8xPbul2CbpA2VtjYl6ROOZ2xcc1ETMx24nx0mnIE4SV3hqvbu" | base64 -d | ./aes -a -m -d -p "${pass}" -k 256 -s $COMMON)
check

setdata R02 "test" "t"
output=$(echo "5RaVj03ZmIoq4Ja8xPbul2CbpA2VtjYl6ROOZ2xcc1ETMx24nx0mnIE4SV3hqvbu" | base64 -d | ./aes -a -m -d -p "${pass}" -k 256 $COMMON)
checkfail

setdata R03 "test" "t"
output=$(echo "VY2IaH0XBdGToe/WRc3Yijz9Xafei/eDD1a0G36729RIYzzGekGXDuKG5ChTvLKQsB6onXYW1l/SH4VyKFr8bQ==" | base64 -d | ./aes -a -m -d -p "${pass}" -k 256 $COMMON)
check

setdata R04 "test" "t"
output=$(echo "8hAJbxs4kmhLbVkZg2z7Ixe1CPmJmFTKbcsFwB6lkhC1nH/R1BE5H3+SOAL/NCYWOxQ25HSZLg0lbiJKCYQ3QQ==" | base64 -d | ./aes -a -d -p "${pass}" -k 256 $COMMON)
check

setdata R05 "test" "t"
output=$(echo -n "3Lw3LwGl///luvv44USlJwrebp0tV9pWHRmlR+s88pZWCQSGRqHr4CVwzEL9yZ88ve7KHtONZwCP0+m9ItH053rmCu2/b1E4rFKcAgEmGXWL37dVnVzCB+xGFevQsJIAX+eDHvXTytVW1qnLWERrdH+lZugD2xcJzPXrQRm9J3k=" | base64 -d | ./aes -d -p "${pass}" -k 256 $COMMON)
check

# defaults

setdata D01 "" "t"
output=$(echo -n "${input}" | ./aes -p "${pass}" $COMMON | ./aes -d -p "${pass}" $COMMON)
check

setdata D02 "0" "t"
output=$(echo -n "${input}" | ./aes -p "${pass}" $COMMON | base64 | base64 -d | ./aes -d -p "${pass}" $COMMON)
check

setdata D03 "01234567" "t"
output=$(echo -n "${input}" | ./aes -p "${pass}" $COMMON | ./aes -d -p "${pass}" $COMMON)
check

setdata D04 "012345678" "t"
output=$(echo -n "${input}" | ./aes -p "${pass}" $COMMON | ./aes -d -p "${pass}" $COMMON)
check

setdata D05 "012345678" "t"
output=$(echo -n "${input}" | ./aes -p "${pass}" $COMMON)
checkfail

setdata D06 "012345678" "t"
output=$(echo -n "${input}" | ./aes -p "${pass}" -i - $COMMON | ./aes -d -p "${pass}" -o - $COMMON)
check

# keysizes

setdata K01 "012345678" "t"
output=$(echo -n "${input}" | ./aes -p "${pass}" -k 128 $COMMON | ./aes -d -p "${pass}" -k 128 $COMMON)
check

setdata K02 "012345678" "t"
output=$(echo -n "${input}" | ./aes -p "${pass}" -k 192 $COMMON | ./aes -d -p "${pass}" -k 192 $COMMON)
check

setdata K03 "012345678" "t"
output=$(echo -n "${input}" | ./aes -p "${pass}" -k 256 $COMMON | ./aes -d -p "${pass}" -k 256 $COMMON)
check

setdata K04 "012345678" "t"
output=$(echo -n "${input}" | ./aes -p "${pass}" -k 256 $COMMON | ./aes -d -p "${pass}" -k 128 $COMMON)
checkfail

setdata K05 "012345678" "t"
output=$(echo -n "${input}" | ./aes -p "${pass}" -k 1aa $COMMON 2>/dev/null | ./aes -d -p "${pass}" -k 128 $COMMON)
checkfail

#pass

setdata P01 "012345678" ""
output=$(echo -n "${input}" | ./aes -p "${pass}" $COMMON 2>/dev/null | ./aes -d -p "${pass}" $COMMON 2>/dev/null)
checkfail

setdata P02 "012345678" "0"
output=$(echo -n "${input}" | ./aes -p "${pass}" $COMMON | tee last.out | ./aes -d -p "${pass}" $COMMON)
check

setdata P03 "012345678" "01234567"
output=$(echo -n "${input}" | ./aes -p "${pass}" $COMMON | tee last.out | ./aes -d -p "${pass}" $COMMON)
check

setdata P04 "012345678" "012345678"
output=$(echo -n "${input}" | ./aes -p "${pass}" $COMMON | tee last.out  | ./aes -d -p "${pass}" $COMMON)
check

setdata P05 "012345678" "012345678"
output=$(echo -n "${input}" | ./aes -p "${pass}" -k 128 $COMMON | tee last.out | ./aes -d -p "${pass}" -k 128 $COMMON)
check

# misc

setdata M01 "\n0\n" "t"
output=$(echo -n "${input}" | ./aes -p "${pass}" $COMMON | tee last.out | ./aes -d -p "${pass}"  $COMMON)
check

setdata M02 "\n0\n" "t"
output=$(echo -n "${input}" | ./aes -p "${pass}" $COMMON | tee last.out | ./aes -d -p "${pass}" $COMMON)
check

setdata M03 "0123456789abcdef" "t"
output=$(echo -n "${input}" | ./aes -p "${pass}"  $COMMON | tee last.out | ./aes -d -p "${pass}" $COMMON)
check

setdata M04 "0123456789abcdef0123456789abcdef" "t"
output=$(echo -n "${input}" | ./aes -p "${pass}" $COMMON | tee last.out | ./aes -d -p "${pass}" $COMMON)
check

setdata M05 "0123456789abcdef0" "t"
output=$(echo -n "${input}" | ./aes -p "${pass}" $COMMON  | tee last.out | ./aes -d -p "${pass}" $COMMON)
check

echo Done --------------------

make clean
