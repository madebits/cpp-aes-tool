#/bin/bash

make

test="0"
output=""
input=""
pass=""

function check() 
{
    temp=$(echo -e "${input}")
    if [[ "${output}" != "${temp}" ]] ; then
        echo "Failed: ${test} with ${output}"
        exit 1
    else 
        echo "OK: ${test}"
    fi
}

function checkfail() 
{
    temp=$(echo -e "${input}")
    if [[ "${output}" == "${temp}" ]] ; then
        echo "Failed: ${test}"
        exit 1
    else 
        echo "OK: ${test}"
    fi
}

function setdata() 
{
    test="$1"
    input="$2"
    pass="$3"
}

# regression
setdata R01 "test" "t"
output=$(echo "5RaVj03ZmIoq4Ja8xPbul2CbpA2VtjYl6ROOZ2xcc1ETMx24nx0mnIE4SV3hqvbu" | base64 -d | ./aes -d -p "${pass}" -k 256 -s)
check

setdata R02 "test" "t"
output=$(echo "5RaVj03ZmIoq4Ja8xPbul2CbpA2VtjYl6ROOZ2xcc1ETMx24nx0mnIE4SV3hqvbu" | base64 -d | ./aes -d -p "${pass}" -k 256)
checkfail

setdata R03 "test" "t"
output=$(echo "VY2IaH0XBdGToe/WRc3Yijz9Xafei/eDD1a0G36729RIYzzGekGXDuKG5ChTvLKQsB6onXYW1l/SH4VyKFr8bQ==" | base64 -d | ./aes -d -p "${pass}" -k 256)
check

setdata R04 "test" "t"
output=$(echo "8hAJbxs4kmhLbVkZg2z7Ixe1CPmJmFTKbcsFwB6lkhC1nH/R1BE5H3+SOAL/NCYWOxQ25HSZLg0lbiJKCYQ3QQ==" | base64 -d | ./aes -d -p "${pass}" -k 256 -m)
check

# defaults

setdata D01 "" "t"
output=$(echo -e "${input}" | ./aes -p "${pass}" | ./aes -d -p "${pass}")
check

setdata D02 "0" "t"
output=$(echo -e "${input}" | ./aes -p "${pass}" | ./aes -d -p "${pass}")
check

setdata D03 "01234567" "t"
output=$(echo -e "${input}" | ./aes -p "${pass}" | ./aes -d -p "${pass}")
check

setdata D04 "012345678" "t"
output=$(echo -e "${input}" | ./aes -p "${pass}" | ./aes -d -p "${pass}")
check

setdata D05 "012345678" "t"
output=$(echo -e "${input}" | ./aes -p "${pass}")
checkfail

setdata D06 "012345678" "t"
output=$(echo -e "${input}" | ./aes -p "${pass}" -i - | ./aes -d -p "${pass}" -o -)
check

# keysizes

setdata K01 "012345678" "t"
output=$(echo -e "${input}" | ./aes -p "${pass}" -k 128 | ./aes -d -p "${pass}" -k 128)
check

setdata K02 "012345678" "t"
output=$(echo -e "${input}" | ./aes -p "${pass}" -k 192 | ./aes -d -p "${pass}" -k 192)
check

setdata K03 "012345678" "t"
output=$(echo -e "${input}" | ./aes -p "${pass}" -k 256 | ./aes -d -p "${pass}" -k 256)
check

setdata K04 "012345678" "t"
output=$(echo -e "${input}" | ./aes -p "${pass}" -k 256 | ./aes -d -p "${pass}" -k 128)
checkfail

setdata K05 "012345678" "t"
output=$(echo -e "${input}" | ./aes -p "${pass}" -k 1aa 2>/dev/null | ./aes -d -p "${pass}" -k 128)
checkfail

#pass

setdata P01 "012345678" ""
output=$(echo -e "${input}" | ./aes -p "${pass}" 2>/dev/null | ./aes -d -p "${pass}" 2>/dev/null)
checkfail

setdata P02 "012345678" "0"
output=$(echo -e "${input}" | ./aes -p "${pass}" | ./aes -d -p "${pass}")
check

setdata P03 "012345678" "01234567"
output=$(echo -e "${input}" | ./aes -p "${pass}" | ./aes -d -p "${pass}")
check

setdata P04 "012345678" "012345678"
output=$(echo -e "${input}" | ./aes -p "${pass}" | ./aes -d -p "${pass}")
check

setdata P05 "012345678" "012345678"
output=$(echo -e "${input}" | ./aes -p "${pass}" -k 128 | ./aes -d -p "${pass}" -k 128)
check

# misc

setdata M01 "\n0\n" "t"
output=$(echo -e "${input}" | ./aes -p "${pass}" -c 1 | ./aes -d -p "${pass}" -c 1)
check

setdata M02 "\n0\n" "t"
output=$(echo -e "${input}" | ./aes -p "${pass}" -c 1 | ./aes -d -p "${pass}")
checkfail

setdata M03 "\n0\n" "t"
output=$(echo -e "${input}" | ./aes -p "${pass}" -h 42 | ./aes -d -p "${pass}" -h 42)
check

setdata M04 "\n0\n" "t"
output=$(echo -e "${input}" | ./aes -p "${pass}" -h 42 | ./aes -d -p "${pass}")
checkfail

setdata M05 "\n0\n" "t"
output=$(echo -e "${input}" | ./aes -p "${pass}" -a | ./aes -d -p "${pass}" -a)
check

setdata M06 "\n0\n" "t"
output=$(echo -e "${input}" | ./aes -p "${pass}" -a | ./aes -d -p "${pass}")
checkfail

setdata M07 "\n0\n" "t"
output=$(echo -e "${input}" | ./aes -p "${pass}" -a 6 | ./aes -d -p "${pass}" -a 6)
check

setdata M08 "\n\n0\n\n1\n\n" "t"
output=$(echo -e "${input}" | ./aes -p "${pass}" -a | ./aes -d -p "${pass}" -a)
check

setdata M09 "\n\n0\n\n1\n\n" "t"
output=$(echo -e "${input}" | ./aes -p "${pass}" -a -r /dev/urandom | ./aes -d -p "${pass}" -a)
check

setdata M10 "\n\n0\n\n1\n\n" "t"
output=$(echo -e "${input}" | ./aes -p "${pass}" -a -r /dev/nothing_there_with_this_name1 2>/dev/null | ./aes -d -p "${pass}" -a)
checkfail

setdata M11 "\n\n0\n\n1\n\n" ""
output=$(echo -e "${input}" | ./aes -p p1 -k 256 -a | ./aes -p p2 -k 128 -a | ./aes -d -p p2 -k 128 -a | ./aes -d -p p1 -k 256 -a)

echo Done

make clean
