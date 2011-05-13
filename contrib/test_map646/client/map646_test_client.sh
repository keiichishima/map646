#!/bin/sh

if [ $# -ne 3 ];
then
echo "usage: <V4 Server Addr>, <V6 Server Addr>, <Server Port>"
exit
fi

echo -e "check 4to6 mapping...\n"

ping -c 2 -W 1 $1 > /dev/null

if [ $? -eq 0 ];
then
echo -e "4to6: ICMP success"
else
echo -e "4to6: ICMP failed"
fi

./map646_test_client "-4" $1 "echo message" $3

echo -e "\ncheck 6to6 mapping...\n"

ping6 -c 2 -W 1 $2 > /dev/null

if [ $? -eq 0 ];
then
echo -e "6to6: ICMP success"
else
echo -e "6to6: ICMP failed"
fi

./map646_test_client "-6" $2 "echo message" $3

