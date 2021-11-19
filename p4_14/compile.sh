CURRENT=`pwd`

API=$CURRENT/API
common_p4=$CURRENT/common_p4

$script_home/p4_build.sh $CURRENT/countsketch/p414_countsketch.p4 \
    -- P4_NAME="p414_countsketch" \
    P4FLAGS="--no-dead-code-elimination" \
    P4PPFLAGS="-I ${API} -I ${common_p4}"

$script_home/p4_build.sh $CURRENT/countmin/p414_countmin.p4 \
    -- P4_NAME="p414_countmin" \
    P4FLAGS="--no-dead-code-elimination" \
    P4PPFLAGS="-I ${API} -I ${common_p4}"

$script_home/p4_build.sh $CURRENT/hll/p414_hll.p4 \
    -- P4_NAME="p414_hll" \
    P4FLAGS="--no-dead-code-elimination" \
    P4PPFLAGS="-I ${API} -I ${common_p4}"

$script_home/p4_build.sh $CURRENT/univmon/p414_univmon.p4 \
    -- P4_NAME="p414_univmon" \
    P4FLAGS="--no-dead-code-elimination" \
    P4PPFLAGS="-I ${API} -I ${common_p4}"
