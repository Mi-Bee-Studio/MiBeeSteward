#!/bin/sh
# detect-lans.test.sh — stubbed-uci scenarios for detect-lans.sh (#688).
#
# Runs anywhere POSIX sh runs (dev box, CI, rig): builds a fake `uci` fed by
# fixture files, then asserts detect-lans.sh output for single-LAN, CIDR-form
# ipaddr (iStoreOS field form), multi-LAN, dhcp-wan-skipped, and
# nothing-derivable cases. Each scenario runs twice — once on the normal
# PATH (ipcalc branch when ipcalc exists) and once on a stripped PATH (pure
# ash math branch) — and requires both to agree, so whichever branch a
# machine exercises, the other is pinned to the same answer.
#
# usage: sh deploy/openwrt/detect-lans.test.sh   (exit 0 = all pass)
set -u

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TMP=$(mktemp -d 2>/dev/null) || { echo "FAIL: mktemp"; exit 1; }
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin"

# stub uci: get → value from fixture; show network → the network.* lines.
cat > "$TMP/bin/uci" <<'EOS'
#!/bin/sh
[ "${1:-}" = "-q" ] && shift
case "${1:-}" in
    get) grep -E "^$2=" "$UCI_FIXTURE" 2>/dev/null | head -n1 | cut -d= -f2- ;;
    show) [ "${2:-}" = network ] && grep -E '^network\.' "$UCI_FIXTURE" 2>/dev/null ;;
esac
exit 0
EOS
chmod +x "$TMP/bin/uci"

# run <fixture> <mode>: mode pure = no ipcalc on PATH, full = normal PATH.
run() {
    if [ "$2" = pure ]; then
        UCI_FIXTURE="$1" PATH="$TMP/bin:/bin:/usr/bin" sh "$DIR/detect-lans.sh" 2>/dev/null
    else
        UCI_FIXTURE="$1" PATH="$TMP/bin:$PATH" sh "$DIR/detect-lans.sh" 2>/dev/null
    fi
}

fail=0
check() {
    if [ "$2" = "$3" ]; then
        echo "ok   $1"
    else
        echo "FAIL $1"
        echo "     expected: [$2]"
        echo "     got:      [$3]"
        fail=1
    fi
}

scenario() { # name fixture expected
    _out_full="$(run "$2" full)"
    _out_pure="$(run "$2" pure)"
    check "$1 (full path)" "$3" "$_out_full"
    check "$1 (pure ash)" "$3" "$_out_pure"
}

# 1. classic single lan: bare ipaddr + netmask.
F="$TMP/single"; cat > "$F" <<'EOF'
network.lan=interface
network.lan.proto=static
network.lan.ipaddr=192.168.1.1
network.lan.netmask=255.255.255.0
network.wan=interface
network.wan.proto=dhcp
EOF
scenario "single lan" "$F" "lan 192.168.1.0/24"

# 2. iStoreOS field form: CIDR ipaddr, no netmask key (#518's discovery).
F="$TMP/cidrform"; cat > "$F" <<'EOF'
network.lan=interface
network.lan.proto=static
network.lan.ipaddr=192.168.60.1/24
EOF
scenario "cidr-form ipaddr" "$F" "lan 192.168.60.0/24"

# 3. multi-LAN: lan + lan2 static (the #688 headline case).
F="$TMP/multi"; cat > "$F" <<'EOF'
network.lan=interface
network.lan.proto=static
network.lan.ipaddr=192.168.62.1
network.lan.netmask=255.255.255.0
network.lan2=interface
network.lan2.proto=static
network.lan2.ipaddr=192.168.63.1
network.lan2.netmask=255.255.255.0
network.wan=interface
network.wan.proto=pppoe
EOF
scenario "multi-lan" "$F" "lan 192.168.62.0/24
lan2 192.168.63.0/24"

# 4. non-/24 mask on the secondary segment.
F="$TMP/mask28"; cat > "$F" <<'EOF'
network.lan=interface
network.lan.proto=static
network.lan.ipaddr=10.1.0.1
network.lan.netmask=255.255.255.0
network.dmz=interface
network.dmz.proto=static
network.dmz.ipaddr=10.2.0.17
network.dmz.netmask=255.255.255.240
EOF
scenario "secondary /28" "$F" "lan 10.1.0.0/24
dmz 10.2.0.16/28"

# 5. nothing derivable: dhcp everywhere → empty output, exit 0.
F="$TMP/none"; cat > "$F" <<'EOF'
network.lan=interface
network.lan.proto=dhcp
network.wan=interface
network.wan.proto=dhcp
EOF
scenario "nothing derivable" "$F" ""

[ "$fail" = 0 ] && echo "-> all detect-lans scenarios passed"
exit "$fail"
