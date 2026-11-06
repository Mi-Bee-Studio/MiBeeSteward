#!/bin/sh
# detect-lans.sh — enumerate the router's LAN segments from uci (#688).
#
# One "<interface> <base/prefix>" line per detected LAN, "lan" first, other
# static interfaces in uci order. Multi-LAN routers (lan2 / extra br-xxx
# bridges) previously surfaced only network.lan — the other segments never
# reached the generated config nor the operator's attention.
#
# Self-contained POSIX sh (dash/busybox ash): runs standalone for tests with
# a stubbed uci on PATH (see detect-lans.test.sh), and is shipped next to
# install.sh in the tar.gz and .ipk packages. Detection is best-effort: any
# failure just omits a line, never aborts an install.
#
# This file must contain NO CR bytes (LuCI/opkg parsers choke on CRLF;
# make package-openwrt strips them at package time and make check-openwrt
# validates the committed copies).
set -u

# ── pure-ash IPv4 math (no ipcalc dependency) ──────────────────────────────
# Same fallbacks install.sh has always carried, duplicated so this script
# runs anywhere (busybox ipcalc is usually present, but not guaranteed).

mask_to_prefix() {
    # dotted mask → prefix length; empty on a non-contiguous/invalid mask.
    # Same per-octet rule the installer always carried: non-255 octets are
    # only legal BEFORE any non-255 has been seen (then only 0 may follow)
    # — the guard must NOT reject the octet that first opens the zero run.
    _mt_mask="${1:?}"
    _mt_prefix=0
    _mt_zero=0
    _mt_rest="$_mt_mask"
    while [ -n "$_mt_rest" ]; do
        _mt_oct="${_mt_rest%%.*}"
        case "$_mt_rest" in
            *.*) _mt_rest="${_mt_rest#*.}" ;;
            *)   _mt_rest="" ;;
        esac
        case "$_mt_oct" in
            255) [ "$_mt_zero" = 0 ] || return 1; _mt_prefix=$((_mt_prefix + 8)) ;;
            254) [ "$_mt_zero" = 0 ] || return 1; _mt_prefix=$((_mt_prefix + 7)); _mt_zero=1 ;;
            252) [ "$_mt_zero" = 0 ] || return 1; _mt_prefix=$((_mt_prefix + 6)); _mt_zero=1 ;;
            248) [ "$_mt_zero" = 0 ] || return 1; _mt_prefix=$((_mt_prefix + 5)); _mt_zero=1 ;;
            240) [ "$_mt_zero" = 0 ] || return 1; _mt_prefix=$((_mt_prefix + 4)); _mt_zero=1 ;;
            224) [ "$_mt_zero" = 0 ] || return 1; _mt_prefix=$((_mt_prefix + 3)); _mt_zero=1 ;;
            192) [ "$_mt_zero" = 0 ] || return 1; _mt_prefix=$((_mt_prefix + 2)); _mt_zero=1 ;;
            128) [ "$_mt_zero" = 0 ] || return 1; _mt_prefix=$((_mt_prefix + 1)); _mt_zero=1 ;;
            0)   _mt_zero=1 ;;
            *)   return 1 ;;
        esac
    done
    echo "$_mt_prefix"
}

ip_mask_base() {
    # network base of ip under dotted mask, pure shell
    _imb_ip="${1:?}"; _imb_mask="${2:?}"
    _imb_out=""
    _imb_i=0
    while [ "$_imb_i" -lt 4 ]; do
        _imb_i=$((_imb_i + 1))
        _imb_o="$(echo "$_imb_ip" | cut -d. -f$_imb_i)"
        _imb_m="$(echo "$_imb_mask" | cut -d. -f$_imb_i)"
        _imb_o=${_imb_o:-0}; _imb_m=${_imb_m:-0}
        _imb_b=$(( (_imb_o + 0) & (_imb_m + 0) ))
        if [ -z "$_imb_out" ]; then _imb_out="$_imb_b"; else _imb_out="$_imb_out.$_imb_b"; fi
    done
    echo "$_imb_out"
}

# prefix_to_mask: dotted mask for the prefixes routers actually use.
prefix_to_mask() {
    case "$1" in
        8)  echo "128.0.0.0" ;;
        16) echo "255.255.0.0" ;;
        24) echo "255.255.255.0" ;;
        25) echo "255.255.255.128" ;;
        26) echo "255.255.255.192" ;;
        27) echo "255.255.255.224" ;;
        28) echo "255.255.255.240" ;;
        29) echo "255.255.255.248" ;;
        30) echo "255.255.255.252" ;;
        *)  return 1 ;;
    esac
}

# derive_cidr <ipaddr> <netmask>: "base/prefix" or empty. Both inputs may be
# empty; ipaddr may carry a CIDR suffix (iStoreOS 24.10 field form) whose
# prefix can synthesize the mask when netmask is absent.
derive_cidr() {
    _dc_ip="${1:-}"
    _dc_mask="${2:-}"
    _dc_prefix_from_ip=""
    case "$_dc_ip" in
        */*) _dc_prefix_from_ip="${_dc_ip##*/}"; _dc_ip="${_dc_ip%%/*}" ;;
    esac
    [ -n "$_dc_ip" ] || return 0
    if [ -z "$_dc_mask" ] && [ -n "$_dc_prefix_from_ip" ]; then
        _dc_mask="$(prefix_to_mask "$_dc_prefix_from_ip" || true)"
    fi
    [ -n "$_dc_mask" ] || return 0
    if command -v ipcalc >/dev/null 2>&1; then
        _dc_eval="$(ipcalc -pn "$_dc_ip" "$_dc_mask" 2>/dev/null || true)"
        _dc_net=""; _dc_pfx=""
        eval "$(echo "$_dc_eval" | grep -E '^(NET|PREFIX)=' || true)"
        if [ -n "${_dc_net:-}" ] && [ -n "${_dc_pfx:-}" ]; then
            echo "$_dc_net/$_dc_pfx"
            return 0
        fi
    fi
    _dc_pfx="$(mask_to_prefix "$_dc_mask" 2>/dev/null || true)"
    [ -n "$_dc_pfx" ] || return 0
    echo "$(ip_mask_base "$_dc_ip" "$_dc_mask")/$_dc_pfx"
}

# ── enumerate interfaces ───────────────────────────────────────────────────
# "lan" first (the router's primary segment: it drives the generated
# config's network.* identity), then every OTHER static interface in uci
# order. proto dhcp/pppoe segments have no derivable on-link subnet (their
# address is leased), so they are skipped by design.

emit_ifc() {
    _ei_ifc="$1"
    _ei_proto="$(uci -q get "network.$_ei_ifc.proto" 2>/dev/null || true)"
    [ "$_ei_proto" = "static" ] || return 0
    _ei_ip="$(uci -q get "network.$_ei_ifc.ipaddr" 2>/dev/null || true)"
    _ei_mask="$(uci -q get "network.$_ei_ifc.netmask" 2>/dev/null || true)"
    _ei_cidr="$(derive_cidr "$_ei_ip" "$_ei_mask" || true)"
    [ -n "$_ei_cidr" ] || return 0
    echo "$_ei_ifc $_ei_cidr"
}

emit_ifc lan

uci -q show network 2>/dev/null | while IFS='=' read -r _lhs _rhs; do
    # `uci show` lines look like "network.lan2=interface": split by IFS above,
    # so match the REJOINED form (matching _lhs alone can never carry the
    # "=interface" suffix).
    case "${_lhs}=${_rhs}" in
        network.*=interface) ;;
        *) continue ;;
    esac
    _ifc="${_lhs#network.}"
    _ifc="${_ifc%=}"
    [ "$_ifc" = "lan" ] && continue
    case "$_ifc" in
        *.*) continue ;; # network.X.Y=... leftovers must not match above anyway
    esac
    emit_ifc "$_ifc"
done
