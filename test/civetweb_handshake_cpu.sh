#!/bin/bash
# Regression check for the mbedTLS 100% CPU busy-spin on stalled TLS handshakes
# (pi-hole/FTL#2882). A client that opens a TCP connection to the HTTPS port but
# never sends a ClientHello must not peg a webserver worker thread. Before the
# fix, each such connection spun a full CPU core in the mbedTLS handshake loop.
#
# Opens several stalled handshakes (plain TCP, no ClientHello), samples FTL's
# CPU time across a short window, and exits non-zero if it exceeds a generous
# threshold. Prints the measured value either way.
#
# Usage: civetweb_handshake_cpu.sh [host] [port] [connections] [window_seconds]

set -u

HOST="${1:-127.0.0.1}"
PORT="${2:-443}"
CONNS="${3:-6}"
WINDOW="${4:-3}"
# Pass threshold in percent of a single core. The spin pegs ~100% per
# connection (hundreds of %); the fix stays near zero, so 50% has wide margin.
LIMIT=50

pid="$(cat /run/pihole-FTL.pid)"

# /proc/<pid>/stat utime+stime, summed over all threads (clock ticks, 1/100 s
# per core). FTL's comm field contains no spaces, so positional fields are safe.
cpu_ticks() {
	local a
	read -ra a < "/proc/${pid}/stat"
	echo "$(( a[13] + a[14] ))"
}

# Open the stalled connections: each subshell holds a bare TCP socket open
# (no TLS ClientHello is ever sent) for longer than the measurement window.
for _ in $(seq 1 "${CONNS}"); do
	( exec 3<>"/dev/tcp/${HOST}/${PORT}"; sleep $(( WINDOW + 10 )) ) &
done

sleep 1
t0="$(cpu_ticks)"
sleep "${WINDOW}"
t1="$(cpu_ticks)"

# Stop the stalled connections before reporting so cleanup always runs.
kill $(jobs -p) 2>/dev/null

# (delta ticks) / (window seconds) == %CPU of one core.
cpu=$(( (t1 - t0) / WINDOW ))
echo "FTL CPU during ${CONNS} stalled TLS handshakes: ${cpu}% of one core"

if [ "${cpu}" -ge "${LIMIT}" ]; then
	echo "FAIL: exceeds ${LIMIT}% of one core (busy-spin present)"
	exit 1
fi
echo "PASS: stayed below ${LIMIT}% of one core"
exit 0
