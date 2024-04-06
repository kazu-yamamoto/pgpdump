#!/bin/sh

mydir=${0%/*}

[ X"$1" = X-v ] && { verbose=true; shift; } || verbose=false
[ "$#" -gt 0 ] || set -- "$mydir"/*.res
status=0

for out in "$@"; do
	in=${out%.res}
	diff=$("${mydir}"/../pgpdump -u < "$in" | diff -au "$out" -)
	if [ -n "$diff" ]; then
		status=1
		echo "$in FAIL"
		$verbose && echo "$diff"
	else
		$verbose && echo "$in PASS"
	fi
done

exit "$status"
