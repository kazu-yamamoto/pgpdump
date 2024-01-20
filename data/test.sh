#!/bin/sh

cd "$(dirname "$0")" || exit 1

[ X"$1" = X-v ] && verbose=true || verbose=false
status=0

for out in *.res; do
	in=${out%.res}
	diff=$(../pgpdump -u < "$in" | diff -au "$out" -)
	if [ -n "$diff" ]; then
		status=1
		echo "$in FAIL"
		$verbose && echo "$diff"
	else
		$verbose && echo "$in PASS"
	fi
done

exit "$status"
