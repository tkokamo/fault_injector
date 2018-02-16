#!/usr/bin/bash

if [[ -z ${1} ]] ; then
	echo "Usage: ${0} <target_def>"
	exit 1
fi

msg=$(cat ${1} 2>&1)
if [[ ${?} -ne 0 ]] ; then
	echo ${msg}
	exit 1
fi

args=()
i=0
while read -r line || [[ -n "${line}" ]] ; do
	args[${i}]="$(echo ${line} | cut -d'=' -f2)"
	i=$i+1
done < "${1}"

./inject_fault "${args[0]}" "${args[1]}" "${args[2]}" "${args[3]}" "${args[4]}"

