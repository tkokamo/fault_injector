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

while read -r line || [[ -n "${line}" ]] ; do
	echo ${line}
done < "${1}"
