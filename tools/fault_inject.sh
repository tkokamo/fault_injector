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
while read -r line || [[ -n "${line}" ]] ; do
	key="$(echo ${line} | cut -d'=' -f1)"
	val="$(echo ${line} | cut -d'=' -f2)"
	case ${key} in
	"target")
		args[0]=${val};;
	"fault")
		args[1]=${val};;
	"comm")
		args[2]=${val};;
	"module")
		args[3]=${val};;
	"when")
		args[4]=${val};;
	"error")
		args[5]=${val};;
	"trace")
		args[6]=${val};;
	esac
done < "${1}"

./inject_fault "${args[0]}" "${args[1]}" "${args[2]}" "${args[3]}" "${args[4]}" "${args[5]}" "${args[6]}"

