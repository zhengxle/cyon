#!/bin/sh
#
# Master to slave sync script. Figures out the state of the given
# slave and scp's over the correct log for it.
#
# Copyright (c) 2014 Joris Vink <joris@coders.se>
# Part of Cyon (https://github.com/jorisvink/cyon)
#

MASTER="127.0.0.1:2222"
SLAVE="127.0.0.1:2223"
LOCAL="/home/joris/db"
REMOTE="/home/joris/db-slave"
DBNAME="sync-test"
LOG="logger -p daemon.info -t cyon-sync"

STATE=`./cyon-cmd -s ${SLAVE} stats | grep "Current" | awk '{ print $3 }'`

if [ $? -ne 0 ]; then
	${LOG} "Failed to grab latest state";
	exit 1;
fi

if [ ! -f ${LOCAL}/${DBNAME}.${STATE} ]; then
	${LOG} "No such state on master: ${STATE}";
	exit 1;
fi

# XXX - We have to give the master time to write its store.
# XXX - We need a better way of checking when it's done
./cyon-cmd -s ${MASTER} write
if [ $? -ne 0 ]; then
	${LOG} "Failed to issue write to master";
	exit 1;
fi

sleep 10;

# Grab the state of the master, if its the same as our slave
# we don't have to do anything
MSTATE=`./cyon-cmd -s ${MASTER} stats | grep "Current" | awk '{ print $3 }'`
if [ $? -ne 0 ]; then
	${LOG} "Failed to grab master state";
	exit 1;
fi

if [ "${MSTATE}" = "${STATE}" ]; then
	${LOG} "Nothing to do, slave is in sync with master (${STATE})";
	exit 0;
fi

${LOG} "Preparing to sync state: ${STATE}";
cp -p ${LOCAL}/${DBNAME}.${STATE} ${REMOTE}/
if [ $? -ne 0 ]; then
	${LOG} "Copy of state ${STATE} has failed";
	exit 1;
fi

${LOG} "Applying state ${STATE} to slave";
./cyon-cmd -s ${SLAVE} replay ${STATE}
if [ $? -ne 0 ]; then
	${LOG} "Slave has failed to apply ${STATE}";
	exit 1;
fi

./cyon-cmd -s ${SLAVE} write
if [ $? -ne 0 ]; then
	${LOG} "Failed to issue write to slave";
fi

${LOG} "Slave synchronized";
