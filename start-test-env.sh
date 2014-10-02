#!/bin/bash

mkdir -p mongodbtest
mongod --dbpath mongodbtest >/dev/null &
mongopid=$!
echo "mongod started with pid: $mongopid"
mysqld --skip-grant-tables >/dev/null 2>/dev/null &
mysqlpid=$!
echo "WARNING: mysqld started with no security"
echo "mysqld started with pid: $mysqlpid"

function ctrl_c() {
    echo "shutting down databases"
    kill -15 $mongopid
    kill -15 $mysqlpid
}
trap ctrl_c INT

echo "press ctrl-c to quit"
# wait forever
cat
