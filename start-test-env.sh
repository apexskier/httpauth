#!/bin/bash

mkdir -p mongodbtest
mongod --dbpath mongodbtest >/dev/null &
mongopid=$!
echo "mongod started with pid: $mongopid"

mysqld --skip-grant-tables >/dev/null 2>/dev/null &
mysqlpid=$!
echo "WARNING: mysqld started with no security"
echo "mysqld started with pid: $mysqlpid"

mkdir -p pgdbtest
initdb pgdbtest -E utf8 >/dev/null 2>/dev/null
postgres -D pgdbtest >/dev/null 2>/dev/null &
postgrespid=$!
echo "postgres started with pid: $postgrespid"
sleep 5
createuser --createdb postgres >/dev/null 2>/dev/null
createdb httpauth_test >/dev/null 2>/dev/null

function ctrl_c() {
    echo "shutting down databases"
    kill -15 $mongopid
    kill -15 $mysqlpid
    kill -15 $postgrespid

    rm -rf mongodbtest pgdbtest
}
trap ctrl_c INT

echo "press ctrl-c to quit"
# wait forever
cat
