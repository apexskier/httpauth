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
    kill -15 $mongopid 2>/dev/null
    kill -15 $mysqlpid 2>/dev/null
    kill -15 $postgrespid 2>/dev/null

    rm -rf mongodbtest pgdbtest auth_test.gob
    exit 0
}
trap ctrl_c INT

echo "ready to test... press ctrl-c to quit"
# wait forever
cat
