package httpauth

import (
    "database/sql"
    "fmt"
    _ "github.com/go-sql-driver/mysql"
    _ "github.com/lib/pq"
    _ "github.com/mattn/go-sqlite3"
    "os"
    "testing"
)

var backend SqlAuthBackend

func testSqlInit(t *testing.T, driver string, info string) {
    con, err := sql.Open(driver, info)
    if err != nil {
        t.Errorf("Couldn't set up test database: %v", err)
        fmt.Printf("Couldn't set up test database: %v\n", err)
        os.Exit(1)
    }
    err = con.Ping()
    if err != nil {
        t.Errorf("Couldn't ping test database: %v", err)
        fmt.Printf("Couldn't ping test database: %v\n", err)
        // t.Errorf("Couldn't ping test database: %v\n", err)
        os.Exit(1)
    }
    con.Exec("drop table goauth")
}

func testSqlBackend(t *testing.T, driver string, info string) {
    var b2 SqlAuthBackend
    b2.DriverName = driver
    b2.DriverInfo = info + "_fail"
    err := b2.Init()
    if err == nil {
        t.Fatal("Expected error on invalid connection.")
    }
    backend.DriverName = driver
    backend.DriverInfo = info
    err = backend.Init()
    if err != nil {
        t.Fatal(err.Error())
    }

    TestBackend(t, backend)
}

func testSqlReopen(t *testing.T, driver string, info string) {
    var err error

    backend.Close()

    err = backend.Init()
    if err != nil {
        t.Fatal(err.Error())
    }

    backend.Close()

    err = backend.Init()
    if err != nil {
        t.Fatal(err.Error())
    }

    TestAfterReopen(t, backend)
}

func sqlTests(t *testing.T, driver string, info string) {
    testSqlInit(t, driver, info)
    testSqlBackend(t, driver, info)
    testSqlReopen(t, driver, info)
}

//
// mysql tests
//
func TestMysqlBackend(t *testing.T) {
    sqlTests(t, "mysql", "travis@tcp(127.0.0.1:3306)/httpauth_test")
}

//
// postgres tests
//
func TestPostgresBackend(t *testing.T) {
    sqlTests(t, "postgres", "user=postgres password='' dbname=httpauth_test sslmode=disable")
}

//
// sqlite3 tests
//
func TestSqliteBackend(t *testing.T) {
    os.Create("./httpauth_test_sqlite.db")
    sqlTests(t, "sqlite3", "./httpauth_test_sqlite.db")
    os.Remove("./httpauth_test_sqlite.db")
}
