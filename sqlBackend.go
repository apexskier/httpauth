package httpauth

import (
    "database/sql"
)

// SqlAuthBackend database and database connection information.
type SqlAuthBackend struct {
    driverName string
    dataSourceName string
}

func (b SqlAuthBackend) connect() *sql.DB {
    con, err := sql.Open(b.driverName, b.dataSourceName)
    if err != nil {
        panic(err)
    }
    return con
}

// NewSqlAuthBackend initializes a new backend by testing the database
// connection and making sure the storage table exists. The table is called
// goauth.
//
// This uses the databases/sql package to open a connection. Its parameters
// should match the sql.Open function. See
// http://golang.org/pkg/database/sql/#Open for more information.
//
// Be sure to import "database/sql" and your driver of choice. If you're not
// using sql for your own purposes, you'll need to use the underscore to import
// for side effects; see http://golang.org/doc/effective_go.html#blank_import.
func NewSqlAuthBackend(driverName, dataSourceName string) (b SqlAuthBackend) {
    b.driverName = driverName
    b.dataSourceName = dataSourceName
    con := b.connect()
    defer con.Close()
    con.Exec(`create table if not exists goauth (Username varchar(255), Email varchar(255), Hash varchar(255), primary key (Username))`)
    return b
}

// User returns the user with the given username.
func (b SqlAuthBackend) User(username string) (user UserData, ok bool) {
    con := b.connect()
    defer con.Close()
    row := con.QueryRow(`select Email, Hash from goauth where Username=?`, username)
    var (
        email string
        hash []byte
    )
    err := row.Scan(&email, &hash)
    if err != nil {
        return user, false
    }
    user.Username = username
    user.Email = email
    user.Hash = hash
    return user, true
}

// Users returns a slice of all users.
func (b SqlAuthBackend) Users() (us []UserData) {
    con := b.connect()
    defer con.Close()
    rows, err := con.Query("select Username, Email, Hash from goauth")
    if err != nil { panic(err) }
    var (
        username, email string
        hash []byte
    )
    for rows.Next() {
        err = rows.Scan(&username, &email, &hash)
        if err != nil { panic(err) }
        us = append(us, UserData{username, email, hash})
    }
    return
}

// SaveUser adds a new user, replacing one with the same username.
func (b SqlAuthBackend) SaveUser(user UserData) (err error) {
    con := b.connect()
    defer con.Close()
    if _, ok := b.User(user.Username); !ok {
        _, err = con.Exec("insert into goauth (Username, Email, Hash) values (?, ?, ?)", user.Username, user.Email, user.Hash)
    } else {
        _, err = con.Exec("update goauth set Email=?, Hash=? where Username=?", user.Email, user.Hash, user.Username)
    }
    return
}

// DeleteUser removes a user.
func (b SqlAuthBackend) DeleteUser(username string) error {
    con := b.connect()
    defer con.Close()
    _, err := con.Exec("delete from goauth where Username=?", username)
    return err
}
