# Go Session Authentication
[![Build Status](http://img.shields.io/travis/apexskier/httpauth.svg)](https://travis-ci.org/apexskier/httpauth)
[![Coverage](https://img.shields.io/coveralls/apexskier/httpauth.svg)](https://coveralls.io/r/apexskier/httpauth)
[![GoDoc](http://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/apexskier/httpauth)
![Version 2.0.0](https://img.shields.io/badge/version-2.0.0-lightgrey.svg)

See git tags/releases for information about potentially breaking change.

This package uses the [Gorilla web toolkit](http://www.gorillatoolkit.org/)'s
sessions package to implement a user authentication and authorization system
for Go web servers.

Multiple user data storage backends are available, and new ones can be
implemented relatively easily.

- [File based](https://godoc.org/github.com/apexskier/goauth#NewGobFileAuthBackend) ([gob](http://golang.org/pkg/encoding/gob/))
- [Various SQL Databases](https://godoc.org/github.com/apexskier/httpauth#NewSqlAuthBackend)
  (tested with [MySQL](https://github.com/go-sql-driver/mysql),
  [PostgresSQL](https://github.com/lib/pq),
  [SQLite](https://github.com/mattn/go-sqlite3))
- [MongoDB](https://godoc.org/github.com/apexskier/httpauth#NewMongodbBackend) ([mgo](http://gopkg.in/mgo.v2))

Access can be restricted by a users' role.

Uses [bcrypt](http://codahale.com/how-to-safely-store-a-password/) for password
hashing.

```go
var (
    aaa httpauth.Authorizer
)

func login(rw http.ResponseWriter, req *http.Request) {
    username := req.PostFormValue("username")
    password := req.PostFormValue("password")
    if err := aaa.Login(rw, req, username, password, "/"); err != nil && err.Error() == "already authenticated" {
        http.Redirect(rw, req, "/", http.StatusSeeOther)
    } else if err != nil {
        fmt.Println(err)
        http.Redirect(rw, req, "/login", http.StatusSeeOther)
    }
}
```

Run `go run server.go` from the examples directory and visit `localhost:8009`
for an example. You can login with the username "admin" and password "adminadmin".

Tests can be run by simulating Travis CI's build environment. There's a very
unsafe script --- `start-test-env.sh` that will do this for you.

You should [follow me on Twitter](https://twitter.com/apexskier). [Appreciate this package?](https://cash.me/$apexskier)

### TODO

- User roles - modification
- SMTP email validation (key based)
- More backends
- Possible remove dependance on bcrypt
