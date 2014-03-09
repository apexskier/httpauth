# Go Session Authentication
[![GoDoc](https://godoc.org/github.com/apexskier/httpauth?status.png)](https://godoc.org/github.com/Wombats/goauth)

This package uses the [Gorilla web toolkit](http://www.gorillatoolkit.org/)'s
sessions and package to implement a user authorization system for web servers
written in Go.

Multiple user data storage backends are available, and new ones can be
implemented relatively easily.

- [File based](https://godoc.org/github.com/apexskier/goauth#NewGobFileAuthBackend) ([gob](http://golang.org/pkg/encoding/gob/))
- [Various SQL Databases](https://godoc.org/github.com/apexskier/goauth#NewSqlAuthBackend)

Using [bcrypt](http://codahale.com/how-to-safely-store-a-password/) for
password hashing.

Run `go run server.go` from the examples directory and visit `localhost:8080`
for an example. You can login with the username and password "test".

**Note**

This is the first time I've worked with implementing the details of cookie
storage, authentication or any sort of real security. There are no guarantees
that this will work as expected, but I'd love feedback. If you have any issues
or suggestions, please [let me
know](https://github.com/Wombats/goauth/issues/new).

### TODO

- User roles
- SMTP email validation (key based)
