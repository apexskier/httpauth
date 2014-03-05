package main

import (
    "encoding/gob"
    "os"
    "errors"
    "bytes"
    "net/http"
    "code.google.com/p/go.crypto/pbkdf2"
    "crypto/sha256"
    "github.com/gorilla/sessions"
    "github.com/gorilla/context"
)

type UserData struct {
    Username string
    Hash []byte
    Email string
}

type Authorizer struct {
    Users map[string]UserData
    Filepath string
    Salt []byte
    cookiejar *sessions.CookieStore
}

func NewAuthorizer(fpath string, salt string) Authorizer {
    var a Authorizer
    if _, err := os.Stat(fpath); err == nil {
        f, err := os.Open(fpath)
        defer f.Close()
        if err != nil {
            panic(err.Error())
        }
        dec := gob.NewDecoder(f)
        dec.Decode(&a)
    } else if !os.IsNotExist(err) {
        panic(err.Error())
    }
    if a.Users == nil {
        a.Users = make(map[string]UserData)
    }
    a.Filepath = fpath
    a.Salt = []byte(salt)
    a.cookiejar = sessions.NewCookieStore([]byte("wombat-secret-key"))
    return a
}

func (a Authorizer) Save(u UserData) error {
    if _, ok := a.Users[u.Username]; ok {
        return errors.New("User already exists.")
    }
    a.Users[u.Username] = u

    f, err := os.Create(a.Filepath)
    defer f.Close()
    if err != nil {
        return errors.New("No auth file found.")
    }
    enc := gob.NewEncoder(f)
    err = enc.Encode(a)
    return nil
}

func (a Authorizer) Login(rw http.ResponseWriter, req *http.Request, u string, p string) error {
    session, _ := a.cookiejar.Get(req, "auth")
    if session.Values["username"] != nil {
        return errors.New("Already authenticated.")
    }
    if user, ok := a.Users[u]; !ok {
        return errors.New("User not found.")
    } else {
        hash := hashString(u + p, a.Salt)
        if !bytes.Equal(user.Hash, hash) {
            return errors.New("Password doesn't match.")
        }
    }
    session.Values["username"] = u
    session.Save(req, rw)

    return nil
}

func hashString(input string, salt []byte) []byte {
    return pbkdf2.Key([]byte(input), salt, 4096, sha256.Size, sha256.New)
}

func (a Authorizer) Register(u string, p string, e string) error {
    hash := hashString(u + p, a.Salt)
    return a.Save(UserData{u, hash, e})
}

func (a Authorizer) Authorize(rw http.ResponseWriter, req *http.Request) (error, int) {
    session, err := a.cookiejar.Get(req, "auth")
    if err != nil {
        return errors.New("Couldn't read cookiejar."), http.StatusInternalServerError
    }
    username := session.Values["username"]
    if username == nil {
        return errors.New("You must login to do that."), http.StatusUnauthorized
    }
    context.Set(req, "username", username)
    return nil, http.StatusOK
}
