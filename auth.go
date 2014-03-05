package main

import (
    "encoding/gob"
    "os"
    "errors"
    "bytes"
    "code.google.com/p/go.crypto/pbkdf2"
    "crypto/sha256"
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
}

func NewAuthorizer(fpath string, salt string) Authorizer {
    var a Authorizer
    if _, err := os.Stat(fpath); err != nil {
        panic(err.Error())
    }
    f, err := os.Open(fpath)
    defer f.Close()
    if err != nil {
        panic(err.Error())
    }
    dec := gob.NewDecoder(f)
    dec.Decode(&a)
    if a.Users == nil {
        a.Users = make(map[string]UserData)
    }
    a.Filepath = fpath
    a.Salt = []byte(salt)
    return a
}

func (a Authorizer) Save(u UserData) error {
    if _, ok := a.Users[u.Username]; ok {
        return errors.New("User already exists.")
    }
    a.Users[u.Username] = u

    f, err := os.Create("data/auth")
    defer f.Close()
    if err != nil {
        return errors.New("No auth file found.")
    }
    enc := gob.NewEncoder(f)
    err = enc.Encode(a)
    return nil
}

func (a Authorizer) Login(u string, p string) error {
    if user, ok := a.Users[u]; !ok {
        return errors.New("User not found.")
    } else {
        hash := hashString(u + p, a.Salt)
        if !bytes.Equal(user.Hash, hash) {
            return errors.New("Password doesn't match.")
        }
    }
    return nil
}

func hashString(input string, salt []byte) []byte {
    return pbkdf2.Key([]byte(input), salt, 4096, sha256.Size, sha256.New)
}

func (a Authorizer) Register(u string, p string, e string) error {
    hash := hashString(u + p, a.Salt)
    return a.Save(UserData{u, hash, e})
}
