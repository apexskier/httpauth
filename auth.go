package main

import (
    "encoding/gob"
    "os"
    "errors"
)

type UserData struct {
    Username string
    Hash string
    Email string
}
type Authorizer struct {
    Users map[string]UserData
    Filepath string
}
func NewAuthorizer(fpath string) Authorizer {
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
    // err := a.Save(UserData{u, u + p, ""})
    // if err != nil {
    //     return err
    // }
    if user, ok := a.Users[u]; !ok {
        return errors.New("User not found.")
    } else {
        hash := u + p
        if user.Hash != hash {
            return errors.New("Password doesn't match.")
        }
    }
    return nil
}

