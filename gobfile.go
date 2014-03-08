package goauth

import (
    "encoding/gob"
    "os"
    "errors"
)

type GobFileAuthBackend struct {
    filepath string
    users map[string]UserData
}

func NewGobFileAuthBackend(filepath string) (b GobFileAuthBackend) {
    b.filepath = filepath
    if _, err := os.Stat(b.filepath); err == nil {
        f, err := os.Open(b.filepath)
        defer f.Close()
        if err != nil {
            panic(err.Error())
        }
        dec := gob.NewDecoder(f)
        dec.Decode(&b.users)
    } else if !os.IsNotExist(err) {
        panic(err.Error())
    }
    if b.users == nil {
        b.users = make(map[string]UserData)
    }
    return b
}

func (b GobFileAuthBackend) User(username string) (user UserData, ok bool) {
    if user, ok := b.users[username]; ok {
        return user, ok
    } else {
        return user, false
    }
}

func (b GobFileAuthBackend) Users() (us []UserData) {
    for _, user := range b.users {
        us = append(us, user)
    }
    return
}

func (b GobFileAuthBackend) SaveUser(user UserData) (err error) {
    b.users[user.Username] = user
    f, err := os.Create(b.filepath)
    defer f.Close()
    if err != nil {
        return errors.New("Auth file can't be edited. Is the data folder there?")
    }
    enc := gob.NewEncoder(f)
    err = enc.Encode(b.users)
    return
}
