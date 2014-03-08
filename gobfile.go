package goauth

import (
    "encoding/gob"
    "os"
    "errors"
)

type GobFileAuthBackend struct {
    Filepath string
}

func (b GobFileAuthBackend) LoadAuth() (Authorizer, error) {
    var a Authorizer
    if _, err := os.Stat(b.Filepath); err == nil {
        f, err := os.Open(b.Filepath)
        defer f.Close()
        if err != nil {
            return a, err
        }
        dec := gob.NewDecoder(f)
        dec.Decode(&a)
    } else if !os.IsNotExist(err) {
        return a, err
    }
    return a, nil
}

func (b GobFileAuthBackend) SaveAuth(a Authorizer) (err error) {
    f, err := os.Create(b.Filepath)
    defer f.Close()
    if err != nil {
        return errors.New("Auth file can't be edited. Is the data folder there?")
    }
    enc := gob.NewEncoder(f)
    err = enc.Encode(a)
    return
}
