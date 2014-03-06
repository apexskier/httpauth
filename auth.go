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
        return errors.New("Auth file can't be edited. Is the data folder there?")
    }
    enc := gob.NewEncoder(f)
    err = enc.Encode(a)
    return nil
}

func (a Authorizer) Login(rw http.ResponseWriter, req *http.Request, u string, p string, dest string) error {
    session, _ := a.cookiejar.Get(req, "auth")
    message_session, _ := a.cookiejar.Get(req, "messages")
    defer message_session.Save(req, rw)
    if session.Values["username"] != nil {
        return errors.New("Already authenticated.")
    }
    if user, ok := a.Users[u]; !ok {
        message_session.AddFlash("Invalid username or password.")
        return errors.New("User not found.")
    } else {
        hash := hashString(u + p, a.Salt)
        if !bytes.Equal(user.Hash, hash) {
            message_session.AddFlash("Invalid username or password.")
            return errors.New("Password doesn't match.")
        }
    }
    session.Values["username"] = u
    session.Save(req, rw)

    redirect_session, _ := a.cookiejar.Get(req, "redirects")
    if flashes := redirect_session.Flashes(); len(flashes) > 0 {
        dest = flashes[0].(string)
    }
    http.Redirect(rw, req, dest, http.StatusSeeOther)
    return nil
}

func hashString(input string, salt []byte) []byte {
    return pbkdf2.Key([]byte(input), salt, 4096, sha256.Size, sha256.New)
}

func (a Authorizer) Register(rw http.ResponseWriter, req *http.Request, u string, p string, e string) (err error) {
    hash := hashString(u + p, a.Salt)
    err = a.Save(UserData{u, hash, e})
    if err != nil {
        message_session, _ := a.cookiejar.Get(req, "messages")
        defer message_session.Save(req, rw)
        message_session.AddFlash(err.Error())
    }
    return
}

func (a Authorizer) Authorize(rw http.ResponseWriter, req *http.Request) error {
    redirect_session, _ := a.cookiejar.Get(req, "redirects");
    message_session, _ := a.cookiejar.Get(req, "messages")
    session, err := a.cookiejar.Get(req, "auth")
    redirect_session.Flashes()
    defer redirect_session.Save(req, rw)
    defer message_session.Save(req, rw)
    if err != nil {
        redirect_session.AddFlash(req.URL.Path)
        return errors.New("Cookie jar doesn't have any auth.")
    }
    username := session.Values["username"]
    if !session.IsNew {
        if _, ok := a.Users[username.(string)]; !ok {
            redirect_session.AddFlash(req.URL.Path)
            session.Options.MaxAge = -1
            session.Save(req, rw)
            return errors.New("User not found.")
        }
    }
    if username == nil {
        redirect_session.AddFlash(req.URL.Path)
        message_session.AddFlash("Log in to do that.")
        return errors.New("User not logged in.")
    }
    context.Set(req, "username", username)
    return nil
}

func (a Authorizer) Logout(rw http.ResponseWriter, req *http.Request) error {
    message_session, _ := a.cookiejar.Get(req, "messages")
    session, _ := a.cookiejar.Get(req, "auth")
    defer message_session.Save(req, rw)
    defer session.Save(req, rw)

    session.Options.MaxAge = -1
    message_session.AddFlash("Logged out.")
    return nil
}

func (a Authorizer) Messages(rw http.ResponseWriter, req *http.Request) []interface{} {
    session, _ := a.cookiejar.Get(req, "messages")
    flashes := session.Flashes()
    session.Save(req, rw)
    return flashes
}
