package goauth

import (
    "errors"
    "net/http"
    "code.google.com/p/go.crypto/bcrypt"
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
    cookiejar *sessions.CookieStore
    backend AuthBackend
}

type AuthBackend interface {
    LoadAuth() (a Authorizer, err error)
    SaveAuth(a Authorizer) (err error)
}

func (a Authorizer) addMessage(rw http.ResponseWriter, req *http.Request, message string) {
    message_session, _ := a.cookiejar.Get(req, "messages")
    defer message_session.Save(req, rw)
    message_session.AddFlash(message)
}

func (a Authorizer) goBack(rw http.ResponseWriter, req *http.Request) {
    redirect_session, _ := a.cookiejar.Get(req, "redirects");
    defer redirect_session.Save(req, rw)
    redirect_session.Flashes()
    redirect_session.AddFlash(req.URL.Path)
}

func NewAuthorizer(backend AuthBackend, key []byte) (a Authorizer) {
    a, err := backend.LoadAuth()
    if err != nil {
        panic(err.Error)
    }
    if a.Users == nil {
        a.Users = make(map[string]UserData)
    }
    a.cookiejar = sessions.NewCookieStore([]byte(key))
    a.backend = backend
    return a
}

func (a Authorizer) Login(rw http.ResponseWriter, req *http.Request, u string, p string, dest string) error {
    session, _ := a.cookiejar.Get(req, "auth")
    if session.Values["username"] != nil {
        return errors.New("Already authenticated.")
    }
    if user, ok := a.Users[u]; !ok {
        a.addMessage(rw, req, "Invalid username or password.")
        return errors.New("User not found.")
    } else {
        verify := bcrypt.CompareHashAndPassword(user.Hash, []byte(u + p))
        if verify != nil {
            a.addMessage(rw, req, "Invalid username or password.")
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

func (a Authorizer) Register(rw http.ResponseWriter, req *http.Request, u string, p string, e string) error {
    if _, ok := a.Users[u]; ok {
        a.addMessage(rw, req, "Username has been taken.")
        return errors.New("User already exists.")
    }

    hash, err := bcrypt.GenerateFromPassword([]byte(u + p), 8)
    if err != nil {
        return errors.New("Couldn't save password: " + err.Error())
    }
    user := (UserData{u, hash, e})

    a.Users[u] = user

    a.backend.SaveAuth(a)

    if err != nil {
        a.addMessage(rw, req, err.Error())
    }
    return nil
}

func (a Authorizer) Authorize(rw http.ResponseWriter, req *http.Request, redirectWithMessage bool) error {
    auth_session, err := a.cookiejar.Get(req, "auth")
    if err != nil {
        if redirectWithMessage {
            a.goBack(rw, req)
        }
        return errors.New("New authorization session. Possible restart of server.")
    }
    if auth_session.IsNew {
        if redirectWithMessage {
            a.goBack(rw, req)
            a.addMessage(rw, req, "Log in to do that.")
        }
        return errors.New("No session existed.")
    }
    username := auth_session.Values["username"]
    if !auth_session.IsNew && username != nil {
        if _, ok := a.Users[username.(string)]; !ok {
            auth_session.Options.MaxAge = -1 // kill the cookie
            auth_session.Save(req, rw)
            if redirectWithMessage {
                a.goBack(rw, req)
                a.addMessage(rw, req, "Log in to do that.")
            }
            return errors.New("User not found.")
        }
    }
    if username == nil {
        if redirectWithMessage {
            a.goBack(rw, req)
            a.addMessage(rw, req, "Log in to do that.")
        }
        return errors.New("User not logged in.")
    }
    context.Set(req, "username", username)
    return nil
}

func (a Authorizer) Logout(rw http.ResponseWriter, req *http.Request) error {
    session, _ := a.cookiejar.Get(req, "auth")
    defer session.Save(req, rw)

    session.Options.MaxAge = -1 // kill the cookie
    a.addMessage(rw, req, "Logged out.")
    return nil
}

func (a Authorizer) Messages(rw http.ResponseWriter, req *http.Request) []string {
    session, _ := a.cookiejar.Get(req, "messages")
    flashes := session.Flashes()
    session.Save(req, rw)
    var messages []string
    for _, val := range flashes {
        messages = append(messages, val.(string))
    }
    return messages
}
