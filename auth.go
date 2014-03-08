// Package goauth implements cookie/session based authentication. Intended for
// use with the net/http or github.com/gorilla/mux packages, but may work with
// github.com/codegangsta/martini as well. Internally, credentials are stored
// as a username + password hash, computed with bcrypt.
//
// Users can be redirected to the page that triggered an authentication error.
//
// Messages describing the reason a user could not authenticate are saved in a
// cookie, and can be accessed with the goauth.Messages function.
package goauth

import (
    "errors"
    "net/http"
    "code.google.com/p/go.crypto/bcrypt"
    "github.com/gorilla/sessions"
    "github.com/gorilla/context"
)

// UserData represents a single user. It contains the users username and email
// as well as a has of their username and password.
type UserData struct {
    Username string
    Email string
    Hash []byte
}

// Authorizer structures contain the store of user session cookies a reference
// to a backend storage system.
type Authorizer struct {
    cookiejar *sessions.CookieStore
    backend AuthBackend
}

// The AuthBackend interface defines a set of methods an AuthBackend must
// implement.
type AuthBackend interface {
    SaveUser(u UserData) (err error)
    User(username string) (user UserData, ok bool)
    Users() (users []UserData)
}

// Helper function to add a user directed message to a message queue.
func (a Authorizer) addMessage(rw http.ResponseWriter, req *http.Request, message string) {
    messageSession, _ := a.cookiejar.Get(req, "messages")
    defer messageSession.Save(req, rw)
    messageSession.AddFlash(message)
}

// Helper function to save a redirect to the page a user tried to visit before
// logging in.
func (a Authorizer) goBack(rw http.ResponseWriter, req *http.Request) {
    redirectSession, _ := a.cookiejar.Get(req, "redirects");
    defer redirectSession.Save(req, rw)
    redirectSession.Flashes()
    redirectSession.AddFlash(req.URL.Path)
}

// NewAuthorizer returns a new Authorizer given an AuthBackend and a cookie
// store key.  If the key changes, logged in users will need to reauthenticate.
func NewAuthorizer(backend AuthBackend, key []byte) (a Authorizer) {
    a.cookiejar = sessions.NewCookieStore([]byte(key))
    a.backend = backend
    return a
}

// Login logs a user in. They will be redirected to faildest with an invalid
// username or password, and to the last location an authorization redirect was
// triggered (if found) on success. A message will be added to the session on
// failure with the reason
func (a Authorizer) Login(rw http.ResponseWriter, req *http.Request, u string, p string, faildest string) error {
    session, _ := a.cookiejar.Get(req, "auth")
    if session.Values["username"] != nil {
        return errors.New("already authenticated")
    }
    if user, ok := a.backend.User(u); ok {
        verify := bcrypt.CompareHashAndPassword(user.Hash, []byte(u + p))
        if verify != nil {
            a.addMessage(rw, req, "Invalid username or password.")
            return errors.New("password doesn't match")
        }
    } else {
        a.addMessage(rw, req, "Invalid username or password.")
        return errors.New("user not found")
    }
    session.Values["username"] = u
    session.Save(req, rw)

    redirectSession, _ := a.cookiejar.Get(req, "redirects")
    if flashes := redirectSession.Flashes(); len(flashes) > 0 {
        faildest = flashes[0].(string)
    }
    http.Redirect(rw, req, faildest, http.StatusSeeOther)
    return nil
}

// Register and save a new user. Returns an error and adds a message if the
// username is in use.
func (a Authorizer) Register(rw http.ResponseWriter, req *http.Request, u string, p string, e string) error {
    if _, ok := a.backend.User(u); ok {
        a.addMessage(rw, req, "Username has been taken.")
        return errors.New("user already exists")
    }

    hash, err := bcrypt.GenerateFromPassword([]byte(u + p), 8)
    if err != nil {
        return errors.New("couldn't save password: " + err.Error())
    }

    user := UserData{u, e, hash}

    err = a.backend.SaveUser(user)
    if err != nil {
        a.addMessage(rw, req, err.Error())
    }
    return nil
}

// Authorize checks if a user is logged in and returns an error on failed
// authentication. If redirectWithMessage is set, the page being authorized
// will be saved and a "Login to do that." message will be saved to the
// messages list. The next time the user logs in, they will be redirected back
// to the saved page.
func (a Authorizer) Authorize(rw http.ResponseWriter, req *http.Request, redirectWithMessage bool) error {
    authSession, err := a.cookiejar.Get(req, "auth")
    if err != nil {
        if redirectWithMessage {
            a.goBack(rw, req)
        }
        return errors.New("new authorization session. Possible restart of server")
    }
    if authSession.IsNew {
        if redirectWithMessage {
            a.goBack(rw, req)
            a.addMessage(rw, req, "Log in to do that.")
        }
        return errors.New("no session existed")
    }
    username := authSession.Values["username"]
    if !authSession.IsNew && username != nil {
        if _, ok := a.backend.User(username.(string)); !ok {
            authSession.Options.MaxAge = -1 // kill the cookie
            authSession.Save(req, rw)
            if redirectWithMessage {
                a.goBack(rw, req)
                a.addMessage(rw, req, "Log in to do that.")
            }
            return errors.New("user not found")
        }
    }
    if username == nil {
        if redirectWithMessage {
            a.goBack(rw, req)
            a.addMessage(rw, req, "Log in to do that.")
        }
        return errors.New("user not logged in")
    }
    context.Set(req, "username", username)
    return nil
}

// Logout clears an authentication session and add a logged out message.
func (a Authorizer) Logout(rw http.ResponseWriter, req *http.Request) error {
    session, _ := a.cookiejar.Get(req, "auth")
    defer session.Save(req, rw)

    session.Options.MaxAge = -1 // kill the cookie
    a.addMessage(rw, req, "Logged out.")
    return nil
}

// Messages fetches a list of saved messages. Use this to get a nice message to print to
// the user on a login page or registration page in case something happened
// (username taken, invalid credentials, successful logout, etc).
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
