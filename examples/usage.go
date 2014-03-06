package main

import (
    "net/http"
    "github.com/Wombats/goauth"
)

var aaa goauth.Authorizer = goauth.NewAuthorizer("auth/file/path", "encryption-salt", []byte("cookie-encryption-key"))

func main() {
    // set up routers and route handlers
}

func handleRegister(rw http.ResponseWriter, req *http.Request) {
    aaa.Register(rw, req, "username", "password", "email@example.com")
    handleLogin(rw, req)
}

func handleLogin(rw http.ResponseWriter, req *http.Request) {
    if err := aaa.Login(rw, req, "username", "password", "/success_redirect"); err != nil {
        http.Redirect(rw, req, "/fail_redirect", http.StatusSeeOther)
    }
}

func handleRestrictedPage(rw http.ResponseWriter, req *http.Request) {
    if err := aaa.Authorize(rw, req, true); err != nil {
        http.Redirect(rw, req, "/fail_redirect", http.StatusSeeOther)
        return
    }
    // continue with sending page
}

func handleLogout(rw http.ResponseWriter, req *http.Request) {
    if err := aaa.Logout(rw, req); err != nil {
        // this shouldn't happen
        return
    }
    http.Redirect(rw, req, "/logged_out", http.StatusSeeOther)
}

