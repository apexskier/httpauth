package main

import (
    "net/http"
    "github.com/apexskier/httpauth"
    "github.com/gorilla/mux"
    "fmt"
)

var (
    backend httpauth.GobFileAuthBackend
    aaa httpauth.Authorizer
)


func main() {
    backend = httpauth.NewGobFileAuthBackend("auth.gob")
    aaa = httpauth.NewAuthorizer(backend, []byte("cookie-encryption-key"))

    // set up routers and route handlers
    r := mux.NewRouter()
    r.HandleFunc("/login", getLogin).Methods("GET")
    r.HandleFunc("/register", postRegister).Methods("POST")
    r.HandleFunc("/login", postLogin).Methods("POST")
    r.HandleFunc("/change", postChange).Methods("POST")
    r.HandleFunc("/", handlePage).Methods("GET") // authorized page
    r.HandleFunc("/logout", handleLogout)

    http.Handle("/", r)
    http.ListenAndServe(":8080", nil)
}

func getLogin(rw http.ResponseWriter, req *http.Request) {
    messages := aaa.Messages(rw, req)
    fmt.Fprintf(rw, `
        <html>
        <head><title>Login</title></head>
        <body>
        <h1>Httpauth example</h1>
        <h2>Entry Page</h2>
        <p><b>Messages: %v</b></p>
        <h3>Login</h3>
        <form action="/login" method="post" id="login">
            <input type="text" name="username" placeholder="username"><br>
            <input type="password" name="password" placeholder="password"></br>
            <button type="submit">Login</button>
        </form>
        <h3>Register</h3>
        <form action="/register" method="post" id="register">
            <input type="text" name="username" placeholder="username"><br>
            <input type="password" name="password" placeholder="password"></br>
            <input type="email" name="email" placeholder="email@example.com"></br>
            <button type="submit">Register</button>
        </form>
        </body>
        </html>
        `, messages)
}

func postLogin(rw http.ResponseWriter, req *http.Request) {
    username := req.PostFormValue("username")
    password := req.PostFormValue("password")
    if err := aaa.Login(rw, req, username, password, "/"); err != nil {
        fmt.Println(err)
        http.Redirect(rw, req, "/login", http.StatusSeeOther)
    }
}

func postRegister(rw http.ResponseWriter, req *http.Request) {
    username := req.PostFormValue("username")
    password := req.PostFormValue("password")
    email := req.PostFormValue("email")
    if err := aaa.Register(rw, req, username, password, email); err == nil {
        postLogin(rw, req)
    } else {
        http.Redirect(rw, req, "/login", http.StatusSeeOther)
    }
}

func postChange(rw http.ResponseWriter, req *http.Request) {
    email := req.PostFormValue("new_email")
    aaa.Update(rw, req, "", email)
    http.Redirect(rw, req, "/", http.StatusSeeOther)
}

func handlePage(rw http.ResponseWriter, req *http.Request) {
    if err := aaa.Authorize(rw, req, true); err != nil {
        fmt.Println(err)
        http.Redirect(rw, req, "/login", http.StatusSeeOther)
        return
    }
    if user, ok := aaa.CurrentUser(rw, req); ok {
        fmt.Fprintf(rw, `
            <html>
            <head><title>Secret page</title></head>
            <body>
                <h1>Httpauth example<h1>
                <h2>Hello %v</h2>
                <p>Your email is %v. <a href="/logout">Logout</a></p>
                <form action="/change" method="post" id="change">
                    <h3>Change email</h3>
                    <p><input type="email" name="new_email" placeholder="new email"></p>
                    <button type="submit">Submit</button>
                </form>
            </body>
            `, user.Username, user.Email)
    }
}

func handleLogout(rw http.ResponseWriter, req *http.Request) {
    if err := aaa.Logout(rw, req); err != nil {
        fmt.Println(err)
        // this shouldn't happen
        return
    }
    http.Redirect(rw, req, "/logout", http.StatusSeeOther)
}

