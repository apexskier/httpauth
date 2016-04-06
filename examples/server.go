package main

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"os"

	"github.com/apexskier/httpauth"
	"github.com/gorilla/mux"
)

var (
	backend     httpauth.LeveldbAuthBackend
	aaa         httpauth.Authorizer
	roles       map[string]httpauth.Role
	port        = 8009
	backendfile = "auth.leveldb"
)

func main() {
	var err error
	os.Mkdir(backendfile, 0755)
	defer os.Remove(backendfile)

	// create the backend
	backend, err = httpauth.NewLeveldbAuthBackend(backendfile)
	if err != nil {
		panic(err)
	}

	// create some default roles
	roles = make(map[string]httpauth.Role)
	roles["user"] = 30
	roles["admin"] = 80
	aaa, err = httpauth.NewAuthorizer(backend, []byte("cookie-encryption-key"), "user", roles)

	// create a default user
	username := "admin"
	defaultUser := httpauth.UserData{Username: username, Role: "admin"}
	err = backend.SaveUser(defaultUser)
	if err != nil {
		panic(err)
	}
	// Update user with a password and email address
	err = aaa.Update(nil, nil, username, "adminadmin", "admin@localhost.com")
	if err != nil {
		panic(err)
	}

	// set up routers and route handlers
	r := mux.NewRouter()
	r.HandleFunc("/login", getLogin).Methods("GET")
	r.HandleFunc("/register", postRegister).Methods("POST")
	r.HandleFunc("/login", postLogin).Methods("POST")
	r.HandleFunc("/admin", handleAdmin).Methods("GET")
	r.HandleFunc("/add_user", postAddUser).Methods("POST")
	r.HandleFunc("/change", postChange).Methods("POST")
	r.HandleFunc("/", handlePage).Methods("GET") // authorized page
	r.HandleFunc("/logout", handleLogout)

	http.Handle("/", r)
	fmt.Printf("Server running on port %d\n", port)
	http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
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
	if err := aaa.Login(rw, req, username, password, "/"); err == nil || (err != nil && strings.Contains(err.Error(), "already authenticated")) {
		http.Redirect(rw, req, "/", http.StatusSeeOther)
	} else if err != nil {
		fmt.Println(err)
		http.Redirect(rw, req, "/login", http.StatusSeeOther)
	}
}

func postRegister(rw http.ResponseWriter, req *http.Request) {
	var user httpauth.UserData
	user.Username = req.PostFormValue("username")
	user.Email = req.PostFormValue("email")
	password := req.PostFormValue("password")
	if err := aaa.Register(rw, req, user, password); err == nil {
		postLogin(rw, req)
	} else {
		http.Redirect(rw, req, "/login", http.StatusSeeOther)
	}
}

func postAddUser(rw http.ResponseWriter, req *http.Request) {
	var user httpauth.UserData
	user.Username = req.PostFormValue("username")
	user.Email = req.PostFormValue("email")
	password := req.PostFormValue("password")
	user.Role = req.PostFormValue("role")
	if err := aaa.Register(rw, req, user, password); err != nil {
		// maybe something
	}

	http.Redirect(rw, req, "/admin", http.StatusSeeOther)
}

func postChange(rw http.ResponseWriter, req *http.Request) {
	email := req.PostFormValue("new_email")
	aaa.Update(rw, req, "", "", email)
	http.Redirect(rw, req, "/", http.StatusSeeOther)
}

func handlePage(rw http.ResponseWriter, req *http.Request) {
	if err := aaa.Authorize(rw, req, true); err != nil {
		fmt.Println(err)
		http.Redirect(rw, req, "/login", http.StatusSeeOther)
		return
	}
	if user, err := aaa.CurrentUser(rw, req); err == nil {
		type data struct {
			User httpauth.UserData
		}
		d := data{User: user}
		t, err := template.New("page").Parse(`
            <html>
            <head><title>Secret page</title></head>
            <body>
                <h1>Httpauth example<h1>
                {{ with .User }}
                    <h2>Hello {{ .Username }}</h2>
                    <p>Your role is '{{ .Role }}'. Your email is {{ .Email }}.</p>
                    <p>{{ if .Role | eq "admin" }}<a href="/admin">Admin page</a> {{ end }}<a href="/logout">Logout</a></p>
                {{ end }}
                <form action="/change" method="post" id="change">
                    <h3>Change email</h3>
                    <p><input type="email" name="new_email" placeholder="new email"></p>
                    <button type="submit">Submit</button>
                </form>
            </body>
            `)
		if err != nil {
			panic(err)
		}
		t.Execute(rw, d)
	}
}

func handleAdmin(rw http.ResponseWriter, req *http.Request) {
	if err := aaa.AuthorizeRole(rw, req, "admin", true); err != nil {
		fmt.Println(err)
		http.Redirect(rw, req, "/login", http.StatusSeeOther)
		return
	}
	if user, err := aaa.CurrentUser(rw, req); err == nil {
		type data struct {
			User  httpauth.UserData
			Roles map[string]httpauth.Role
			Users []httpauth.UserData
			Msg   []string
		}
		messages := aaa.Messages(rw, req)
		users, err := backend.Users()
		if err != nil {
			panic(err)
		}
		d := data{User: user, Roles: roles, Users: users, Msg: messages}
		t, err := template.New("admin").Parse(`
            <html>
            <head><title>Admin page</title></head>
            <body>
                <h1>Httpauth example<h1>
                <h2>Admin Page</h2>
                <p>{{.Msg}}</p>
                {{ with .User }}<p>Hello {{ .Username }}, your role is '{{ .Role }}'. Your email is {{ .Email }}.</p>{{ end }}
                <p><a href="/">Back</a> <a href="/logout">Logout</a></p>
                <h3>Users</h3>
                <ul>{{ range .Users }}<li>{{.Username}}</li>{{ end }}</ul>
                <form action="/add_user" method="post" id="add_user">
                    <h3>Add user</h3>
                    <p><input type="text" name="username" placeholder="username"><br>
                    <input type="password" name="password" placeholder="password"><br>
                    <input type="email" name="email" placeholder="email"><br>
                    <select name="role">
                        <option value="">role<option>
                        {{ range $key, $val := .Roles }}<option value="{{$key}}">{{$key}} - {{$val}}</option>{{ end }}
                    </select></p>
                    <button type="submit">Submit</button>
                </form>
            </body>
            `)
		if err != nil {
			panic(err)
		}
		t.Execute(rw, d)
	}
}

func handleLogout(rw http.ResponseWriter, req *http.Request) {
	if err := aaa.Logout(rw, req); err != nil {
		fmt.Println(err)
		// this shouldn't happen
		return
	}
	http.Redirect(rw, req, "/", http.StatusSeeOther)
}
