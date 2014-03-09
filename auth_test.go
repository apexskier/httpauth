package httpauth

import (
    "testing"
    "os"
    "net/http"
    "net/http/httptest"
    "time"
)

var (
    b GobFileAuthBackend
    a Authorizer
    file = "auth_test.gob"
    c http.Client
    authCookie http.Cookie
)

func init() {
    os.Remove(file)
    b = NewGobFileAuthBackend(file)
    a = NewAuthorizer(b, []byte("secret-key"))
    t, _ := time.Parse("Mon, 02 Jan 2006 15:04:05 MST", "Mon, 07 Apr 2014 21:47:54 UTC")
    authCookie = http.Cookie{
        Name:"auth",
        Value:"MTM5NDMxNTI3NHxEdi1GQkFFQ180WUFBUkFCRUFBQUt2LUdBQUVHYzNSeWFXNW5EQW9BQ0hWelpYSnVZVzFsQm5OMGNtbHVad3dLQUFoMWMyVnlibUZ0WlE9PXxR5vqFijkMnXg5SNpymM0LhaNRdlA97bBarGb_S4ghGQ==",
        Path:"/",
        Expires: t,
        MaxAge:2592000}
}

func TestNewAuthorizer(t *testing.T) {
    a = NewAuthorizer(b, []byte("testkey"))
}

func TestRegister(t *testing.T) {
    rw := httptest.NewRecorder()
    req, _ := http.NewRequest("POST", "/", nil)
    err := a.Register(rw, req, "username", "password", "email@example.com")
    if rw.Code != http.StatusOK {
        t.Fatalf("Register: Wrong status code: %v", rw.Code)
    }
    if err != nil {
        t.Fatalf("Register: error %v", err)
    }

    err = a.Register(rw, req, "username", "password", "email@example.com")
    if rw.Code != http.StatusOK {
        t.Fatalf("Register: Wrong status code: %v", rw.Code)
    }
    if err == nil {
        t.Fatalf("Register: User registered with duplicate name")
    }
    if em := err.Error(); em != "user already exists" {
        t.Fatalf("Register: %v", em)
    }
    headers := rw.Header()
    if headers.Get("Set-Cookie") == "" {
        t.Fatal("Messages cookies not set")
    }
}

func TestLogin(t *testing.T) {
    rw := httptest.NewRecorder()
    req, _ := http.NewRequest("POST", "/", nil)
    if err := a.Login(rw, req, "username", "wrongpassword", "/redirect"); err == nil {
        t.Fatalf("Login: Logged in with incorrect password.")
    }
    headers := rw.Header()
    if cookies := headers.Get("Set-Cookie"); cookies == "" {
        t.Fatal("Login: No cookies set")
    }

    req.AddCookie(&authCookie)
    if err := a.Login(rw, req, "username", "password", "/redirect"); err != nil {
        t.Fatalf("Login: Didn't catch existing cookie")
    }
    req, _ = http.NewRequest("POST", "/", nil)
    if err := a.Login(rw, req, "username", "password", "/redirect"); err != nil {
        t.Fatalf("Login: Error on login: %v", err)
    }
    headers = rw.Header()
    if loc := headers.Get("Location"); loc != "/redirect" {
        t.Fatal("Login: Redirect not set")
    }
    if cookies := headers.Get("Set-Cookie"); cookies == "" {
        t.Fatal("Login: No cookies set")
    }
}

func TestAuthorize(t *testing.T) {
    rw := httptest.NewRecorder()
    req, _ := http.NewRequest("GET", "/", nil)
    if err := a.Authorize(rw, req, true); err == nil {
        t.Fatal("Authorize: no error on non authorized request")
    }
    a.Login(rw, req, "username", "password", "/redirect")

    req.AddCookie(&authCookie)
    if err := a.Authorize(rw, req, true); err == nil || err.Error() != "no session existed" {
        t.Fatalf("Authorization: didn't catch new cookie")
    }
    req, _ = http.NewRequest("GET", "/", nil)
    if err := a.Login(rw, req, "username", "password", "/redirect"); err != nil {
        t.Fatalf("Authorization login error: %v", err)
    }
    req.AddCookie(&authCookie)
    if err := a.Authorize(rw, req, true); err != nil {
        //t.Fatalf("Authorization error: %v", err) // Should work
    }
}

func TestLogout(t *testing.T) {
    rw := httptest.NewRecorder()
    req, _ := http.NewRequest("GET", "/", nil)
    if err := a.Logout(rw, req); err != nil {
        t.Fatalf("Logout error: %v", err)
    }
    // headers := rw.Header()
    // Test that the auth cookie's expiration date is set to Thu, 01 Jan 1970 00:00:01
}

func TestDeleteUser(t *testing.T) {
    if err := a.DeleteUser("username"); err != nil {
        t.Fatalf("DeleteUser error: %v", err)
    }
}


