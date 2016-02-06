package httpauth

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

var (
	b          GobFileAuthBackend
	a          Authorizer
	file       = "auth_test.gob"
	c          http.Client
	authCookie http.Cookie
)

func init() {
	roles := make(map[string]Role)
	roles["user"] = 40
	roles["admin"] = 80
	t, _ := time.Parse("Mon, 02 Jan 2006 15:04:05 MST", "Mon, 07 Apr 2014 21:47:54 UTC")
	authCookie = http.Cookie{
		Name:    "auth",
		Value:   "MTM5NDMxNTI3NHxEdi1GQkFFQ180WUFBUkFCRUFBQUt2LUdBQUVHYzNSeWFXNW5EQW9BQ0hWelpYSnVZVzFsQm5OMGNtbHVad3dLQUFoMWMyVnlibUZ0WlE9PXxR5vqFijkMnXg5SNpymM0LhaNRdlA97bBarGb_S4ghGQ==",
		Path:    "/",
		Expires: t,
		MaxAge:  2592000}
}

func TestNewAuthorizer(t *testing.T) {
	os.Remove(file)
	if _, err := os.Create(file); err != nil {
		t.Fatal(err.Error())
	}

	var err error
	b, err = NewGobFileAuthBackend(file)
	if err != nil {
		t.Fatal(err.Error())
	}

	roles := make(map[string]Role)
	roles["user"] = 40
	roles["admin"] = 80
	a, err = NewAuthorizer(b, []byte("testkey"), "user", roles)
	if err != nil {
		t.Fatal(err.Error())
	}
}

func TestRegister(t *testing.T) {
	rw := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/", nil)
	newUser := UserData{Username: "username", Email: "email@example.com"}
	err := a.Register(rw, req, newUser, "password")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if rw.Code != http.StatusOK {
		t.Fatalf("Register: Wrong status code: %v", rw.Code)
	}

	newUser2 := UserData{Username: "username", Email: "email@example.com", Role: "admin"}
	err = a.Register(rw, req, newUser2, "password")
	if rw.Code != http.StatusOK {
		t.Fatalf("Register: Wrong status code: %v", rw.Code)
	}
	if err == nil {
		t.Fatal("Register: User registered with duplicate name")
	}
	if em := err.Error(); em != "httpauth: user already exists" {
		t.Fatalf("Register: %v", em)
	}
	headers := rw.Header()
	if headers.Get("Set-Cookie") == "" {
		t.Fatal("Messages cookies not set")
	}
}

func TestUpdate(t *testing.T) {
	rw := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/", nil)
	updatedEmail := "email2@example.com"
	err := a.Update(rw, req, "username", "", updatedEmail)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if rw.Code != http.StatusOK {
		t.Fatalf("Update: Wrong status code: %v", rw.Code)
	}

	user, err := a.backend.User("username")
	if err != nil {
		t.Fatalf("Couldn't get updated user: %v", err)
	}

	if user.Email != updatedEmail {
		t.Errorf("Updated user's email is %s, expected %s", user.Email, updatedEmail)
	}
}

func TestLogin(t *testing.T) {
	rw := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/", nil)
	if err := a.Login(rw, req, "username", "wrongpassword", "/redirect"); err == nil {
		t.Fatal("Login: Logged in with incorrect password.")
	}
	headers := rw.Header()
	if cookies := headers.Get("Set-Cookie"); cookies == "" {
		t.Fatal("Login: No cookies set")
	}

	req.AddCookie(&authCookie)
	if err := a.Login(rw, req, "username", "password", "/redirect"); err != nil {
		t.Fatal("Login: Didn't catch existing cookie")
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
		t.Log("Authorization: didn't catch new cookie")
	}
	req, _ = http.NewRequest("GET", "/", nil)
	if err := a.Login(rw, req, "username", "password", "/redirect"); err != nil {
		t.Fatalf("Authorization login error: %v", err)
	}
	req.AddCookie(&authCookie)
	if err := a.Authorize(rw, req, true); err != nil {
		t.Fatalf("Authorization error: %v", err) // Should work
	}
}

func TestAuthorizeRole(t *testing.T) {
	rw := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	if err := a.AuthorizeRole(rw, req, "user", true); err == nil {
		t.Fatal("AuthorizeRole: no error on non authorized request")
	}
	a.Login(rw, req, "username", "password", "/redirect")

	req.AddCookie(&authCookie)
	// TODO:
	//if err := a.AuthorizeRole(rw, req, 20, true); err == nil || err.Error() != "no session existed" {
	//   t.Log("Authorization: didn't catch new cookie")
	//}
	req, _ = http.NewRequest("GET", "/", nil)
	if err := a.Login(rw, req, "username", "password", "/redirect"); err != nil {
		t.Fatalf("Authorization login error: %v", err)
	}
	req.AddCookie(&authCookie)
	if err := a.AuthorizeRole(rw, req, "blah", true); err == nil {
		t.Fatal("AuthorizeRole error: Didn't fail on invalid role")
	}
	if err := a.AuthorizeRole(rw, req, "user", true); err != nil {
		t.Fatalf("AuthorizeRole error: %v", err) // Should work
	}
	if err := a.AuthorizeRole(rw, req, "admin", true); err == nil {
		t.Fatal("AuthorizeRole error: didn't restrict lower role user", err) // Should work
	}
}

func TestLogout(t *testing.T) {
	rw := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	if err := a.Logout(rw, req); err != nil {
		t.Fatalf("Logout error: %v", err)
	}
	// headers := rw.Header()
	// TODO: Test that the auth cookie's expiration date is set to Thu, 01 Jan 1970 00:00:01
}

func TestDeleteUser(t *testing.T) {
	if err := a.DeleteUser("username"); err != nil {
		t.Fatalf("DeleteUser error: %v", err)
	}
	if err := a.DeleteUser("username"); err != ErrDeleteNull {
		t.Fatalf("DeleteUser should have returned ErrDeleteNull: got %v", err)
	}

	os.Remove(file)
}
