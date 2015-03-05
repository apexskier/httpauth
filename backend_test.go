package httpauth

import (
	"bytes"
	"testing"
)

func testBackendAuthorizer(t *testing.T, backend AuthBackend) {
	roles := make(map[string]Role)
	roles["user"] = 40
	roles["admin"] = 80
	_, err := NewAuthorizer(backend, []byte("testkey"), "user", roles)
	if err != nil {
		t.Fatal(err)
	}
}

func testBackendSaveUser(t *testing.T, backend AuthBackend) {
	user2 := UserData{"username2", "email2", []byte("passwordhash2"), "role2"}
	if err := backend.SaveUser(user2); err != nil {
		t.Fatalf("SaveUser sql error: %v", err)
	}

	user := UserData{"username", "email", []byte("passwordhash"), "role"}
	if err := backend.SaveUser(user); err != nil {
		t.Fatalf("SaveUser sql error: %v", err)
	}
}

func testBackendNewAuthBackend_existing(t *testing.T, backend AuthBackend) {
	user, err := backend.User("username")
	if err != nil {
		t.Fatal("Secondary backend failed")
	}
	if user.Username != "username" {
		t.Fatal("Username not correct.")
	}
	if user.Email != "email" {
		t.Fatal("User email not correct.")
	}
	if !bytes.Equal(user.Hash, []byte("passwordhash")) {
		t.Fatal("User password not correct.")
	}
}

func testBackendUser_existing(t *testing.T, backend AuthBackend) {
	if user, err := backend.User("username"); err == nil {
		if user.Username != "username" {
			t.Error("Username not correct.")
		}
		if user.Email != "email" {
			t.Error("User email not correct.")
		}
		if !bytes.Equal(user.Hash, []byte("passwordhash")) {
			t.Error("User password not correct.")
		}
	} else {
		t.Errorf("User not found: %v", err)
	}
	if user, err := backend.User("username2"); err == nil {
		if user.Username != "username2" {
			t.Error("Username not correct.")
		}
		if user.Email != "email2" {
			t.Error("User email not correct.")
		}
		if !bytes.Equal(user.Hash, []byte("passwordhash2")) {
			t.Error("User password not correct.")
		}
	} else {
		t.Fatalf("User not found: %v", err)
	}
}

func testBackendUser_notexisting(t *testing.T, backend AuthBackend) {
	if _, err := backend.User("notexist"); err != ErrMissingUser {
		t.Fatal("Not existing user found.")
	}
}

func testBackendUsers(t *testing.T, backend AuthBackend) {
	var (
		u1 UserData
		u2 UserData
	)
	users, err := backend.Users()
	if err != nil {
		t.Fatal(err.Error())
	}
	if len(users) != 2 {
		t.Fatal("Wrong amount of users found.")
	}
	if users[0].Username == "username" {
		u1 = users[0]
		u2 = users[1]
	} else if users[1].Username == "username" {
		u1 = users[1]
		u2 = users[0]
	} else {
		t.Fatal("One of the users not found.")
	}

	if u1.Username != "username" {
		t.Error("Username not correct.")
	}
	if u1.Email != "email" {
		t.Error("User email not correct.")
	}
	if !bytes.Equal(u1.Hash, []byte("passwordhash")) {
		t.Error("User password not correct.")
	}
	if u2.Username != "username2" {
		t.Error("Username not correct.")
	}
	if u2.Email != "email2" {
		t.Error("User email not correct.")
	}
	if !bytes.Equal(u2.Hash, []byte("passwordhash2")) {
		t.Error("User password not correct.")
	}
}

func testBackendUpdateUser(t *testing.T, backend AuthBackend) {
	user2 := UserData{"username", "newemail", []byte("newpassword"), "newrole"}
	if err := backend.SaveUser(user2); err != nil {
		t.Fatalf("SaveUser sql error: %v", err)
	}
	u2, err := backend.User("username")
	if err != nil {
		t.Fatal("Updated user not found")
	}
	if u2.Username != "username" {
		t.Fatal("Username not correct.")
	}
	if u2.Email != "newemail" {
		t.Fatal("User email not correct.")
	}
	if u2.Role != "newrole" {
		t.Fatalf("User role not correct: found %v, expected %v", u2.Role, "newrole")
	}
	if !bytes.Equal(u2.Hash, []byte("newpassword")) {
		t.Fatal("User password not correct.")
	}
}

func testBackendDeleteUser(t *testing.T, backend AuthBackend) {
	if err := backend.DeleteUser("username"); err != nil {
		t.Fatalf("DeleteUser error: %v", err)
	}
	err := backend.DeleteUser("username")
	if err == nil {
		t.Fatalf("DeleteUser should have raised error")
	} else if err != ErrDeleteNull {
		t.Fatalf("DeleteUser raised unexpected error: %v", err)
	}
}

func testBackendClose(t *testing.T, backend AuthBackend) {
	backend.Close()
}

func testBackend(t *testing.T, backend AuthBackend) {
	testBackendAuthorizer(t, backend)
	testBackendSaveUser(t, backend)
	testBackendNewAuthBackend_existing(t, backend)
	testBackendUser_existing(t, backend)
	testBackendUser_notexisting(t, backend)
	testBackendUsers(t, backend)
	testBackendUpdateUser(t, backend)
	testBackendDeleteUser(t, backend)
	testBackendClose(t, backend)
}

func testAfterReopen(t *testing.T, backend AuthBackend) {
	users, err := backend.Users()
	if err != nil {
		t.Fatal(err.Error())
	}
	if len(users) != 1 {
		t.Fatalf("Users not loaded properly. length = %d", len(users))
	}
	if users[0].Username != "username2" {
		t.Error("Username not correct.")
	}
	if users[0].Email != "email2" {
		t.Error("User email not correct.")
	}
	if !bytes.Equal(users[0].Hash, []byte("passwordhash2")) {
		t.Error("User password not correct.")
	}
}

func testDelete2(t *testing.T, backend AuthBackend) {
	if err := backend.DeleteUser("username2"); err != nil {
		t.Fatalf("DeleteUser error: %v", err)
	}
}

func testClose2(t *testing.T, backend AuthBackend) {
	backend.Close()
}

func testBackend2(t *testing.T, backend AuthBackend) {
	testAfterReopen(t, backend)
	testDelete2(t, backend)
	testClose2(t, backend)
}
