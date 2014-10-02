package httpauth

import (
    "bytes"
    "fmt"
    "os"
    "testing"
    "gopkg.in/mgo.v2"
)

var (
    mongo_backend   MongodbAuthBackend
    url     = "mongodb://127.0.0.1/"
    db      = "test"
)

func TestMongodbInit(t *testing.T) {
    con, err := mgo.Dial(url)
    if err != nil {
        t.Errorf("Couldn't set up test mongodb session: %v\nHave you started the mongo db?\n```\n$ mongod --dbpath mongodbtest/\n```", err)
        fmt.Printf("Couldn't set up test mongodb session: %v\nHave you started the mongo db?\n```\n$ mongod --dbpath mongodbtest/\n```\n", err)
        os.Exit(1)
    }
    defer con.Close()
    err = con.Ping()
    if err != nil {
        t.Errorf("Couldn't ping test mongodb database: %v", err)
        fmt.Printf("Couldn't ping test mongodb database: %v\n", err)
        // t.Errorf("Couldn't ping test database: %v\n", err)
        os.Exit(1)
    }
    database := con.DB(db)
    err = database.DropDatabase()
    if err != nil {
        t.Errorf("Couldn't drop test mongodb database: %v", err)
        fmt.Printf("Couldn't drop test mongodb database: %v\n", err)
        // t.Errorf("Couldn't ping test database: %v\n", err)
        os.Exit(1)
    }
}

func TestNewMongodbAuthBackend(t *testing.T) {
    var err error
    // Note: the following takes 10 seconds. It really should be included, but
    // I don't want to wait that long.
    //_, err = NewMongodbBackend("mongodb://example.com.doesntexist", db)
    //if err == nil {
    //    t.Fatal("Expected error on invalid url.")
    //}
    mongo_backend, err = NewMongodbBackend(url, db)
    if err != nil {
        t.Fatalf("NewMongodbBackend error: %v", err)
    }
    if mongo_backend.mongoURL != url {
        t.Fatal("Url name.")
    }
    if mongo_backend.database != db {
        t.Fatal("DB not saved.")
    }
}

func TestMongodbAuthorizer(t *testing.T) {
    roles := make(map[string]Role)
    roles["user"] = 40
    roles["admin"] = 80
    _, err := NewAuthorizer(mongo_backend, []byte("testkey"), "user", roles)
    if err != nil {
        t.Fatal(err)
    }
}

func TestSaveUser_mongodb(t *testing.T) {
    user2 := UserData{"username2", "email2", []byte("passwordhash2"), "role2"}
    if err := mongo_backend.SaveUser(user2); err != nil {
        t.Fatalf("SaveUser mongodb error: %v", err)
    }

    user := UserData{"username", "email", []byte("passwordhash"), "role"}
    if err := mongo_backend.SaveUser(user); err != nil {
        t.Fatalf("SaveUser mongodb error: %v", err)
    }
}

func TestNewMongodbAuthBackend_existing(t *testing.T) {
    var err error
    b2, err := NewMongodbBackend(url, db)
    if err != nil {
        t.Fatalf("NewMongodbBackend (existing) error: %v", err)
    }

    user, err := b2.User("username")
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

func TestUser_existing_mongodb(t *testing.T) {
    if user, err := mongo_backend.User("username"); err == nil {
        if user.Username != "username" {
            t.Fatal("Username not correct.")
        }
        if user.Email != "email" {
            t.Fatal("User email not correct.")
        }
        if !bytes.Equal(user.Hash, []byte("passwordhash")) {
            t.Fatal("User password not correct.")
        }
    } else {
        t.Fatalf("User not found: %v", err)
    }
    if user, err := mongo_backend.User("username2"); err == nil {
        if user.Username != "username2" {
            t.Fatal("Username not correct.")
        }
        if user.Email != "email2" {
            t.Fatal("User email not correct.")
        }
        if !bytes.Equal(user.Hash, []byte("passwordhash2")) {
            t.Fatal("User password not correct.")
        }
    } else {
        t.Fatalf("User not found: %v", err)
    }
}

func TestUser_notexisting_mongodb(t *testing.T) {
    if _, err := mongo_backend.User("notexist"); err != ErrMissingUser {
        t.Fatalf("Not existing user found: %v", err)
    }
}

func TestUsers_mongodb(t *testing.T) {
    var (
        u1 UserData
        u2 UserData
    )
    users, err := mongo_backend.Users()
    if err != nil {
        t.Fatal(err)
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
        t.Fatal("Username not correct.")
    }
    if u1.Email != "email" {
        t.Fatal("User email not correct.")
    }
    if !bytes.Equal(u1.Hash, []byte("passwordhash")) {
        t.Fatal("User password not correct.")
    }
    if u2.Username != "username2" {
        t.Fatal("Username not correct.")
    }
    if u2.Email != "email2" {
        t.Fatal("User email not correct.")
    }
    if !bytes.Equal(u2.Hash, []byte("passwordhash2")) {
        t.Fatal("User password not correct.")
    }
}

func TestUpdateUser_mongodb(t *testing.T) {
    user2 := UserData{"username", "newemail", []byte("newpassword"), "newrole"}
    if err := mongo_backend.SaveUser(user2); err != nil {
        t.Fatalf("SaveUser mongodb error: %v", err)
    }
    u2, err := mongo_backend.User("username")
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
        t.Fatalf("User role not correct: found %v, expected %v", u2.Role, "newrole");
    }
    if !bytes.Equal(u2.Hash, []byte("newpassword")) {
        t.Fatal("User password not correct.")
    }
}

func TestMongodbDeleteUser(t *testing.T) {
    if err := mongo_backend.DeleteUser("username"); err != nil {
        t.Fatalf("DeleteUser error: %v", err)
    }
    err := mongo_backend.DeleteUser("username")
    if err != ErrDeleteNull {
        t.Fatalf("DeleteUser should have raised ErrDeleteNull: %v", err)
    } else if err != ErrDeleteNull {
        t.Fatalf("DeleteUser raised unexpected error: %v", err)
    }
}

func TestMongodbReopen(t *testing.T) {
    var err error

    mongo_backend.Close()

    mongo_backend, err = NewMongodbBackend(url, db)
    if err != nil {
        t.Fatal(err.Error())
    }

    mongo_backend.Close()

    mongo_backend, err = NewMongodbBackend(url, db)
    if err != nil {
        t.Fatal(err.Error())
    }

    users, err := mongo_backend.Users()
    if err != nil {
        t.Fatal(err.Error())
    }
    if len(users) != 1 {
        t.Error("Users not loaded.")
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

func TestMongodbDelete2(t *testing.T) {
    if err := mongo_backend.DeleteUser("username2"); err != nil {
        t.Fatalf("DeleteUser error: %v", err)
    }
}

func TestMongodbClose(t *testing.T) {
    mongo_backend.Close()
}
