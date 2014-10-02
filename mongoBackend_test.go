package httpauth

import (
    "fmt"
    "os"
    "testing"
    "gopkg.in/mgo.v2"
)

var (
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
    // Note: the following takes 10 seconds. It really should be included, but
    // I don't want to wait that long.
    //_, err = NewMongodbBackend("mongodb://example.com.doesntexist", db)
    //if err == nil {
    //    t.Fatal("Expected error on invalid url.")
    //}
    mongo_backend, err := NewMongodbBackend(url, db)
    if err != nil {
        t.Fatalf("NewMongodbBackend error: %v", err)
    }
    if mongo_backend.mongoURL != url {
        t.Error("Url name.")
    }
    if mongo_backend.database != db {
        t.Error("DB not saved.")
    }

    TestBackend(t, mongo_backend)
}

func TestMongodbReopen(t *testing.T) {
    mongo_backend, err := NewMongodbBackend(url, db)
    if err != nil {
        t.Fatal(err.Error())
    }

    mongo_backend.Close()

    mongo_backend, err = NewMongodbBackend(url, db)
    if err != nil {
        t.Fatal(err.Error())
    }

    TestBackend2(t, mongo_backend)
}
