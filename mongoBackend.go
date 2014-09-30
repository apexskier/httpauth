package httpauth

import (
    "gopkg.in/mgo.v2"
    "gopkg.in/mgo.v2/bson"
    "fmt"
)


// MongodbAuthBackend stores database connection information.
type MongodbAuthBackend struct {
    mongoUrl string
    database string
    session  *mgo.Session
}

func (b MongodbAuthBackend) connect() *mgo.Collection {
    session := b.session.Copy()
    return session.DB(b.database).C("goauth")
}

// NewMongodbAuthBackend initializes a new backend.
// Be sure to call Close() on this to clean up the mongodb connection.
// Example:
//     backend = httpauth.MongodbAuthBackend("mongodb://127.0.0.1/", "auth")
//     defer backend.Close()
func NewMongodbBackend(mongoUrl string, database string) (b MongodbAuthBackend) {
    // Set up connection to database
    b.mongoUrl = mongoUrl
    b.database = database
    session, err := mgo.Dial(b.mongoUrl)
    if err != nil {
        panic(err)
    }

    // Ensure that the Username field is unique
    index := mgo.Index{
        Key: []string{"Username"},
        Unique: true,
    }
    err = session.DB(b.database).C("goauth").EnsureIndex(index)
    if err != nil {
        panic(err)
    }
    b.session = session
    return
}

// User returns the user with the given username.
func (b MongodbAuthBackend) User(username string) (user UserData, ok bool) {
    var result UserData

    c := b.connect()
    defer c.Database.Session.Close()

    err := c.Find(bson.M{"Username": username}).One(&result)
    if err != nil {
        return result, false
    }
    return result, true
}

// Users returns a slice of all users.
func (b MongodbAuthBackend) Users() (us []UserData) {
    var results []UserData

    c := b.connect()
    defer c.Database.Session.Close()

    err := c.Find(bson.M{}).All(&results)
    if err != nil {
        // TODO: Remove
        fmt.Printf("got an error finding a doc %v\n")
    }
    return results
}

// SaveUser adds a new user, replacing if the same username is in use.
func (b MongodbAuthBackend) SaveUser(user UserData) error {
    c := b.connect()
    defer c.Database.Session.Close()

    _, err := c.Upsert(bson.M{ "Username": user.Username }, bson.M{ "$set": user })
    return err
}

// DeleteUser removes a user. ErrNotFound is returned if the user isn't found.
func (b MongodbAuthBackend) DeleteUser(username string) error {
    c := b.connect()
    defer c.Database.Session.Close()

    // raises error if "username" doesn't exist
    err := c.Remove(bson.M{"Username": username})
    if err == mgo.ErrNotFound {
        return ErrDeleteNull
    }
    return err
}

func (b MongodbAuthBackend) Close() {
    if b.session != nil {
        b.session.Close()
    }
}
