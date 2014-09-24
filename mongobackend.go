package httpauth

import (
    "errors"
    "gopkg.in/mgo.v2"
    "gopkg.in/mgo.v2/bson"
    "fmt"
)


// MongodbAuthBackend stores database connection information.
type MongodbAuthBackend struct {
    mongoUrl string
    database string
}

func (b MongodbAuthBackend) connect() (c *mgo.Collection, err error) {
    sesh, err := mgo.Dial(b.mongoUrl)
    if err != nil {
        return c, errors.New("Can't connect to mongodb: " + err.Error())
    }
    return sesh.DB(b.database).C("goauth"), nil
}

// NewMongodbAuthBackend initializes a new backend.
func NewMongodbBackend(mongoUrl string, database string) (b MongodbAuthBackend, err error) {
    b.mongoUrl = mongoUrl
    b.database = database
    sesh, err := mgo.Dial(b.mongoUrl)
    defer sesh.Close()
    if err != nil {
        return b, errors.New("Can't connect to mongodb: " + err.Error())
    }
    return b, nil
}

// User returns the user with the given username.
func (b MongodbAuthBackend) User(username string) (user UserData, ok bool) {
    c, err := b.connect()
    if err != nil {
        panic(err)
    }
    var result UserData

    err = c.Find(bson.M{"Username": username}).One(&result)
    if err != nil {
        return result, false
    }
    return result, true
}

// Users returns a slice of all users.
func (b MongodbAuthBackend) Users() (us []UserData) {
    c, err := b.connect()
    if err != nil {
        panic(err)
    }
    var results []UserData
    err = c.Find(bson.M{}).All(&results)
    if err != nil {
        fmt.Printf("got an error finding a doc %v\n")
    }
    return results
}

// SaveUser adds a new user, replacing if the same username is in use.
func (b MongodbAuthBackend) SaveUser(user UserData) error {
    c, err := b.connect()
    if err != nil {
        panic(err)
    }
    hash := string(user.Hash)
    m := c.Find(bson.M{ "Username": user.Username })
    l, err := m.Count()
    if err != nil {
        panic(err)
    }
    if (l == 0) {
        err = c.Insert(bson.M{ "Username": user.Username, "Hash": hash, "Email": user.Email, "Role": user.Role })
    } else {
        err = c.Update(bson.M{ "Username": user.Username }, bson.M{ "Username": user.Username, "Hash": hash, "Email": user.Email, "Role": user.Role })
    }
    return err
}

// DeleteUser removes a user. An error is raised if the user isn't found.
// TODO: Should that error be raised? (Different than sql)
func (b MongodbAuthBackend) DeleteUser(username string) error {
    c, err := b.connect()
    if err != nil {
        panic(err)
    }
    err = c.Remove(bson.M{"Username": username})
    return err
}
