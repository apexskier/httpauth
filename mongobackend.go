package httpauth-mgo

import (
    "errors"
    "gopkg.in/mgo.v2"
    "gopkg.in/mgo.v2/bson"
    "fmt"
)


type udata struct {
	Userame	string	`bson:"Username"`
	Email  	string	`bson:"Email"`
	Hash  	[]byte 	`bson:"Hash"`
	Role 	string	`bson:"Role"`
}

// MongodbAuthBackend stores database connection information.
type MongodbAuthBackend struct {
    mongoUrl string
    database string
}

// NewMongodbAuthBackend initializes a new backend.
func NewMongodbBackend(mongoUrl string, database string) (b MongodbAuthBackend, err error) {
    b.mongoUrl = mongoUrl
    b.database = database
    _, err = mgo.Dial(b.mongoUrl)
    if err != nil {
        return b, errors.New("Can't connect to mongodb: " + err.Error())
    }
    return b, nil
}

func (b MongodbAuthBackend) connect() (c *mgo.Collection, err error) {
    sesh, err := mgo.Dial(b.mongoUrl)
    if err != nil {
        return c, errors.New("Can't connect to mongodb: " + err.Error())
    }
    return sesh.DB(b.database).C("goauth"), nil
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
	fmt.Println("Cannot find specified user (" + username + ")")
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

// SaveUser adds a new user, replacing one with the same username.
func (b MongodbAuthBackend) SaveUser(user UserData) error {
    c, err := b.connect()
    if err != nil {
        panic(err)
    }
    hash := string(user.Hash)
    err = c.Insert(bson.M{ "Username": user.Username, "Hash": hash, "Email": user.Email, "Role": user.Role })
    return err
}

// DeleteUser removes a user.
func (b MongodbAuthBackend) DeleteUser(username string) error {
    c, err := b.connect()
    if err != nil {
        panic(err)
    }
    err = c.Remove(bson.M{"Username": username})
    return err
}
