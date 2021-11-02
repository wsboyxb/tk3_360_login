package main

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"net/http"
	"time"
)

const (
	loginKey = "7HaZ64vvXBdppcbrClqvZmj02XzB6ubg" //key为登录key(360自接入后台生成)
	mongoURI = "mongodb+srv://<username>:<password>@<cluster-address>/test?w=majority"
)

var (
	coll                    *mongo.Collection
	dbURI, dbName, collName string
)

func main() {
	flag.StringVar(&dbURI, "u", mongoURI, "database uri")
	flag.StringVar(&dbName, "d", "", "database name")
	flag.StringVar(&collName, "c", "", "collection name")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(dbURI))
	if err != nil {
		panic(err)
	}
	defer func() {
		err := client.Disconnect(ctx)
		if err != nil {
			panic(err)
		}
	}()
	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		panic(err)
	}
	coll = client.Database(dbName).Collection(collName)

	// Echo instance
	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	e.Logger.SetLevel(log.INFO)
	//e.Debug = true

	// Routes
	group := e.Group("/360")
	group.GET("/login", login)
	group.GET("/active", active)

	// Start server
	e.Logger.Fatal(e.Start(":1323"))
}

type Result struct {
	Errno  int    `json:"errno"`
	Errmsg string `json:"errmsg"`
	Data   struct {
		Uid       string `json:"uid,omitempty"`
		AuthKey   string `json:"auth_key,omitempty"`
		Zone      *int   `json:"zone,omitempty"`
		ExtraInfo string `json:"extraInfo,omitempty"`
	} `json:"data"`
}

func active(c echo.Context) error {
	var qid int64
	var serverID, sign string
	err := echo.QueryParamsBinder(c).MustInt64("qid", &qid).MustString("server_id", &serverID).
		MustString("sign", &sign).BindError()
	if err != nil {
		return c.String(http.StatusOK, "-1")
	}

	//签名校验
	s := fmt.Sprintf("%d%s%s", qid, serverID, loginKey)
	hash := md5.Sum([]byte(s))
	if sign != hex.EncodeToString(hash[:]) {
		return c.String(http.StatusOK, "-1")
	}

	err = coll.FindOne(context.TODO(), bson.M{"_id": fmt.Sprint("360_", qid)}).Err()
	if errors.Is(err, mongo.ErrNoDocuments) {
		return c.String(http.StatusOK, "0")
	}
	if err != nil {
		return c.String(http.StatusOK, "-2")
	}
	return c.String(http.StatusOK, "1")
}

func login(c echo.Context) error {
	var qid int64
	var timeStamp, isAdult int
	var serverID, sign string

	err := echo.QueryParamsBinder(c).MustInt64("qid", &qid).MustInt("time", &timeStamp).
		MustInt("isAdult", &isAdult).MustString("server_id", &serverID).
		MustString("sign", &sign).BindError()
	if err != nil {
		return c.JSON(http.StatusOK, returnErr(-2, "参数错误"))
	}

	s := fmt.Sprintf("qid=%d&time=%d&server_id=%s%s", qid, timeStamp, serverID, loginKey)
	hash := md5.Sum([]byte(s))
	if sign != hex.EncodeToString(hash[:]) {
		return c.JSON(http.StatusOK, returnErr(-1, "签名错误"))
	}

	var r Result
	r.Errmsg = "成功"
	r.Data.Uid = fmt.Sprint(qid)
	r.Data.AuthKey = tokenGenerator()
	r.Data.ExtraInfo = fmt.Sprint(time.Now().Unix())
	var i = 0
	r.Data.Zone = &i
	return c.JSON(http.StatusOK, r)
}

func returnErr(code int, msg string) Result {
	return Result{
		Errno:  code,
		Errmsg: msg,
	}
}

func tokenGenerator() string {
	b := make([]byte, 12)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
