package api

import (
	"backend/proto/out"
	ucrypto "backend/utils/security/crypto"
	"os"

	"context"
	"log"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	keysPassword = os.Getenv("KEYS_PASSWORD")
	apiPrivateKey = ucrypto.LoadPrivateKey("API_PRIVATE_KEY", keysPassword)
	frontendPublicKey = ucrypto.LoadPublicKey("FRONTEND_PUBLIC_KEY")
	backendPublicKey = ucrypto.LoadPublicKey("BACKEND_PUBLIC_KEY")
)


type Response struct {
	Message  string `json:"message" xml:"message"`
}

type Request struct {
	Message  string `json:"message" xml:"message"`
}

type GrpcClient struct {
	conn *grpc.ClientConn
}

func NewGrpcClient(address string, opts []grpc.DialOption) (*GrpcClient, error) {
	connection, err := grpc.NewClient(address, opts...)
	if err != nil {
		return nil, err
	}

	return &GrpcClient{conn: connection}, nil
}

func (gc *GrpcClient) TestFunc(msg string) (*out.TestResponse, error) {
	testClient := out.NewTestClient(gc.conn)
	encryptedMessage := ucrypto.Encrypt(backendPublicKey, []byte(msg))
	encodedMessage := ucrypto.EncodeBase64(encryptedMessage)

	res, err := testClient.TestFunc(context.Background(), &out.TestRequest{Message: encodedMessage})
	return res, err
}

func Server() {
	gc,err := NewGrpcClient("localhost:50051", []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	})
	if err != nil {
		log.Fatalln(err.Error())
	}


	e := echo.New()
	e.Use(middleware.CORS())
	log.Println("Starting Echo HTTP Server")
	e.GET("/api/test", func(c echo.Context) error {
		return c.JSON(http.StatusOK, &Response{
			Message: "GO GET RESPONSE",
		})
	})

	e.POST("/api/test", func(c echo.Context) error {
		r := new(Request)
		if err := c.Bind(r); err != nil {
			return c.JSON(http.StatusBadRequest, &Response{
				Message: "BAD REQUEST",
			})
		}

		decodedMessage := ucrypto.DecodeBase64(r.Message)
		decryptedMessage := ucrypto.Decrypt(apiPrivateKey, decodedMessage)


		response, err := gc.TestFunc(string(decryptedMessage))
		if err != nil {
			log.Fatalln(err.Error())
		}

		reponseMessage := response.GetMessage()
		decodedResponseMessage := ucrypto.DecodeBase64(reponseMessage)
		decryptedResponseMessage := ucrypto.Decrypt(apiPrivateKey, decodedResponseMessage)

		returnEncryptedMessage := ucrypto.Encrypt(frontendPublicKey, decryptedResponseMessage)
		encodedReturnMessage := ucrypto.EncodeBase64(returnEncryptedMessage)


		return c.JSON(http.StatusOK, &Response{
			Message: encodedReturnMessage,
		})
	})
	e.Logger.Fatal(e.Start(":1323"))
}