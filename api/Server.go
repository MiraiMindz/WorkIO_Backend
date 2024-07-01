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
	keysPassword      = os.Getenv("KEYS_PASSWORD")
	apiPrivateKey     = ucrypto.LoadPrivateKey("API_PRIVATE_KEY", keysPassword)
	frontendPublicKey = ucrypto.LoadPublicKey("FRONTEND_PUBLIC_KEY")
	backendPublicKey  = ucrypto.LoadPublicKey("BACKEND_PUBLIC_KEY")
)

type LoginResponse struct {
	Token string `json:"token" xml:"token"`
}

type LoginRequest struct {
	Email    string `json:"email" xml:"email"`
	Password string `json:"password" xml:"password"`
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

func (gc *GrpcClient) AuthenticateLogin(req *LoginRequest) (*out.Token, error) {
	authClient := out.NewAuthenticationClient(gc.conn)
	encodedEmail := ucrypto.EncryptEncode(backendPublicKey, []byte(req.Email))
	encodedPassword:= ucrypto.EncryptEncode(backendPublicKey, []byte(req.Password))

	res, err := authClient.AuthenticateLogin(context.Background(), &out.Login{Email: encodedEmail, Password: encodedPassword})
	return res, err
}

func LoginRoute(gc *GrpcClient) (func(c echo.Context) error) {
	return func(c echo.Context) error {
		r := new(LoginRequest)
		if err := c.Bind(r); err != nil {
			return c.JSON(http.StatusBadRequest, &LoginResponse{
				Token: "",
			})
		}

		decryptedEmail := ucrypto.DecodeDecrypt(apiPrivateKey, r.Email)
		decryptedPassword := ucrypto.DecodeDecrypt(apiPrivateKey, r.Password)

		response, err := gc.AuthenticateLogin(&LoginRequest{
			Email: string(decryptedEmail),
			Password: string(decryptedPassword),
		})
		if err != nil {
			log.Fatalln(err.Error())
		}

		responseToken := response.GetToken()

		returnToken := ucrypto.DecodeDecryptFromEncryptEncodeTo(apiPrivateKey, frontendPublicKey, responseToken)

		return c.JSON(http.StatusOK, &LoginResponse{
			Token: returnToken,
		})
	}
}

func Server() {
	gc, err := NewGrpcClient("localhost:50051", []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	})
	if err != nil {
		log.Fatalln(err.Error())
	}

	e := echo.New()
	e.Use(middleware.CORS())
	log.Println("Starting Echo HTTP Server")

	e.POST("/api/login", LoginRoute(gc))
	e.Logger.Fatal(e.Start(":1323"))
}
