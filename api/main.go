package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	secure "github.com/moos3/smuggler/api/internal"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

// Secret key to uniquely sign the token
var key []byte

// AWSCreds Aws Response from the metadata uri
type (
	AWSCreds struct {
		RoleArn         string `json:"RoleArn"`
		AccessKeyID     string `json:"AccessKeyId"`
		SecretAccessKey string `json:"SecretAccessKey"`
		Token           string `json:"Token"`
		Expiration      string `json:"Expiration"`
	}

	// Payload - is just a holder
	Payload struct {
		Data        string
		FingerPrint string
	}

	// Credential User's login information
	Credential struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	// Token jwt Standard Claim Object
	Token struct {
		Username string `json:"username"`
		jwt.StandardClaims
	}

	// Users for access to web service
	Users struct {
		User []struct {
			Username string   `json:"username"`
			Password string   `json:"password"`
			ACL      []string `json:"acl"`
		} `json:"users"`
	}
)

// Create a dummy local db instance as a key value pair
var userdb = map[string]string{
	"user1": "password123",
}

// Fetch AWS Instance Creds
func fetchAWSCreds() (creds AWSCreds) {
	awsCreds := AWSCreds{}

	awsURI, ok := os.LookupEnv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
	if !ok {
		log.Fatal("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI is not present")
	}
	resp, err := http.Get(fmt.Sprintf("http://169.254.170.2%s", awsURI))
	if err != nil {
		log.Fatal(err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	data := string(body)
	json.Unmarshal([]byte(data), &awsCreds)

	return awsCreds
}

func main() {

	envFile := flag.String("config", "", "Path to configuration file")
	flag.Parse()

	// Load the .env file to access the environment variable
	err := godotenv.Load(*envFile)

	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// read the secret_key from the .env file
	key = []byte(os.Getenv("SECRET_KEY"))

	r := mux.NewRouter()

	r.HandleFunc("/login", login).Methods("POST")
	r.HandleFunc("/m", getAWSCreds).Methods("GET")
	r.HandleFunc("/ping", healthCheck).Methods("GET")

	loggedRouter := handlers.LoggingHandler(os.Stdout, r)
	fmt.Println("Starting server on the port 8000...")
	log.Fatal(http.ListenAndServe(":8000", loggedRouter))
}

func healthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "OK")
}

// login user login function
func login(w http.ResponseWriter, r *http.Request) {
	// create a Credentials object
	var creds Credential
	// decode json to struct
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// verify if user exist or not
	userPassword, ok := userdb[creds.Username]

	// if user exist, verify the password
	if !ok || userPassword != creds.Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Create a token object
	var tokenObj = Token{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			// Enter expiration in milisecond
			ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, tokenObj)

	tokenString, err := token.SignedString(key)

	if err != nil {
		log.Fatal(err)
	}
	json.NewEncoder(w).Encode(tokenString)
}

// return the instances aws credentials
func getAWSCreds(w http.ResponseWriter, r *http.Request) {
	// get the bearer token from the reuest header
	bearerToken := r.Header.Get("Authorization")

	// validate token, it will return Token and error
	token, err := ValidateToken(bearerToken)

	if err != nil {
		// check if Error is Signature Invalid Error
		if err == jwt.ErrSignatureInvalid {
			// return the Unauthorized Status
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode("{\"message\":\"UNAUTHORIZED\"}")
			return
		}
		// Return the Bad Request for any other error
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// Validate the token if it expired or not
	if !token.Valid {
		// return the Unauthoried Status for expired token
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode("{\"message\":\"UNAUTHORIZED\"}")
		return
	}

	// fetch aws creds from the instance to be able to return them to the requester
	data := fetchAWSCreds()
	e, err := json.Marshal(data)
	if err != nil {
		log.Fatal(err)
	}
	b := string(e)
	d := secure.CipherData(b)
	chkSum, err := secure.CheckSum(d, 512)
	if err != nil {
		log.Fatal(err)
	}
	payload := Payload{Data: d, FingerPrint: chkSum}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(payload)
}

// ValidateToken validates the token with the secret key and return the object
func ValidateToken(bearerToken string) (*jwt.Token, error) {

	// format the token string
	tokenString := strings.Split(bearerToken, " ")[1]

	// Parse the token with tokenObj
	token, err := jwt.ParseWithClaims(tokenString, &Token{}, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	})

	// return token and err
	return token, err
}
