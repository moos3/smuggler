package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"errors"
	"flag"
	"net/http"
	"strings"
)

const (
	usage = `usage: %s
Run caller

Options:
`
)

// Environment -- This defines the configuration file
type Environment struct {
	Label    string `json:"label"`
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// AWSCreds -- Response from AWS
type AWSCreds struct {
	RoleArn         string `json:"RoleArn"`
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	Token           string `json:"Token"`
	Expiration      string `json:"Expiration"`
}

// CheckSum -- generates a checksum fingerprint for a given string and sizes using SHA
func CheckSum(data string, size uint) (string, error) {
	switch size {
	case 256:
		h := sha256.New()
		h.Write([]byte(data))
		bs := h.Sum(nil)
		bytes := string(fmt.Sprintf("%x\n", bs))
		return bytes, nil
	case 512:
		h := sha512.New()
		h.Write([]byte(data))
		bs := h.Sum(nil)
		bytes := string(fmt.Sprintf("%x\n", bs))
		return bytes[:], nil
	default:
		return "", errors.New("unsupported sha size")
	}

}

// DecipherMydata --- Decrypts the payload returned by
func DecipherMydata(adata, data string) AWSCreds {
	dStr, _ := hex.DecodeString(os.Getenv("CIPHER_KEY"))

	var creds AWSCreds

	//*******************************
	hasher := sha512.New()
	hasher.Write(dStr)
	out := hex.EncodeToString(hasher.Sum(nil))
	newKey, _ := hex.DecodeString(out[:64])
	nonce, _ := hex.DecodeString(out[64:(64 + 24)])
	//*******************************

	aData, _ := hex.DecodeString(adata)
	block, err := aes.NewCipher(newKey)
	if err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	cipherText, _ := hex.DecodeString(data)
	output, _ := aesgcm.Open(nil, nonce, cipherText, aData)
	json.Unmarshal(output, &creds)
	return creds
}

// getAccessToken -- Fetches the Bearer token from the remote end
func getAccessToken(username string, password string, URL string) (string, error) {
	fmt.Println("Logging into Funny Farm")
	method := "POST"
	payload, _ := json.Marshal(map[string]string{"username": username, "password": password})
	req, err := http.NewRequest(method, fmt.Sprintf("%s/login", URL), bytes.NewBuffer(payload))
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	req.Header.Add("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	sb := strings.Trim(strings.TrimSpace(strings.TrimSuffix(string(body), "\n")), "\"")
	return sb, nil
}

// getAwsCredsFromFarm -- calls the farm to fetch the payload
func getAwsCredsFromFarm(token string, url string) (string, error) {
	fmt.Println("Getting remote creds")
	method := "GET"
	endpoint := fmt.Sprintf("%s/m", url)

	req, err := http.NewRequest(method, endpoint, nil)
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	bearer := fmt.Sprintf("Bearer %s", token)
	req.Header.Add("Authorization", bearer)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	defer res.Body.Close()

	defer res.Body.Close()
	body, _ := ioutil.ReadAll(res.Body)

	var payload struct {
		Data        string `json:"Data"`
		Fingerprint string `json:"Fingerprint"`
	}
	json.Unmarshal(body, &payload)
	// Compare Data and Fingerprint for matching
	iSum, _ := CheckSum(payload.Data, 512)

	if iSum == payload.Fingerprint {
		return payload.Data, nil
	} else {
		return "", errors.New("Fingerprint matching failed! UNTRUSTED DATA SENT")
	}
}

func main() {
	configFile := flag.String("config", "", "Path to configuration file")
	envSetting := flag.String("env", "dev", "Set the environment name to match the endpoint in config file default: dev")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), usage, os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	// Load Configuration File
	jsonFile, err := os.Open(*configFile)
	if err != nil {
		fmt.Println(err)
	}

	var cfg map[string]Environment

	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	json.Unmarshal(byteValue, &cfg)
	env := fmt.Sprintf("%s", *envSetting)

	fmt.Println("Smuggling out the credentials")
	token, _ := getAccessToken(cfg[env].Username, cfg[env].Password, cfg[env].URL)
	payload, err := getAwsCredsFromFarm(token, cfg[env].URL)
	if err != nil {
		fmt.Println(err)
	}
	creds := DecipherMydata(os.Getenv("DECRYPT_KEY"), payload)

	fmt.Println("================ CREDS ========================")
	fmt.Println("")

	fmt.Printf("Access Key ID: %s\n", creds.AccessKeyID)
	fmt.Println("")
	fmt.Printf("Secret Access Key ID: %s\n", creds.SecretAccessKey)
	fmt.Println("")
	fmt.Printf("STS TOKEN: %s\n", creds.Token)
	fmt.Println("")

}
