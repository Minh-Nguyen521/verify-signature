package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

type signatureData struct {
	R string `json:"r"`
	S string `json:"s"`
}

type VerifyRequest struct {
	Signature   signatureData `json:"signature"`
	HashMessage string        `json:"hashmessage"`
	PublicKey   string        `json:"publickey"`
}

func verify(c *gin.Context) {
	var data VerifyRequest
	if err := c.ShouldBindJSON(&data); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Decode the public key from Base64
	derBytes, err := base64.StdEncoding.DecodeString(data.PublicKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid public key format"})
		return
	}

	log.Print("Public key: ", derBytes)

	// Parse the public key
	pubKey, err := x509.ParsePKIXPublicKey(derBytes)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to parse public key"})
		return
	}

	// log.Print("Public key: ", pubKey)


	// Assert the type to *ecdsa.PublicKey
	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "public key is not of type ECDSA"})
		return
	}

	// Decode R and S from hex
	rBytes, err := hex.DecodeString(data.Signature.R)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid signature R value"})
		return
	}

	sBytes, err := hex.DecodeString(data.Signature.S)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid signature S value"})
		return
	}

	// Convert R and S to big.Int
	r := new(big.Int).SetBytes(rBytes)
	s := new(big.Int).SetBytes(sBytes)

	// Verify the signature
	valid := ecdsa.Verify(ecdsaPubKey, []byte(data.HashMessage), r, s)

	log.Printf("Signature verification result: %v\n", valid)
	c.JSON(http.StatusOK, gin.H{"valid": valid})
}

func main() {
	r := gin.Default()

	config := cors.Config{
		AllowOrigins:     []string{"http://localhost:5173"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}
	r.Use(cors.New(config))
	
	r.POST("/verify", verify)
	r.Run(":8080") 
}
