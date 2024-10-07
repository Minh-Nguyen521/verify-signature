package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
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
	pubBytes, err := base64.StdEncoding.DecodeString(data.PublicKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid public key format"})
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


	// convert the public key to ecdsa.PublicKey
	curve := elliptic.P256()

	x := new(big.Int).SetBytes(pubBytes[1:33])
	y := new(big.Int).SetBytes(pubBytes[33:65])

	publicKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	// Verify the signature
	valid := ecdsa.Verify(publicKey, []byte(data.HashMessage), r, s)

    address := crypto.PubkeyToAddress(*publicKey).Hex()

	c.JSON(http.StatusOK, gin.H{"address": address, "valid": valid})
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