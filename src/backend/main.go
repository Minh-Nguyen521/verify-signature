package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"log"
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

	// Decode the public key from hex
	pubKeyBytes, err := hex.DecodeString(data.PublicKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid public key"})
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

	log.Println("Bytes: ", data.Signature.R);
	log.Println("Bytes: ", data.Signature.S);

	log.Println("rBytes: ", new(big.Int).SetBytes(rBytes));
	log.Println("sBytes: ", new(big.Int).SetBytes(sBytes));

	publicKey, err := crypto.UnmarshalPubkey(pubKeyBytes)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid public key format"})
		return
	}

	valid := ecdsa.Verify(publicKey, []byte(data.HashMessage), new(big.Int).SetBytes(rBytes), new(big.Int).SetBytes(sBytes));
	
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
