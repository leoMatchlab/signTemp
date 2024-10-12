package main

import (
	"fmt"
	"github.com/holiman/uint256"
	"log"
	"signTemp/mycrypto"
)

const (
	privateKeyHex      = "0c1c14c3267ce0e99a29017f79c2daadee765fdc654244b3147f68c00f17d5af" // 用你的私钥替换这里
	rpcURL             = "https://bsc-testnet-rpc.publicnode.com"
	contractAddressHex = "0xcE8d19BA49d3D1A0057dB602E287581cB1cC6b58"
	contractABI        = "[\n\t{\n\t\t\"inputs\": [\n\t\t\t{\n\t\t\t\t\"internalType\": \"address\",\n\t\t\t\t\"name\": \"signer\",\n\t\t\t\t\"type\": \"address\"\n\t\t\t},\n\t\t\t{\n\t\t\t\t\"internalType\": \"address\",\n\t\t\t\t\"name\": \"addr\",\n\t\t\t\t\"type\": \"address\"\n\t\t\t},\n\t\t\t{\n\t\t\t\t\"internalType\": \"uint256\",\n\t\t\t\t\"name\": \"num1\",\n\t\t\t\t\"type\": \"uint256\"\n\t\t\t},\n\t\t\t{\n\t\t\t\t\"internalType\": \"uint256\",\n\t\t\t\t\"name\": \"num2\",\n\t\t\t\t\"type\": \"uint256\"\n\t\t\t},\n\t\t\t{\n\t\t\t\t\"internalType\": \"string\",\n\t\t\t\t\"name\": \"memo\",\n\t\t\t\t\"type\": \"string\"\n\t\t\t},\n\t\t\t{\n\t\t\t\t\"internalType\": \"bytes\",\n\t\t\t\t\"name\": \"signature\",\n\t\t\t\t\"type\": \"bytes\"\n\t\t\t}\n\t\t],\n\t\t\"name\": \"verifyMultidataSignature\",\n\t\t\"outputs\": [\n\t\t\t{\n\t\t\t\t\"internalType\": \"bool\",\n\t\t\t\t\"name\": \"\",\n\t\t\t\t\"type\": \"bool\"\n\t\t\t}\n\t\t],\n\t\t\"stateMutability\": \"pure\",\n\t\t\"type\": \"function\"\n\t},\n\t{\n\t\t\"inputs\": [\n\t\t\t{\n\t\t\t\t\"internalType\": \"address\",\n\t\t\t\t\"name\": \"signer\",\n\t\t\t\t\"type\": \"address\"\n\t\t\t},\n\t\t\t{\n\t\t\t\t\"internalType\": \"string\",\n\t\t\t\t\"name\": \"data\",\n\t\t\t\t\"type\": \"string\"\n\t\t\t},\n\t\t\t{\n\t\t\t\t\"internalType\": \"bytes\",\n\t\t\t\t\"name\": \"signature\",\n\t\t\t\t\"type\": \"bytes\"\n\t\t\t}\n\t\t],\n\t\t\"name\": \"verifySingleSignature\",\n\t\t\"outputs\": [\n\t\t\t{\n\t\t\t\t\"internalType\": \"bool\",\n\t\t\t\t\"name\": \"\",\n\t\t\t\t\"type\": \"bool\"\n\t\t\t}\n\t\t],\n\t\t\"stateMutability\": \"pure\",\n\t\t\"type\": \"function\"\n\t}\n]"
)

func Multidata(addr string, num1 uint256.Int, num2 uint256.Int, memo string) error {
	// 创建SDK实例
	sdk, err := mycrypto.NewSDK(privateKeyHex, rpcURL, contractAddressHex, contractABI)
	if err != nil {
		log.Fatalf("Failed to create SDK: %v", err)
	}
	// 多数据签名
	//inputAddr := ethgo.HexToAddress(addr).Bytes()
	//num1 = uint256.Int{123451234512345}
	//num2 = uint256.Int{678901234512345}
	signatureResult, err := sdk.SignByMultidata(memo, num1, num2, addr)
	if err != nil {
		log.Fatalf("Failed to sign multidata: %v", err)
	}
	fmt.Printf("Signature: %x\n", signatureResult)
	// 验证签名
	valid, err := sdk.VerifyByMultidata(memo, num1, num2, addr, signatureResult)
	if err != nil {
		log.Fatalf("Failed to verify signature: %v", err)
	}
	fmt.Printf("Single data Signature valid: %v\n", valid)
	return nil
}

func Singledata() error {
	// 创建SDK实例
	sdk, err := mycrypto.NewSDK(privateKeyHex, rpcURL, contractAddressHex, contractABI)
	if err != nil {
		log.Fatalf("Failed to create SDK: %v", err)
	}

	// 签名数据
	data := "Hello, world!"
	signature, err := sdk.Sign(data)
	if err != nil {
		log.Fatalf("Failed to sign data: %v", err)
	}
	fmt.Printf("Signature: %x\n", signature)

	// 验证签名
	valid, err := sdk.Verify(data, signature)
	if err != nil {
		log.Fatalf("Failed to verify signature: %v", err)
	}
	fmt.Printf("Single data Signature valid: %v\n", valid)
	return nil
}

/*
demo for SDK
Singledata() is test for verifySingleSignature(address signer, string memory data, bytes memory signature)
Multidata() is test for verifyMultidataSignature(address signer, address addr,uint num1, uint num2, string memory memo, bytes memory signature)
*/
func main() {

	err := Singledata()
	if err != nil {
		fmt.Println(err)
	}

	err1 := Multidata("0x8b4885bd650c9EB5454aaD4AbB2CCdbf42bf62bf",
		uint256.Int{123451234512345},
		uint256.Int{678901234512345},
		"Hello, World!")
	if err1 != nil {
		fmt.Println(err1)
	}
}
