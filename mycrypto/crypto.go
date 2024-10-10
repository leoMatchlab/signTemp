package mycrypto

import (
	"encoding/hex"
	"fmt"
	"github.com/umbracle/ethgo"
	"github.com/umbracle/ethgo/abi"
	"github.com/umbracle/ethgo/jsonrpc"
	"github.com/umbracle/ethgo/wallet"
	"log"
	"strconv"
)

// SDK 结构体
type SDK struct {
	addrKey       *wallet.Key
	client        *jsonrpc.Client
	formatSignAbi *abi.ABI
	contractAddr  string
}

// NewSDK 创建一个新的SDK实例
func NewSDK(privateKeyHex, rpcURL, contractAddressHex, contractABI string) (*SDK, error) {
	// 解析私钥
	privateKey, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}
	addrKey, err := wallet.NewWalletFromPrivKey(privateKey)
	// 创建以太坊客户端
	client, err := jsonrpc.NewClient(rpcURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to the Ethereum client: %v", err)
	}

	// 创建合约实例
	formatSignAbi := abi.MustNewABI(contractABI)

	return &SDK{
		addrKey:       addrKey,
		client:        client,
		formatSignAbi: formatSignAbi,
		contractAddr:  contractAddressHex,
	}, nil
}

// Sign 根据输入内容获取签名结果
func (sdk *SDK) Sign(data string) ([]byte, error) {
	hash := ethgo.Keccak256([]byte(data))
	signature, err := sdk.addrKey.Sign(hash)
	if err != nil {
		fmt.Errorf("failed to sign data: %v", err)
	}
	return signature, nil
}

// Verify 调用链上合约验证签名
func (sdk *SDK) Verify(data string, signature []byte) (bool, error) {
	methodVetify := sdk.formatSignAbi.Methods["verifySignature"]
	conAddr := ethgo.HexToAddress(sdk.contractAddr)
	callData, err := methodVetify.Encode([]interface{}{sdk.addrKey.Address(), data, signature})
	if err != nil {
		log.Fatalf("Failed to encode call data: %v", err)
	}
	// 调用智能合约的verify函数
	result, err := sdk.client.Eth().Call(&ethgo.CallMsg{
		To:   &conAddr,
		Data: callData,
	}, ethgo.Latest)
	if err != nil {
		log.Fatalf("Failed to call contract: %v", err)
	}

	intValue, err := strconv.ParseInt(result, 0, 64)
	if err != nil {
		log.Fatalf("Failed to parse int: %v", err)
	}
	boolValue := intValue != 0
	return boolValue, nil
}
