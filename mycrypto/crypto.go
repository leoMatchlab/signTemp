package mycrypto

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/holiman/uint256"
	"github.com/umbracle/ethgo"
	"github.com/umbracle/ethgo/abi"
	"github.com/umbracle/ethgo/jsonrpc"
	"github.com/umbracle/ethgo/wallet"
	"log"
	"math/big"
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
	methodVetify := sdk.formatSignAbi.Methods["verifySingleSignature"]
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

// 模拟abi.encodepacked编码结果
func PackedEncode(fields ...interface{}) ([]byte, error) {
	var buffer bytes.Buffer

	for _, field := range fields {
		switch v := field.(type) {
		case uint8:
			buffer.WriteByte(v)
		case uint16:
			buf := make([]byte, 2)
			binary.BigEndian.PutUint16(buf, v)
			buffer.Write(buf)
		case uint32:
			buf := make([]byte, 4)
			binary.BigEndian.PutUint32(buf, v)
			buffer.Write(buf)
		case uint64:
			buf := make([]byte, 8)
			binary.BigEndian.PutUint64(buf, v)
			buffer.Write(buf)
		case int8:
			buffer.WriteByte(byte(v))
		case int16:
			buf := make([]byte, 2)
			binary.BigEndian.PutUint16(buf, uint16(v))
			buffer.Write(buf)
		case int32:
			buf := make([]byte, 4)
			binary.BigEndian.PutUint32(buf, uint32(v))
			buffer.Write(buf)
		case int64:
			buf := make([]byte, 8)
			binary.BigEndian.PutUint64(buf, uint64(v))
			buffer.Write(buf)
		case *big.Int:
			buf := v.Bytes()
			buffer.Write(buf)
		case bool:
			if v {
				buffer.WriteByte(1)
			} else {
				buffer.WriteByte(0)
			}
		case uint256.Int:
			buf := v.Bytes32()
			buffer.Write(buf[:])
		case []byte:
			buffer.Write(v)
		case string:
			buffer.Write([]byte(v))
		default:
			return nil, fmt.Errorf("unsupported type: %T", v)
		}
	}

	return buffer.Bytes(), nil
}

// signByMultidata 对多数据进行签名
func (sdk *SDK) SignByMultidata(data string, num1 uint256.Int, num2 uint256.Int, address string) ([]byte, error) {
	inputAddr := ethgo.HexToAddress(address).Bytes()
	result, err := PackedEncode(inputAddr, num1, num2, data)
	if err != nil {
		log.Fatalf("Failed to EncodePacked: %v", err)
	}
	hash := ethgo.Keccak256(result)
	signature, err := sdk.addrKey.Sign(hash)
	if err != nil {
		fmt.Errorf("failed to sign data: %v", err)
	}
	return signature, nil
}

// verifyByMultidata 调用链上合约验证签名
func (sdk *SDK) VerifyByMultidata(memo string, num1 uint256.Int, num2 uint256.Int, addr string, signature []byte) (bool, error) {
	methodVetify := sdk.formatSignAbi.Methods["verifyMultidataSignature"]
	conAddr := ethgo.HexToAddress(sdk.contractAddr)
	bigNum1 := new(big.Int).SetBytes(num1.Bytes())
	bigNum2 := new(big.Int).SetBytes(num2.Bytes())
	callData, err := methodVetify.Encode([]interface{}{sdk.addrKey.Address(), addr, bigNum1, bigNum2, memo, signature})
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
