// Copyright 2019 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package tcp

import (
	"bytes"
	"encoding/json"
)

type jsonError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type jsonrpcMessage struct {
	Version string          `json:"jsonrpc,omitempty"`
	ID      int             `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Error   *jsonError      `json:"error,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
}

// isBatch returns true when the first non-whitespace characters is '['
func isBatch(raw json.RawMessage) bool {
	for _, c := range raw {
		// skip insignificant whitespace (http://www.ietf.org/rfc/rfc4627.txt)
		if c == 0x20 || c == 0x09 || c == 0x0a || c == 0x0d {
			continue
		}
		return c == '['
	}
	return false
}

func parseMessage(raw json.RawMessage) ([]*jsonrpcMessage, bool) {
	if !isBatch(raw) {
		msgs := []*jsonrpcMessage{{}}
		json.Unmarshal(raw, &msgs[0])
		return msgs, false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.Token() // skip '['
	var msgs []*jsonrpcMessage
	for dec.More() {
		msgs = append(msgs, new(jsonrpcMessage))
		dec.Decode(&msgs[len(msgs)-1])
	}
	return msgs, true
}

func blockNumber(message *jsonrpcMessage) (*jsonrpcMessage, error) {
	res, err := json.Marshal("0x4b7")
	return &jsonrpcMessage{
		ID:      message.ID,
		Version: message.Version,
		Result:  res,
	}, err
}

func accounts(message *jsonrpcMessage) (*jsonrpcMessage, error) {
	res, err := json.Marshal([]string{"0x407d73d8a49eeb85d32cf465507dd71d507100c1"})
	return &jsonrpcMessage{
		ID:      message.ID,
		Version: message.Version,
		Result:  res,
	}, err
}

func getBlockByNumber(message *jsonrpcMessage) (*jsonrpcMessage, error) {
	result := struct {
		Difficulty       string        `json:"difficulty"`
		ExtraData        string        `json:"extraData"`
		GasLimit         string        `json:"gasLimit"`
		GasUsed          string        `json:"gasUsed"`
		Hash             string        `json:"hash"`
		LogsBloom        string        `json:"logsBloom"`
		Miner            string        `json:"miner"`
		MixHash          string        `json:"mixHash"`
		Nonce            string        `json:"nonce"`
		Number           string        `json:"number"`
		ParentHash       string        `json:"parentHash"`
		ReceiptsRoot     string        `json:"receiptsRoot"`
		Sha3Uncles       string        `json:"sha3Uncles"`
		Size             string        `json:"size"`
		StateRoot        string        `json:"stateRoot"`
		Timestamp        string        `json:"timestamp"`
		TotalDifficulty  string        `json:"totalDifficulty"`
		Transactions     []interface{} `json:"transactions"`
		TransactionsRoot string        `json:"transactionsRoot"`
		Uncles           []interface{} `json:"uncles"`
	}{
		Difficulty:       "0x4ea3f27bc",
		ExtraData:        "0x476574682f4c5649562f76312e302e302f6c696e75782f676f312e342e32",
		GasLimit:         "0x1388",
		GasUsed:          "0x0",
		Hash:             "0xdc0818cf78f21a8e70579cb46a43643f78291264dda342ae31049421c82d21ae",
		LogsBloom:        "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		Miner:            "0xbb7b8287f3f0a933474a79eae42cbca977791171",
		MixHash:          "0x4fffe9ae21f1c9e15207b1f472d5bbdd68c9595d461666602f2be20daf5e7843",
		Nonce:            "0x689056015818adbe",
		Number:           "0x1b4",
		ParentHash:       "0xe99e022112df268087ea7eafaf4790497fd21dbeeb6bd7a1721df161a6657a54",
		ReceiptsRoot:     "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
		Sha3Uncles:       "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
		Size:             "0x220",
		StateRoot:        "0xddc8b0234c2e0cad087c8b389aa7ef01f7d79b2570bccb77ce48648aa61c904d",
		Timestamp:        "0x55ba467c",
		TotalDifficulty:  "0x78ed983323d",
		Transactions:     []interface{}{},
		TransactionsRoot: "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
		Uncles:           []interface{}{},
	}
	res, err := json.Marshal(result)
	return &jsonrpcMessage{
		ID:      message.ID,
		Version: message.Version,
		Result:  res,
	}, err
}

func handleEthereumRPC(body []byte) ([]byte, error) {
	var rawmsg json.RawMessage
	err := json.NewDecoder(bytes.NewReader(body)).Decode(&rawmsg)
	if err != nil {
		return nil, err
	}
	messages, _ := parseMessage(rawmsg)
	for i, msg := range messages {
		if msg == nil {
			messages[i] = new(jsonrpcMessage)
		}
	}

	responses := []*jsonrpcMessage{}
	var response *jsonrpcMessage
	for _, message := range messages {
		switch message.Method {
		case "eth_blockNumber":
			response, err = blockNumber(message)
		case "eth_getBlockByNumber":
			response, err = getBlockByNumber(message)
		case "eth_accounts":
			response, err = accounts(message)
		default:
			continue
		}
		if err != nil {
			return nil, err
		}
		responses = append(responses, response)
	}
	return json.Marshal(responses)
}
