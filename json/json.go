package json

import (
	"encoding/json"
	"io"
)

func JsonMarshal(m interface{}) string {
	byteData, _ := Marshal(m)
	str := string(byteData)
	if str == "null" {
		str = ""
	}
	return str
}

func Marshal(m any) ([]byte, error) {
	return json.Marshal(m)
}

func Unmarshal(b []byte, m any) error {
	return json.Unmarshal(b, m)
}

func NewDecoder(r io.Reader) *json.Decoder {
	return json.NewDecoder(r)
}
