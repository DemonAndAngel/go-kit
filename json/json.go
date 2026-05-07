package json

import (
	"encoding/json"
	"io"
)

func Marshal(m any) ([]byte, error) {
	return json.Marshal(m)
}

func Unmarshal(b []byte, m any) error {
	return json.Unmarshal(b, m)
}

func NewDecoder(r io.Reader) *json.Decoder {
	return json.NewDecoder(r)
}
