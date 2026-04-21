package xml

import (
	"bytes"
	"encoding/xml"
	"errors"
	"strings"
)

func XmlUnmarshalE(b []byte, m interface{}) error {
	payload := bytes.TrimSpace(b)
	if len(payload) == 0 {
		return errors.New("empty xml payload")
	}
	lower := strings.ToLower(string(payload))
	if strings.Contains(lower, "<!doctype") || strings.Contains(lower, "<!entity") {
		return errors.New("unsafe xml payload")
	}
	decoder := xml.NewDecoder(bytes.NewReader(payload))
	decoder.Strict = true
	return decoder.Decode(m)
}

func XmlUnmarshal(b []byte, m interface{}) {
	_ = XmlUnmarshalE(b, m)
}
