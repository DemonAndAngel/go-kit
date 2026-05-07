package http

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Request struct {
	Data    string
	Headers []string
}

func DoPost(url string, reqData Request) (resp *http.Response, err error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	req, err := http.NewRequest("POST", url, bytes.NewBufferString(reqData.Data))
	if err != nil {
		return
	}
	for _, header := range reqData.Headers {
		arr := strings.SplitN(header, ":", 2)
		if len(arr) != 2 {
			err = fmt.Errorf("invalid header format: %s", header)
			return
		}
		key := strings.TrimSpace(arr[0])
		value := strings.TrimSpace(arr[1])
		if key == "" {
			err = errors.New("invalid header key")
			return
		}
		if strings.ContainsAny(key, "\r\n") || strings.ContainsAny(value, "\r\n") {
			err = fmt.Errorf("invalid header content: %s", key)
			return
		}
		req.Header.Add(key, value)
	}
	resp, err = client.Do(req)
	return
}
