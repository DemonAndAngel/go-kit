package juhe

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Get 网络请求
func Get(apiURL string, params url.Values) (rs []byte, err error) {
	var Url *url.URL
	Url, err = url.Parse(apiURL)
	if err != nil {
		return nil, err
	}
	
	// SSRF 防御: 禁止内网 IP 和 localhost
	host := strings.ToLower(Url.Hostname())
	if host == "localhost" || host == "127.0.0.1" || strings.HasPrefix(host, "192.168.") || strings.HasPrefix(host, "10.") {
		return nil, errors.New("SSRF detected: private network access blocked")
	}

	// 如果参数中有中文参数,这个方法会进行URLEncode
	Url.RawQuery = params.Encode()
	
	// 使用默认 Client 或配置好的 Proxy
	c := &http.Client{}
	resp, err := c.Get(Url.String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// Post 网络请求
func Post(apiURL string, params url.Values) (rs []byte, err error) {
	c := &http.Client{}
	resp, err := c.PostForm(apiURL, params)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
