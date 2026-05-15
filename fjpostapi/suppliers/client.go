package suppliers

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/DemonAndAngel/go-kit/fjpostapi/suppliers/crypt"
	"github.com/DemonAndAngel/go-kit/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	redis "github.com/go-redis/redis/v8"
	"github.com/spf13/viper"
)

const (
	Supplier_Type_YiDian = "yidian"
	Supplier_Type_WeiNa  = "weina"
)

type SuppliersClient struct {
	cfg        *SupplierConfig
	crypto     *CryptoHelper
	tokenStore *redis.Client
	httpClient *http.Client
}

func NewSupplierClient(supplier string, rdc *redis.Client) (*SuppliersClient, error) {
	switch supplier {
	case Supplier_Type_YiDian, Supplier_Type_WeiNa:
	default:
		return nil, fmt.Errorf("supplier %s is not supported", supplier)
	}

	configPrefix := fmt.Sprintf("appConfig.fjpostapi.supplier.%s", strings.ToLower(supplier))
	cfg := &SupplierConfig{
		Name:             strings.ToLower(supplier),
		SM4Key:           viper.GetString(fmt.Sprintf("%s.sm4_key", configPrefix)),
		Un:               viper.GetString(fmt.Sprintf("%s.un", configPrefix)),
		Pw:               viper.GetString(fmt.Sprintf("%s.pw", configPrefix)),
		BaseURL:          viper.GetString(fmt.Sprintf("%s.base_url", configPrefix)),
		PayAppid:         viper.GetString(fmt.Sprintf("%s.pay_appid", configPrefix)),
		PayAppPath:       viper.GetString(fmt.Sprintf("%s.pay_app_path", configPrefix)),
		PayAppEnvVersion: viper.GetString(fmt.Sprintf("%s.pay_app_env_version", configPrefix)),
	}
	privateKey, err := base64.StdEncoding.DecodeString(viper.GetString(fmt.Sprintf("%s.private_key", configPrefix)))
	if err != nil {
		return nil, err
	}
	cfg.PrivateKey = string(privateKey)

	publicKey, err := base64.StdEncoding.DecodeString(viper.GetString(fmt.Sprintf("%s.public_key", configPrefix)))
	if err != nil {
		return nil, err
	}
	cfg.PublicKey = string(publicKey)

	iv, err := base64.StdEncoding.DecodeString(viper.GetString(fmt.Sprintf("%s.aes_iv", configPrefix)))
	if err != nil {
		return nil, err
	}
	cfg.AesIv = string(iv)

	err = cfg.CheckConfig()
	if err != nil {
		return nil, fmt.Errorf("券商【%s】初始化配置，%s", cfg.Name, err.Error())
	}

	rsaCli, err := crypt.NewRsa(cfg.PrivateKey, cfg.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("券商【%s】初始化RSA，%s", cfg.Name, err.Error())
	}

	client := &SuppliersClient{
		cfg:        cfg,
		tokenStore: rdc,
		crypto: &CryptoHelper{
			rsaCli: rsaCli,
			sm4Cli: crypt.NewSM4(cfg.SM4Key),
			aesIv:  cfg.AesIv,
		},
		httpClient: &http.Client{
			Timeout: time.Second * 15,
			Transport: &http.Transport{
				Proxy: GetHttpProxy(),
			},
		},
	}
	return client, nil
}

func (c *SuppliersClient) getToken(ctx context.Context) (string, error) {
	if c.tokenStore != nil {
		authorization := c.tokenStore.Get(ctx, fmt.Sprintf("supplier:%s:api-token:%s", c.cfg.Name, c.cfg.Un)).Val()
		if strings.ReplaceAll(authorization, " ", "") != "" {
			return authorization, nil
		}
	}

	// 1.1 对pw进行进行摘要运算（明文密码使用SHA512 ，小写）
	sum := sha512.Sum512([]byte(c.cfg.Pw))
	requestData := map[string]string{}
	requestData["un"] = c.cfg.Un
	requestData["pw"] = hex.EncodeToString(sum[:])

	// 序列化输入参数
	uri := c.cfg.BaseURL + "/auth"
	requestDataStr := json.JsonMarshal(requestData)
	fmt.Println("请求地址：", uri)
	fmt.Println("请求参数：", requestDataStr)

	// 创建请求
	request, err := http.NewRequest("POST", uri, bytes.NewBuffer([]byte(requestDataStr)))
	if err != nil {
		return "", err
	}

	// 添加请求头
	request.Header.Add("Content-Type", "application/json;charset=utf-8")
	request.Header.Add("Accept", "application/json")

	response, err := c.httpClient.Do(request)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = response.Body.Close()
	}()

	// 判断响应码
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("错误状态码【%d】", response.StatusCode)
	}

	// 读取响应数据
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}

	type Token struct {
		Token string `json:"token"`
	}
	var resp Response[Token]
	err = json.Unmarshal(body, &resp)
	if err != nil {
		return "", err
	}
	if resp.Code != "OK" {
		return "", errors.New(resp.Remark)
	}
	if c.tokenStore != nil {
		err = c.tokenStore.Set(ctx, fmt.Sprintf("supplier:%s:api-token:%s", c.cfg.Name, c.cfg.Un), resp.Data.Token, time.Hour*12).Err()
		if err != nil {
			fmt.Println("缓存token失败：", resp.Data.Token)
		}
	}

	// 返回响应
	return resp.Data.Token, nil
}

func (c *SuppliersClient) doPost(ctx context.Context, path string, requestBody any) ([]byte, []byte, error) {
	token, err := c.getToken(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("获取授权，%s", err.Error())
	}

	aesBodyEn, rsaAesKeyEn, err := c.crypto.EncryptRequest(requestBody)
	if err != nil {
		return nil, nil, err
	}

	// 序列化输入参数
	uri := c.cfg.BaseURL + path
	fmt.Println("请求地址：", uri)
	fmt.Println("请求参数：", aesBodyEn)
	fmt.Println("临时AES-KEY：", rsaAesKeyEn)
	reqBody := make(map[string]string)
	reqBody["aesBodyEn"] = aesBodyEn
	reqBody["rsaAesKeyEn"] = rsaAesKeyEn
	reqreqBodyByte, err := json.Marshal(reqBody)
	if err != nil {
		return nil, nil, err
	}
	// 创建请求
	request, err := http.NewRequest("POST", uri, bytes.NewBufferString(aesBodyEn))
	if err != nil {
		return nil, reqreqBodyByte, err
	}
	// 添加请求头
	request.Header.Add("Content-Type", "application/json;charset=utf-8")
	request.Header.Add("Accept", "application/json")
	request.Header.Set("X-Auth-Token", token)
	request.Header.Set("AES-Key", rsaAesKeyEn)

	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, reqreqBodyByte, err
	}
	defer func() {
		_ = response.Body.Close()
	}()

	// 判断响应码
	if response.StatusCode != http.StatusOK {
		return nil, reqreqBodyByte, fmt.Errorf("错误状态码【%d】", response.StatusCode)
	}

	// 读取响应数据
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, reqreqBodyByte, err
	}

	fmt.Println("响应数据：", string(body))

	// 返回响应
	return body, reqreqBodyByte, nil
}

func (c *SuppliersClient) CheckPw(pw string) error {
	if pw == "" {
		return errors.New("pw is empty")
	}
	sum := sha512.Sum512([]byte(c.cfg.Pw))
	if pw != hex.EncodeToString(sum[:]) {
		return errors.New("pw is wrong")
	}

	return nil
}

func (c *SuppliersClient) GenToken(str string) string {
	return crypt.Sha256(str)
}

func GetHttpProxy() func(*http.Request) (*url.URL, error) {
	proxyStr := os.Getenv("MY_HTTP_PROXY")
	var proxy func(*http.Request) (*url.URL, error)
	if proxyStr != "" {
		p, err := url.Parse(proxyStr)
		if err == nil {
			proxy = http.ProxyURL(p)
		}
	}
	return proxy
}
