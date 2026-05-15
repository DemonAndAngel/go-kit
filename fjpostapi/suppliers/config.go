package suppliers

import "errors"

type SupplierConfig struct {
	Name    string // 券商标识
	BaseURL string // 请求地址

	AesIv      string // aes向量
	PrivateKey string // ras私钥
	PublicKey  string // ras公钥
	SM4Key     string // sm4密钥
	Un         string // 授权账号
	Pw         string // 授权账号密码

	PayAppid         string `json:"pay_appid"`
	PayAppPath       string `json:"pay_app_path"`
	PayAppEnvVersion string `json:"pay_app_env_version"`
}

// 配置检测
func (c *SupplierConfig) CheckConfig() error {
	if c.BaseURL == "" {
		return errors.New("未设置 BaseURL")
	} else if c.AesIv == "" {
		return errors.New("未设置 AesIv")
	} else if c.PrivateKey == "" {
		return errors.New("未设置 PrivateKey")
	} else if c.PublicKey == "" {
		return errors.New("未设置 PublicKey")
	} else if c.Un == "" {
		return errors.New("未设置 Un")
	} else if c.Pw == "" {
		return errors.New("未设置 Pw")
	}

	return nil
}
