package suppliers

import (
	"context"
	"github.com/DemonAndAngel/go-kit/json"
)

type (
	Response[T any] struct {
		Code   string `json:"code"`
		Remark string `json:"remark"`
		Data   T      `json:"data"`
	}

	// 派发接口
	TicketDistribute struct {
		OutBatchId string `json:"outBatchId"`
		SenderNo   string `json:"serialNo"`
		Account    string `json:"account"`
	}

	TicketDistributeRes struct {
		SerialNo     string `json:"serialNo"`     // 请求单据号
		CouponId     string `json:"couponId"`     // 代金券记录第
		StartUseTime string `json:"startUseTime"` // 使用开始时间 yyyy-MM-dd HH:mm:ss
		EndUseTime   string `json:"endUseTime"`   // 使用结束时间 yyyy-MM-dd HH:mm:ss
	}

	// 支付查账号查询接口
	Account struct {
		AccountNo string `json:"accountNo"` // 支付宝账号
		Openid    string `json:"openid"`    // openid
	}
	AlipayAccountQuery struct {
		Phone string `json:"phone"`
	}

	AlipayAccountQueryRes struct {
		AlipayOpenIds []Account `json:"alipayOpenIds"`
	}

	// 券记录领取情况查询接口
	TicketQuery struct {
		SenderNo string `json:"serialNo"` // 请求单据号、保持唯一
	}

	TicketQueryRes struct {
		SerialNo     string `json:"serialNo"`     // 请求单据号
		CouponId     string `json:"couponId"`     // 代金券记录第
		StartUseTime string `json:"startUseTime"` // 使用开始时间 yyyy-MM-dd HH:mm:ss
		EndUseTime   string `json:"endUseTime"`   // 使用结束时间 yyyy-MM-dd HH:mm:ss
	}

	// 支付跳转
	PayPreOrderReq struct {
		SerialNo string `json:"serialNo"` // 请求单据号
		Mobile   string `json:"mobile"`
		Count    string `json:"count"`
	}
	PayPreOrderRes struct {
		Appid      string `json:"appid"`
		Path       string `json:"app_path"`
		EnvVersion string `json:"app_env_version"`
		SerialNoEn string `json:"serialNoEn"` // 请求单据号(加密)
		MobileEn   string `json:"mobileEn"`   // 手机号(加密)
		CountEn    string `json:"countEn"`    // 数量(加密)
	}

	// 派发状态回调通知
	TicketCallBack struct {
		SerialNo     string `json:"serialNo"`     // 请求单据号
		CouponId     string `json:"couponId"`     // 代金券记录第
		Time         string `json:"time"`         // 发生时间 yyyy-MM-dd HH:mm:ss
		CouponStatus string `json:"couponStatus"` // 券状态 UD-已使用 E-已过期 P-待使用
	}

	// 代金券核销/退款账单明细回调通知
	TradeBillCallBack struct {
		SerialNo  string `json:"serialNo"`  // 请求单据号
		TradeType string `json:"tradeType"` // 交易类型 退款：Refund 核销使用：Payment
		Time      string `json:"time"`      // 发生时间 yyyy-MM-dd HH:mm:ss
		Amount    int64  `json:"amount"`    // 金额，单位：分
	}

	// 订单支付结果回调通知
	PayCallBack struct {
		SerialNo   string `json:"serialNo"`   // 请求单据号
		TradeState string `json:"tradeState"` // 交易类型 退款：REFUND 支付成功：SUCCESS
		Time       string `json:"time"`       // 发生时间 yyyy-MM-dd HH:mm:ss
		Amount     int64  `json:"amount"`     // 金额，单位：分
		OutTradeNo string `json:"outTradeNo"` // 支付商户订单号
	}
)

// 派发接口：
// Path：/ticket/distribute
// 字段名称	 		说明						类型		备注								是否必填
// outBatchId	 	外部商品编号				String									是
// serialNo	 		请求单据号、保持唯一		String									是
// account	 		账户 					String									是
//
//	1、发放微信代金券，传入对应用户openid
//	2、发放支付宝代金券时，传入对应支付宝 openid
func (c *SuppliersClient) TicketDistribute(ctx context.Context, req TicketDistribute) (*Response[TicketDistributeRes], string, error) {
	respBody, reqBody, err := c.doPost(ctx, "/ticket/distribute", req)
	if err != nil {
		return nil, string(reqBody), err
	}
	var response Response[TicketDistributeRes]
	err = json.Unmarshal(respBody, &response)
	if err != nil {
		return nil, string(reqBody), err
	}
	return &response, string(reqBody), nil
}

// 支付查账号查询接口
// Path：/alipay/account/query
// 字段名称	 		说明				类型		备注								是否必填
// phone	 		手机号			String									是

func (c *SuppliersClient) AlipayAccountQuery(ctx context.Context, req AlipayAccountQuery) (*Response[AlipayAccountQueryRes], error) {
	body, _, err := c.doPost(ctx, "/alipay/account/query", req)
	if err != nil {
		return nil, err
	}
	var response Response[AlipayAccountQueryRes]
	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, err
	}
	return &response, nil
}

// 券记录领取情况查询接口
// Path：/ticket/query
// 字段名称	 		说明				类型		备注								是否必填
// phone	 		手机号			String									是
func (c *SuppliersClient) TicketQuery(ctx context.Context, req TicketQuery) (*Response[TicketQueryRes], error) {
	body, _, err := c.doPost(ctx, "/ticket/query", req)
	if err != nil {
		return nil, err
	}
	var response Response[TicketQueryRes]
	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, err
	}
	return &response, nil
}

// 券记录领取情况查询接口
// 字段名称	 		说明				类型		备注								是否必填
// phone	 		手机号			String									是
func (c *SuppliersClient) PayPreOrder(req PayPreOrderReq) (*PayPreOrderRes, error) {
	serialNoEn, err := c.crypto.sm4Cli.Encrypt(req.SerialNo)
	if err != nil {
		return nil, err
	}
	mobileEn, err := c.crypto.sm4Cli.Encrypt(req.Mobile)
	if err != nil {
		return nil, err
	}
	countEn, err := c.crypto.sm4Cli.Encrypt(req.Count)
	if err != nil {
		return nil, err
	}

	return &PayPreOrderRes{
		SerialNoEn: serialNoEn,
		MobileEn:   mobileEn,
		CountEn:    countEn,
		Appid:      c.cfg.PayAppid,
		Path:       c.cfg.PayAppPath,
		EnvVersion: c.cfg.PayAppEnvVersion,
	}, nil
}

// 派发结果回调通知
func (c *SuppliersClient) TicketCallBack(contentEn, aesKeyEn string) (*TicketCallBack, error) {
	body, err := c.crypto.DecryptRequest(contentEn, aesKeyEn)
	if err != nil {
		return nil, err
	}
	var response TicketCallBack
	err = json.Unmarshal([]byte(json.JsonMarshal(body)), &response)
	if err != nil {
		return nil, err
	}
	return &response, nil
}

// 代金券核销/退款账单明细回调通知
func (c *SuppliersClient) TradeBillCallBack(contentEn, aesKeyEn string) (*TradeBillCallBack, error) {
	body, err := c.crypto.DecryptRequest(contentEn, aesKeyEn)
	if err != nil {
		return nil, err
	}
	var response TradeBillCallBack
	err = json.Unmarshal([]byte(json.JsonMarshal(body)), &response)
	if err != nil {
		return nil, err
	}
	return &response, nil
}

// // 订单支付结果回调通知
func (c *SuppliersClient) PayCallBack(contentEn, aesKeyEn string) (*PayCallBack, error) {
	body, err := c.crypto.DecryptRequest(contentEn, aesKeyEn)
	if err != nil {
		return nil, err
	}
	var response PayCallBack
	err = json.Unmarshal([]byte(json.JsonMarshal(body)), &response)
	if err != nil {
		return nil, err
	}
	return &response, nil
}
