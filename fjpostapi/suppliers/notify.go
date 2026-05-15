package suppliers

import (
	"errors"
	"github.com/DemonAndAngel/go-kit/json"
	"github.com/Shopify/sarama"
)

const (
	Topic              = "vmall"
	KeyTicketNotify    = Topic + "-" + "fjpostapi-ticket-notify"
	KeyTradeBillNotify = Topic + "-" + "fjpostapi-trade_bill-notify"
	KeyPayNotify       = Topic + "-" + "fjpostapi-pay-notify"
)

const (
	Ticket_Status_Used     = "UD"
	Ticket_Status_Not_Used = "P"
	Ticket_Status_Expired  = "E"
)

type TicketNotify struct {
	SerialNo     string `json:"serialNo"`     // 请求单据号
	CouponId     string `json:"couponId"`     // 代金券记录第
	Time         string `json:"time"`         // 发生时间 yyyy-MM-dd HH:mm:ss
	CouponStatus string `json:"couponStatus"` // 券状态 UD-已使用 E-已过期 P-待使用

	Source         string `json:"source"`
	SourceActId    string `json:"sourceActId"`
	SourceActLogId string `json:"sourceActLogId"`
}

func (t *TicketNotify) Notify(producer sarama.AsyncProducer) error {
	if err := t.validator(); err != nil {
		return err
	}

	msg := &sarama.ProducerMessage{
		Topic: Topic,
		Key:   sarama.ByteEncoder(KeyTicketNotify),
		Value: sarama.ByteEncoder(json.JsonMarshal(t)),
	}
	producer.Input() <- msg

	return nil
}

func (t *TicketNotify) validator() error {
	if t.SerialNo == "" {
		return errors.New("serialNo is required")
	}
	if t.CouponId == "" {
		return errors.New("couponId is required")
	}
	if t.CouponStatus == "" {
		return errors.New("couponStatus is required")
	}
	if t.Source == "" {
		return errors.New("source is required")
	}
	if t.SourceActId == "" {
		return errors.New("sourceActId is required")
	}

	return nil
}

const (
	TradeBill_Status_Refund  = "Refund"
	TradeBill_Status_Payment = "Payment"
)

type TradeBillNotify struct {
	SerialNo  string `json:"serialNo"`  // 请求单据号
	TradeType string `json:"TradeType"` // 交易类型 退款：Refund 核销使用：Payment
	Time      string `json:"time"`      // 发生时间 yyyy-MM-dd HH:mm:ss
	Amount    int64  `json:"amount"`    // 金额，单位：分

	Source         string `json:"source"`
	SourceActId    string `json:"sourceActId"`
	SourceActLogId string `json:"sourceActLogId"`
}

func (t *TradeBillNotify) Notify(producer sarama.AsyncProducer) error {
	if err := t.validator(); err != nil {
		return err
	}

	msg := &sarama.ProducerMessage{
		Topic: Topic,
		Key:   sarama.ByteEncoder(KeyTradeBillNotify),
		Value: sarama.ByteEncoder(json.JsonMarshal(t)),
	}
	producer.Input() <- msg

	return nil
}

func (t *TradeBillNotify) validator() error {
	if t.SerialNo == "" {
		return errors.New("serialNo is required")
	}
	if t.TradeType == "" {
		return errors.New("tradeType is required")
	}
	if t.Amount == 0 {
		return errors.New("amount is required")
	}
	if t.Source == "" {
		return errors.New("source is required")
	}
	if t.SourceActId == "" {
		return errors.New("sourceActId is required")
	}

	return nil
}

const (
	Pay_Status_Refund  = "REFUND"
	Pay_Status_Success = "SUCCESS"
)

type PayNotify struct {
	SerialNo   string `json:"serialNo"`   // 请求单据号
	TradeState string `json:"tradeState"` // 交易类型 退款：REFUND 支付成功：SUCCESS
	Time       string `json:"time"`       // 发生时间 yyyy-MM-dd HH:mm:ss
	Amount     int64  `json:"amount"`     // 金额，单位：分
	OutTradeNo string `json:"outTradeNo"` // 支付商户订单号

	Source         string `json:"source"`
	SourceActId    string `json:"sourceActId"`
	SourceActLogId string `json:"sourceActLogId"`
}

func (t *PayNotify) Notify(producer sarama.AsyncProducer) error {
	if err := t.validator(); err != nil {
		return err
	}

	msg := &sarama.ProducerMessage{
		Topic: Topic,
		Key:   sarama.ByteEncoder(KeyPayNotify),
		Value: sarama.ByteEncoder(json.JsonMarshal(t)),
	}
	producer.Input() <- msg

	return nil
}

func (t *PayNotify) validator() error {
	if t.SerialNo == "" {
		return errors.New("serialNo is required")
	}
	if t.TradeState == "" {
		return errors.New("tradeState is required")
	}
	if t.Amount == 0 {
		return errors.New("amount is required")
	}
	if t.OutTradeNo == "" {
		return errors.New("outTradeNo is required")
	}
	if t.Source == "" {
		return errors.New("source is required")
	}
	if t.SourceActId == "" {
		return errors.New("sourceActId is required")
	}

	return nil
}
