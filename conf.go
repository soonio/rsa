package security

type Config struct {
	PublicKey  string `yaml:"pub"` // 公钥
	PrivateKey string `yaml:"pri"` // 私钥
}
