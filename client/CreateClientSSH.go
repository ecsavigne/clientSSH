package client

import (
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

type config struct {
	xxx_PathSecretKey   string
	xxx_ServerPublicKey string
	xxx_Host            string
	xxx_Port            string
	xxx_User            string
	xxx_Algorithms      string
}

type Option func(*config)

func WithPathSecretKey(path string) Option {
	return func(c *config) {
		c.xxx_PathSecretKey = path
	}
}

func WithServerPublicKey(key string) Option {
	return func(c *config) {
		c.xxx_ServerPublicKey = key
	}
}

func WithHost(host string) Option {
	return func(c *config) {
		c.xxx_Host = host
	}
}

func WithPort(port string) Option {
	return func(c *config) {
		c.xxx_Port = port
	}
}

func WithUser(user string) Option {
	return func(c *config) {
		c.xxx_User = user
	}
}

// ED25519, ECDSA256, ECDSA384, ECDSA521, etc. Default is KeyAlgoED25519
func WithAlgorithms(algorithm string) Option {
	return func(c *config) {
		c.xxx_Algorithms = algorithm
	}
}

type clientSSH struct {
	c *ssh.Client
}

func defaultOptions() *config {
	return &config{
		xxx_PathSecretKey:   "",
		xxx_ServerPublicKey: "",
		xxx_Host:            "",
		xxx_Port:            "22",
		xxx_User:            "",
		xxx_Algorithms:      "ED25519",
	}
}

func setAlgoritms(c config, cc *ssh.ClientConfig) {
	switch c.xxx_Algorithms {
	case "ED25519":
		cc.HostKeyAlgorithms = []string{ssh.KeyAlgoED25519}
	case "ECDSA256":
		cc.HostKeyAlgorithms = []string{ssh.KeyAlgoECDSA256}
	case "ECDSA384":
		cc.HostKeyAlgorithms = []string{ssh.KeyAlgoECDSA384}
	case "ECDSA521":
		cc.HostKeyAlgorithms = []string{ssh.KeyAlgoECDSA521}
	default:
		cc.HostKeyAlgorithms = []string{ssh.KeyAlgoED25519}
	}
}

func NewClientSSH(opts ...Option) (*clientSSH, error) {
	c := defaultOptions()

	for _, o := range opts {
		o(c)
	}

	if c.xxx_PathSecretKey == "" {
		return nil, fmt.Errorf("path  secret key is required")
	}

	if c.xxx_ServerPublicKey == "" {
		return nil, fmt.Errorf("path public key is required")
	}

	if c.xxx_Host == "" {
		return nil, fmt.Errorf("host is required")
	}

	if c.xxx_User == "" {
		return nil, fmt.Errorf("user is required")
	}

	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(c.xxx_ServerPublicKey))
	if err != nil {
		return nil, fmt.Errorf("error obtain public key: (%v)", err)
	}
	// fmt.Println("Finder fingerprint:\n", ssh.FingerprintSHA256(publicKey))

	secretKey, err := os.ReadFile(c.xxx_PathSecretKey)
	if err != nil {
		return nil, fmt.Errorf("error obtain secret key: (%v)", err)
	}

	signer, err := ssh.ParsePrivateKey(secretKey)
	if err != nil {
		return nil, fmt.Errorf("error obtain signer: (%v)", err)
	}

	config := &ssh.ClientConfig{
		User:            c.xxx_User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(publicKey),
	}
	setAlgoritms(*c, config)

	address := fmt.Sprintf("%s:%s", c.xxx_Host, c.xxx_Port)
	client, err := ssh.Dial("tcp", address, config)
	if err != nil {
		panic(err)
	}

	return &clientSSH{c: client}, nil
}

func (self *clientSSH) Close() {
	self.c.Close()
}

func (self *clientSSH) NewSession() (*ssh.Session, error) {
	return self.c.NewSession()
}

type ClientSHH interface {
	Close()
	NewSession() (*ssh.Session, error)
}
