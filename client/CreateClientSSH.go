package client

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/crypto/ssh"
)

type config struct {
	xxx_PathSecretKey   string
	xxx_ServerPublicKey string
	xxx_Host            string
	xxx_Port            string
	xxx_User            string
	xxx_Password        string
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

func WithPassword(password string) Option {
	return func(c *config) {
		c.xxx_Password = password
	}
}

// ecdsa, ed25519, ecdsa-sk, ed25519-sk, or rsa
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
		xxx_Password:        "",
		xxx_Algorithms:      "ed25519",
	}
}

func setAlgoritms(c config, cc *ssh.ClientConfig) {
	switch strings.ToLower(c.xxx_Algorithms) {
	case "ed25519":
		cc.HostKeyAlgorithms = []string{ssh.KeyAlgoED25519}
	case "ecdsa":
		cc.HostKeyAlgorithms = []string{ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA256}
	case "ecdsa-sk":
		cc.HostKeyAlgorithms = []string{ssh.KeyAlgoSKECDSA256}
	case "ed25519-sk":
		cc.HostKeyAlgorithms = []string{ssh.KeyAlgoSKED25519}
	case "rsa":
		cc.HostKeyAlgorithms = []string{ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512}
	default:
		cc.HostKeyAlgorithms = []string{ssh.KeyAlgoED25519}
	}
}

// “ecdsa”, “ed25519”, “ecdsa-sk”, ed25519-sk, or “rsa”
func getPublicKeyServer(algorithm string, ip, port string) (string, error) {
	command := []string{
		"ssh-keyscan",
		"-t", strings.ToLower(algorithm),
		"-p", port, ip,
	}
	resp, err := exec.Command(command[0], command[1:]...).CombinedOutput()
	if err != nil {
		if strings.Contains(string(resp), "OpenSSH") {
			return "", fmt.Errorf("the server does not present the public key for the algorithm: (%v)", algorithm)
		}
		return "", fmt.Errorf("error obtain public key: (%v)", err)
	}

	keyPrefix := ""
	switch algorithm {
	case "ed25519", "rsa":
		keyPrefix = fmt.Sprintf("ssh-%s", strings.ToLower(algorithm))
	case "ecdsa":
		keyPrefix = fmt.Sprintf("%s-sha2-nistp256", strings.ToLower(algorithm))
	case "ecdsa-sk": // SSH-2.0-OpenSSH_8.2p1
		keyPrefix = "SSH-2.0-OpenSSH_8.2p1"
		// ed25519-sk
	}

	_, after, _ := strings.Cut(string(resp), keyPrefix)
	key := fmt.Sprintf("%s%s", keyPrefix, after)

	return key, nil
}

func NewClientSSH(opts ...Option) (*clientSSH, error) {
	c := defaultOptions()

	for _, o := range opts {
		o(c)
	}

	if c.xxx_Host == "" {
		return nil, fmt.Errorf("host is required")
	}

	if c.xxx_User == "" {
		return nil, fmt.Errorf("user is required")
	}

	if c.xxx_ServerPublicKey == "" {
		key, e := getPublicKeyServer(c.xxx_Algorithms, c.xxx_Host, c.xxx_Port)
		if key == "" {
			return nil, fmt.Errorf("server public key cannot be obtained, error: (%v)", e)
		}

		c.xxx_ServerPublicKey = key
	}

	var (
		publicKey ssh.PublicKey
		signer    ssh.Signer
		err       error
	)

	publicKey, _, _, _, err = ssh.ParseAuthorizedKey([]byte(c.xxx_ServerPublicKey))
	if err != nil {
		return nil, fmt.Errorf("error obtain public key: (%v)", err)
	}

	config := &ssh.ClientConfig{
		User:            c.xxx_User,
		HostKeyCallback: ssh.FixedHostKey(publicKey),
	}

	if c.xxx_Password != "" {
		config.Auth = []ssh.AuthMethod{ssh.Password(c.xxx_Password)}
	} else {
		if c.xxx_PathSecretKey == "" {
			return nil, fmt.Errorf("server por secret key or password is required")
		}
		// fmt.Println("Finder fingerprint:\n", ssh.FingerprintSHA256(publicKey))

		secretKey, err := os.ReadFile(c.xxx_PathSecretKey)
		if err != nil {
			return nil, fmt.Errorf("error obtain secret key: (%v)", err)
		}

		signer, err = ssh.ParsePrivateKey(secretKey)
		if err != nil {
			return nil, fmt.Errorf("error obtain signer: (%v)", err)
		}

		config.Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	}

	if c.xxx_Algorithms != "" {
		setAlgoritms(*c, config)
	}

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
