package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/ecsavigne/clientSSH/client"

	"github.com/spf13/viper"
)

func init() {
	pathDir, _ := os.Getwd()
	viper.AddConfigPath(pathDir)
	viper.SetConfigType("env")
	viper.SetConfigName("xxx_config")
	viper.WatchConfig()
	if err := viper.ReadInConfig(); err != nil {
		panic(err)
	}
}

func main() {
	cl, e := client.NewClientSSH(
		client.WithHost(viper.GetString("XXX_HOST_U2")),
		client.WithPort("22"),
		client.WithUser(viper.GetString("XXX_USER")),
		client.WithPassword(viper.GetString("XXX_PASS")),
		client.WithAlgorithms("ed25519"),
		// client.WithServerPublicKey(viper.GetString("XXX_PUBLIC_KEY_SERVER")),
		// client.WithPathSecretKey(viper.GetString("XXX_PATH_SECRET_KEY")),
	)
	if e != nil {
		fmt.Println(e)
		return
	}
	defer cl.Close()

	session, err := cl.NewSession()
	if err != nil {
		fmt.Printf("error create session: (%v)\n", err)
	}
	defer session.Close()

	// session.Stdin = strings.NewReader(viper.GetString("XXX_PASS") + "\n")
	// output, err := session.CombinedOutput("sudo -S -p '' sh /var/www/html/my_whatsmeow/utils/updatetest.sh")
	output, err := session.CombinedOutput("df -h / | awk 'NR==2 {$NF=\"\"; print}'")
	if err != nil {
		fmt.Printf("ejecutar comando: (%+v); salida: %s", err, output)
	}
	data := strings.Split(string(output), " ")
	size := data[1]
	used := data[2]
	avaliable := data[3]
	use := data[4]

	fmt.Printf("Size: %v; Used: %v; Avaliable: %v; Use: %v", size, used, avaliable, use)
}
