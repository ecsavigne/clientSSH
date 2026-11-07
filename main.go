package main

import (
	"fmt"
	"os"

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
		client.WithServerPublicKey(viper.GetString("XXX_PUBLIC_KEY_SERVER")),
		client.WithPathSecretKey(viper.GetString("XXX_PATH_SECRET_KEY")),
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

	output, err := session.CombinedOutput("df -h")
	if err != nil {
		fmt.Printf("ejecutar comando: (%+v); salida: %s", err, output)
	}

	fmt.Printf("%s", output)
}
