package config

import (
	"fmt"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// See: https://medium.com/@bnprashanth256/reading-configuration-files-and-environment-variables-in-go-golang-c2607f912b63

type Configurations struct {
	Server ServerConfigurations
}

type ServerConfigurations struct {
	SoftwareName    string
	UDP             UDPConfigurations
	Signaling       SignalingConfigurations
	DomainName      string
	StunServerAddr  string
	MaskIpOnConsole bool
	RequestAudio    bool
}

type UDPConfigurations struct {
	SinglePort   int
	DockerHostIp string
}

type SignalingConfigurations struct {
	WsPort int
}

var Val Configurations

func Load() {
	// Set the file name of the configurations file
	viper.SetConfigName("config")

	// Set the path to look for the configurations file
	viper.AddConfigPath(".")
	viper.AddConfigPath("../")

	// Enable VIPER to read Environment Variables
	viper.AutomaticEnv()

	viper.SetConfigType("yml")

	if err := viper.ReadInConfig(); err != nil {
		fmt.Printf("Error reading config file, %s", err)
	}

	// Set undefined variables
	viper.SetDefault("database.dbname", "test_db")

	err := viper.Unmarshal(&Val)
	if err != nil {
		fmt.Printf("Unable to decode into struct, %v", err)
	}
}

func ToString() string {
	result, err := yaml.Marshal(Val)
	if err != nil {
		return fmt.Sprintf("Error: %s", err)
	}
	return string(result)
}
