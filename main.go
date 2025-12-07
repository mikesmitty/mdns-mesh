package main

import (
	"fmt"
	"net/url"

	"github.com/mikesmitty/mdns-mesh/mdns"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func main() {
	switch {
	case viper.GetBool("trace"):
		log.SetLevel(log.TraceLevel)
	case viper.GetBool("debug"):
		log.SetLevel(log.DebugLevel)
	case viper.GetBool("verbose"):
		log.SetLevel(log.InfoLevel)
	case viper.GetBool("quiet"):
		log.SetLevel(log.FatalLevel)
	default:
		log.SetLevel(log.WarnLevel)
	}

	uri, err := url.Parse(viper.GetString("server"))
	if err != nil {
		log.Fatalf("Error parsing server URL: %v", err)
	}

	topic := "mdns-mesh"
	if len(uri.Path) > 1 {
		topic = uri.Path[1:len(uri.Path)]
	}

	config := mdns.Config{
		AllowFilter: viper.GetStringSlice("allow-filter"),
		DenyFilter:  viper.GetStringSlice("deny-filter"),
		DenyIP:      viper.GetStringSlice("deny-ip"),
		FilterTTL:   viper.GetInt("filter-ttl"),
		HighPort:    viper.GetBool("high-port"),
		ListenIP:    viper.GetString("listen-ip"),
		Monitor:     viper.GetStringSlice("monitor"),
		PortFilter:  viper.GetStringSlice("port-filter"),
		Server:      uri,
		Topic:       topic,
		UniqueID:    viper.GetString("unique-id"),
	}

	err = mdns.StartServer(config)
	if err != nil {
		log.Fatalf("Error starting listener: %v", err)
	}
	log.Fatal("Exiting main (this should not happen)")
}

func init() {
	pflag.StringP("config", "c", "", "config file (default is $HOME/mdns-mesh.yaml)")
	pflag.StringP("server", "s", "", "MQTT server address")
	pflag.StringSliceP("monitor", "m", nil, "network interface(s) on which to send/receive mDNS traffic")
	pflag.IntP("filter-ttl", "t", 1, "TTL used to mark outgoing packets to prevent broadcast loops")
	pflag.StringP("listen-ip", "l", "", "ip address from which to listen and send broadcasts")
	pflag.String("unique-id", "", "sender id used to filter out each client's own traffic from the queue")
	pflag.Bool("high-port", false, "send broadcasts from separate socket with a high port")
	pflag.StringSlice("port-filter", nil, "regex filters to send traffic to high or low source ports")
	pflag.StringSlice("allow-filter", nil, "regex filters to allow only matching traffic (cannot be used with --deny-filter)")
	pflag.StringSlice("deny-filter", nil, "regex filters to deny only matching traffic (cannot be used with --allow-filter)")
	pflag.IPSlice("deny-ip", nil, "discard all messages from these IPs")

	pflag.BoolP("quiet", "q", false, "enable verbose mode")
	pflag.BoolP("verbose", "v", false, "enable verbose mode")
	pflag.Bool("debug", false, "enable debug mode")
	pflag.Bool("trace", false, "enable trace mode")

	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)

	cfgFile := viper.GetString("config")
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	}

	viper.SetConfigName("mdns-mesh")
	viper.AddConfigPath("$HOME")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}
