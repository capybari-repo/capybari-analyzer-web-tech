// Command capybari-web-tech runs this capability on its own.
package main

import (
	webtech "github.com/capybari/capybari-analyzer-web-tech"
	"github.com/capybari/capybari-core/standalone"
)

var version = "dev"

func main() { standalone.Main(version, webtech.New()) }
