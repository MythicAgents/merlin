/*
Merlin is a post-exploitation command and control framework.

This file is part of Merlin.
Copyright (C) 2023  Russel Van Tuyl

Merlin is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as
published by the Free Software Foundation, either version 3 of the License, or any later version.

Merlin is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with Merlin.  If not, see <http://www.gnu.org/licenses/>.
*/

package main

import (
	// Standard
	"os"
	"path/filepath"

	// Mythic
	"github.com/MythicMeta/MythicContainer"
	structs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"

	// Internal
	"github.com/MythicAgents/merlin/Payload_Type/merlin/container/commands"
	"github.com/MythicAgents/merlin/Payload_Type/merlin/container/payload/build"
)

func main() {
	logging.LogInfo("Starting Merlin container")

	// Create a service for this Merlin container
	payloadService := structs.AllPayloadData.Get("merlin")

	// Build the Merlin Payload container definition and add it
	// If running as standalone, locally, outside Mythic: export MYTHIC_SERVER_HOST=127.0.0.1
	payload, err := build.NewPayload()
	if err != nil {
		logging.LogError(err, "quitting")
		os.Exit(2)
	}
	payloadService.AddPayloadDefinition(payload)

	// Add the Merlin payload build function definition
	payloadService.AddBuildFunction(build.Build)

	// Add the Merlin agent commands
	for _, command := range commands.Commands() {
		payloadService.AddCommand(command)
	}

	// Get the Merlin icon and add it
	payloadService.AddIcon(filepath.Join(".", "..", "merlin.svg"))

	// Start the container
	MythicContainer.StartAndRunForever([]MythicContainer.MythicServices{MythicContainer.MythicServicePayload})
}
