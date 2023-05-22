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

// Package commands holds all the Mythic command logic for issuing, receiving, and processing commands to Merlin
package commands

import (
	// Standard
	"encoding/json"
	"fmt"
	"strings"

	// Mythic
	structs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/jobs"
)

type Command interface {
	Command() structs.Command
}

// Job structure
type Job struct {
	Type    int    `json:"type"`
	Payload string `json:"payload"`
}

// Commands returns a list of all the commands the Merlin agent payload supports
func Commands() (commands []structs.Command) {
	// TODO Fix the following commands: executePE, executeShellcode, donut
	// TODO Add the following commands: mimikatz, sharpgen, srdi
	commands = append(
		commands, cd(), createProcess(), download(), env(), executeAssembly(), executeShellcode(),
		exit(), ifconfig(), invokeAssembly(), ja3(), killdate(), killProcess(), loadAssembly(), listAssembly(), ls(),
		makeToken(), maxRetry(), memfd(), memory(), netstat(), nslookup(), parrot(), pipes(), ps(), pwd(), rev2Self(),
		rm(), run(), runas(), sdelete(), shell(), skew(), socks(), ssh(), stealToken(), timeStomp(), token(), upload(),
		uptime(),
	)
	return
}

// taskFunctionParseArgDictionary is a generic function used to parse the input map into the provided Mythic task message
func taskFunctionParseArgDictionary(args *structs.PTTaskMessageArgsData, input map[string]interface{}) error {
	// Nothing ot parse
	if len(input) == 0 {
		return nil
	}
	return args.LoadArgsFromDictionary(input)
}

// taskFunctionParseArgString is a generic function used to parse the input string into the provided Mythic task message
func taskFunctionParseArgString(args *structs.PTTaskMessageArgsData, input string) error {
	// Nothing to parse
	if input == "" {
		return nil
	}
	return args.LoadArgsFromJSONString(input)
}

// GetFile processes a Mythic task to retrieve a file and return its contents, filename, and any errors.
// The Mythic task must have a "filename" and "file" command arguments.
// The "filename" command argument references a file that has already been uploaded to Mythic.
// The "file" command argument reference is used when a new file was uploaded as part of the Mythic task.
func GetFile(task *structs.PTTaskMessageAllData) (data []byte, filename string, err error) {
	pkg := "merlin/Payload_Type/merlin/mythic/container/commands/commands.go/GetFile():"
	// Determine if a "filename" or "file" Mythic command argument was provided
	switch strings.ToLower(task.Task.ParameterGroupName) {
	case "default":
		filename, err = task.Args.GetStringArg("filename")
		if err != nil {
			err = fmt.Errorf("%s there was an error getting the \"filename\" command argument for task %d: %s", pkg, task.Task.ID, err)
			return
		}
		data, err = GetFileByName(filename, task.Callback.ID)
		if err != nil {
			err = fmt.Errorf("%s there was an error getting the file by its name \"%s\" for task %d: %s", pkg, filename, task.Task.ID, err)
			return
		}
	case "new file":
		var fileID string
		fileID, err = task.Args.GetStringArg("file")
		if err != nil {
			err = fmt.Errorf("%s there was an error getting the \"file\" command argument for task %d: %s", pkg, task.Task.ID, err)
			return
		}
		data, err = GetFileContents(fileID)
		if err != nil {
			err = fmt.Errorf("%s there was an error getting the file by its id \"%s\" for task %d: %s", pkg, fileID, task.Task.ID, err)
			return
		}
		filename, err = GetFileName(fileID)
		if err != nil {
			err = fmt.Errorf("%s there was an error getting the file name by its id \"%s\" for task %d: %s", pkg, fileID, task.Task.ID, err)
			return
		}
	default:
		err = fmt.Errorf("%s unknown parameter group: %s", pkg, task.Task.ParameterGroupName)
		return
	}
	return
}

// GetFileList queries the Mythic server for files it knows about and returns a list of those Mythic file objects
// This function is used as a DynamicQuery to populate Mythic Command Parameter dropdown lists
func GetFileList(msg structs.PTRPCDynamicQueryFunctionMessage) (files []string) {
	search := mythicrpc.MythicRPCFileSearchMessage{
		TaskID:              0,
		CallbackID:          msg.Callback,
		Filename:            "",
		LimitByCallback:     false,
		MaxResults:          -1,
		Comment:             "",
		AgentFileID:         "",
		IsPayload:           false,
		IsDownloadFromAgent: false,
		IsScreenshot:        false,
	}
	resp, err := mythicrpc.SendMythicRPCFileSearch(search)
	if err != nil {
		fmt.Printf("Payload_Type/merlin/mythic/container/commands/GetFileList(): there was an error calling the SendMythicRPCFileSearch function: %s", err)
		return
	}

	if resp.Error != "" {
		fmt.Printf("Payload_Type/merlin/mythic/container/commands/GetFileList(): the SendMythicRPCFileSearch function returned a response message that contained an error: %s", resp.Error)
		return
	}

	for _, file := range resp.Files {
		files = append(files, file.Filename)
	}
	return
}

// GetFileByName queries the Mythic server for files that match the passed in name argument and returns the contents of the first match
func GetFileByName(name string, callback int) (contents []byte, err error) {
	search := mythicrpc.MythicRPCFileSearchMessage{
		TaskID:              0,
		CallbackID:          callback,
		Filename:            name,
		LimitByCallback:     false,
		MaxResults:          -1,
		Comment:             "",
		AgentFileID:         "",
		IsPayload:           false,
		IsDownloadFromAgent: false,
		IsScreenshot:        false,
	}
	resp, err := mythicrpc.SendMythicRPCFileSearch(search)
	if err != nil {
		err = fmt.Errorf("Payload_Type/merlin/mythic/container/commands/GetFileByName(): there was an error calling the SendMythicRPCFileSearch function: %s", err)
		return
	}

	if len(resp.Files) <= 0 {
		err = fmt.Errorf("Payload_Type/merlin/mythic/container/commands/GetFileByName(): %d files were returned", len(resp.Files))
		return
	}

	for _, file := range resp.Files {
		if file.Filename == name {
			contents, err = GetFileContents(file.AgentFileId)
		}
	}
	return
}

// GetFileContents retrieves the file content as bytes for the provided fileID string
func GetFileContents(fileID string) (contents []byte, err error) {
	msg := mythicrpc.MythicRPCFileGetContentMessage{
		AgentFileID: fileID,
	}
	resp, err := mythicrpc.SendMythicRPCFileGetContent(msg)
	if err != nil {
		err = fmt.Errorf("Payload_Type/merlin/mythic/container/commands/GetFileContents(): the SendMythicRPCFileGetContent function returned an error: %s", resp.Error)
		return
	}
	contents = resp.Content
	return
}

// GetFileName retrieves the file name for the provided fileID string
func GetFileName(fileID string) (name string, err error) {
	search := mythicrpc.MythicRPCFileSearchMessage{
		TaskID:              0,
		CallbackID:          0,
		Filename:            "",
		LimitByCallback:     false,
		MaxResults:          -1,
		Comment:             "",
		AgentFileID:         fileID,
		IsPayload:           false,
		IsDownloadFromAgent: false,
		IsScreenshot:        false,
	}
	resp, err := mythicrpc.SendMythicRPCFileSearch(search)
	if err != nil {
		err = fmt.Errorf("Payload_Type/merlin/mythic/container/commands/GetFileName(): there was an error calling the SendMythicRPCFileSearch function: %s", err)
		return
	}

	if len(resp.Files) <= 0 {
		err = fmt.Errorf("Payload_Type/merlin/mythic/container/commands/GetFileName(): %d files were returned", len(resp.Files))
		return
	}

	for _, file := range resp.Files {
		if file.AgentFileId == fileID {
			name = file.Filename
			return
		}
	}
	return
}

// ConvertMerlinJobToMythicTask takes in a Merlin jobs.Job structure and converts it to a Mythic Job structure
func ConvertMerlinJobToMythicTask(job jobs.Command, jobType int) (bytes string, err error) {
	jobBytes, err := json.Marshal(job)
	if err != nil {
		err = fmt.Errorf("mythic/container/commands/ConvertMerlinJobToMythicTask: there was an error JSON marshalling the Merlin jobs.Job structure: %s", err)
		return
	}

	mythicJob := Job{
		Type:    jobType,
		Payload: string(jobBytes),
	}
	mythicJobBytes, err := json.Marshal(mythicJob)
	if err != nil {
		err = fmt.Errorf("mythic/container/commands/ConvertMerlinJobToMythicTask: there was an error JSON marshalling the Job structure: %s", err)
		return
	}
	return string(mythicJobBytes), nil
}
