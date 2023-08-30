package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	_ "strings"
)

func isBase64Encoded2(input string) bool {
	decoded, err := url.QueryUnescape(input)
	if err != nil {
		return false
	}
	_, decodeErr := base64.StdEncoding.DecodeString(decoded)
	return decodeErr == nil
}

func isValidUUID(uuidString string) bool {
	// Regular expression to match UUID format
	pattern := `^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[1-5][0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$`
	match, _ := regexp.MatchString(pattern, uuidString)
	return match
}

func getPort(decodedConfig map[string]interface{}) int {
	port, _ := decodedConfig["port"].(int)
	if port != 0 {
		return port
	}
	return 443
}

func getSNI(decodedConfig map[string]interface{}) string {
	if sni, ok := decodedConfig["params"].(map[string]interface{})["sni"].(string); ok {
		return sni
	}
	return ""
}

func getTLS(decodedConfig map[string]interface{}) bool {
	if security, ok := decodedConfig["params"].(map[string]interface{})["security"].(string); ok && security == "tls" {
		return true
	}
	return false
}

func getFlow(decodedConfig map[string]interface{}) string {
	if flow, ok := decodedConfig["params"].(map[string]interface{})["flow"].(string); ok {
		return flow
	}
	return ""
}

func getNetwork(decodedConfig map[string]interface{}) string {
	if network, ok := decodedConfig["params"].(map[string]interface{})["type"].(string); ok {
		return network
	}
	return "tcp"
}

func getWSOpts(decodedConfig map[string]interface{}) string {
	network := getNetwork(decodedConfig)
	if network != "ws" {
		return ""
	}
	path := decodedConfig["params"].(map[string]interface{})["path"].(string)
	host := decodedConfig["params"].(map[string]interface{})["host"].(string)
	return fmt.Sprintf(`,"ws-opts":{"path":"%s","headers":{"host":"%s"}}`, path, host)
}

func getGRPCOpts(decodedConfig map[string]interface{}) string {
	network := getNetwork(decodedConfig)
	if network != "grpc" {
		return ""
	}
	serviceName := decodedConfig["params"].(map[string]interface{})["serviceName"].(string)
	mode := decodedConfig["params"].(map[string]interface{})["mode"].(string)
	return fmt.Sprintf(`,"grpc-opts":{"grpc-service-name":"%s","grpc-mode":"%s"}`, serviceName, mode)
}

func getClientFingerprint(decodedConfig map[string]interface{}) string {
	fp, ok := decodedConfig["params"].(map[string]interface{})["fp"].(string)
	if !ok || fp == "" {
		return `,"client-fingerprint":"chrome"`
	}
	if fp == "random" || fp == "ios" || fp == "android" {
		return `,"client-fingerprint":"chrome"`
	}
	return fmt.Sprintf(`,"client-fingerprint":"%s"`, fp)
}

func getRealityOpts(decodedConfig map[string]interface{}) string {
	if security, ok := decodedConfig["params"].(map[string]interface{})["security"].(string); !ok || security != "reality" {
		return ""
	}
	pbk := decodedConfig["params"].(map[string]interface{})["pbk"].(string)
	sid, sidOK := decodedConfig["params"].(map[string]interface{})["sid"].(string)
	sidStr := ""
	if sidOK && sid != "" {
		sidStr = fmt.Sprintf(`,"short-id":"%s"`, sid)
	}
	return fmt.Sprintf(`,"reality-opts":{"public-key":"%s"%s%s}`, pbk, sidStr, getClientFingerprint(decodedConfig))
}

func getUsername(decodedConfig map[string]interface{}) string {
	username := decodedConfig["username"].(string)
	if isValidUUID(username) {
		return username
	}
	return ""
}

func processVlessClash(decodedConfig map[string]interface{}, outputType string) string {
	name := decodedConfig["hash"].(string)
	if name == "" {
		return ""
	}
	server := decodedConfig["hostname"].(string)
	port := getPort(decodedConfig)
	username := getUsername(decodedConfig)
	if username == "" {
		return ""
	}
	sni := getSNI(decodedConfig)
	tls := getTLS(decodedConfig)
	flow := getFlow(decodedConfig)
	network := getNetwork(decodedConfig)
	opts := ""
	switch network {
	case "ws":
		opts = getWSOpts(decodedConfig)
	case "grpc":
		opts = getGRPCOpts(decodedConfig)
	}
	fingerprint := getClientFingerprint(decodedConfig)
	realityOpts := getRealityOpts(decodedConfig)

	switch outputType {
	case "meta":
		vlTemplate := `  - {"name":"%s","type":"vless","server":"%s","port":%d,"udp":false,"uuid":"%s","tls":%t%s%s,"network":"%s"%s%s}`
		return fmt.Sprintf(vlTemplate, name, server, port, username, tls, sni, flow, network, opts, realityOpts, fingerprint)
	case "clash":
		fallthrough
	case "surfboard":
		return ""
	default:
		return ""
	}
}

func main() {
	// Example usage
	config := "vmess://...your_vmess_config..."
	decodedConfig := make(map[string]interface{})
	err := json.Unmarshal([]byte(config), &decodedConfig)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	outputType := "meta"
	result := processVlessClash(decodedConfig, outputType)
	fmt.Println(result)
}
