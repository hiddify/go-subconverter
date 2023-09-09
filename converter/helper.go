package converter

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

func detectType(input string) string {
	switch {
	case strings.HasPrefix(input, "vmess://"):
		return "vmess"
	case strings.HasPrefix(input, "vless://"):
		return "vless"
	case strings.HasPrefix(input, "trojan://"):
		return "trojan"
	case strings.HasPrefix(input, "ss://"):
		return "ss"
	default:
		return ""
	}
}

// Parse the key-value's of the config to a map
func ParseConfig(input, detectedType string) (parsedConfig map[string]interface{}, err error) {
	err = nil
	switch detectedType {
	case "vmess":
		parsedConfig, err = decodeVMess(input)
	case "vless", "trojan":
		parsedConfig, err = parseProxyURL(input, detectedType)
	case "ss":
		parsedConfig, err = parseShadowsocks(input)
	}
	return
}

func decodeVMess(vmessConfig string) (map[string]interface{}, error) {
	vmessData := vmessConfig[8:] // remove "vmess://"
	decodedData, err := base64.StdEncoding.DecodeString(vmessData)
	if err != nil {
		return nil, err
	}
	var result map[string]interface{}
	err = json.Unmarshal(decodedData, &result)
	return result, err
}

func parseProxyURL(proxyURL, proxyType string) (map[string]interface{}, error) {
	parsedURL, err := url.Parse(proxyURL)
	if err != nil {
		return nil, err
	}
	params := parsedURL.Query()
	paramsMap := make(map[string]interface{})
	for k, v := range params {
		if len(v) == 0 {
			continue
		}
		paramsMap[k] = v[0]
	}
	output := map[string]interface{}{
		"protocol": proxyType,
		"username": parsedURL.User.Username(),
		"hostname": parsedURL.Hostname(),
		"port":     parsedURL.Port(),
		"params":   paramsMap,
		"hash":     parsedURL.Fragment,
	}
	if parsedURL.Fragment == "" {
		uuidObj, err := uuid.NewRandom()
		if err != nil {
			return output, err
		}
		output["hash"] = "unnamed-" + uuidObj.String()
	}
	return output, nil
}

func parseShadowsocks(configStr string) (map[string]interface{}, error) {
	parsedURL, err := url.Parse(configStr)
	if err != nil {
		return nil, err
	}
	userString := parsedURL.User.String()
	if dec, err := base64.StdEncoding.DecodeString(userString); err == nil {
		userString = string(dec)
	}
	userInfo := strings.Split(userString, ":")
	encryptionMethod := userInfo[0]
	password := userInfo[1]
	serverAddress := parsedURL.Hostname()
	serverPort := parsedURL.Port()
	name := parsedURL.Fragment

	server := map[string]interface{}{
		"encryption_method": encryptionMethod,
		"password":          password,
		"server_address":    serverAddress,
		"server_port":       serverPort,
		"name":              name,
	}

	return server, nil
}

func isBase64Encoded(input string) bool {
	decoded, err := base64.StdEncoding.DecodeString(input)
	return err == nil && base64.StdEncoding.EncodeToString(decoded) == input
}

func isNumberWithDots(s string) bool {
	match, _ := regexp.MatchString(`^[\d.]+$`, s)
	return match
}

func isValidAddress(address string) bool {
	if net.ParseIP(address) != nil {
		return true
	} else if !isNumberWithDots(address) {
		if strings.HasPrefix(address, "https://") || strings.HasPrefix(address, "http://") {
			_, err := url.ParseRequestURI(address)
			return err == nil
		}
		if _, err := url.Parse(address); err == nil { // is a vpn link
			return false
		}
		urlWithScheme := "https://" + address
		_, err := url.Parse(urlWithScheme)
		return err == nil
	}
	return false
}
