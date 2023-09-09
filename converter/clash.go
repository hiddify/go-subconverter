package converter

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

func isValidUUID(uuidString string) bool {
	_, err := uuid.Parse(uuidString)
	return err == nil
}

func getCipher(decodedConfig map[string]interface{}) string {
	cipher, found := decodedConfig["scy"]
	if found {
		return fmt.Sprintf(`,"cipher":"%s"`, cipher)
	}
	return `,"cipher":"auto"`
}

func getUUID(decodedConfig map[string]interface{}) string {
	uuid := strings.ReplaceAll(decodedConfig["id"].(string), " ", "-")
	return uuid
}

func getVMessTLS(decodedConfig map[string]interface{}) string {
	tls := decodedConfig["tls"]
	if tls == "tls" {
		return "true"
	}
	return "false"
}

func getOpts(decodedConfig map[string]interface{}) string {
	network, found := decodedConfig["net"]
	if !found {
		network = "tcp"
	}

	switch network {
	case "ws":
		path := decodedConfig["path"].(string)
		host := decodedConfig["host"].(string)
		path = escapeHTML(path)
		return fmt.Sprintf(`,"ws-opts":{"path":"%s","headers":{"host":"%s"}}`, path, host)
	case "grpc":
		serviceName := decodedConfig["path"].(string)
		mode := decodedConfig["type"].(string)
		return fmt.Sprintf(`,"grpc-opts":{"grpc-service-name":"%s","grpc-mode":"%s"}`, serviceName, mode)
	case "tcp":
		return ""
	default:
		return ""
	}
}

func escapeHTML(s string) string {
	return strings.ReplaceAll(s, `"`, `\"`)
}

func getVMessAEAD(decodedConfig map[string]interface{}) string {
	alterID, err := getNumber(decodedConfig["aid"])
	if err == nil && alterID == 0 {
		return "true"
	}
	return "false"
}

func ProcessVMessClash(decodedConfig map[string]interface{}, outputType string) string {
	name := decodedConfig["ps"].(string)
	if name == "" {
		return ""
	}
	server := decodedConfig["add"].(string)
	port, err := getNumber(decodedConfig["port"]) // Assuming port is a number
	if err != nil {
		return ""
	}
	cipher := getCipher(decodedConfig)
	uuid := getUUID(decodedConfig)
	alterID := int(decodedConfig["aid"].(float64)) // Assuming alterID is a number
	tls := getVMessTLS(decodedConfig)
	network, found := decodedConfig["net"]
	if !found {
		network = "tcp"
	}
	opts := getOpts(decodedConfig)
	vmessAEAD := getVMessAEAD(decodedConfig)

	var vmTemplate string

	switch outputType {
	case "clash", "meta":
		vmTemplate = fmt.Sprintf(`  - {"name":"%s","type":"vmess","server":"%s","port":%d%s,"uuid":"%s","alterId":%d,"tls":%s,"skip-cert-verify":false,"network":"%s"%s,"client-fingerprint":"chrome"}`,
			name, server, port, cipher, uuid, alterID, tls, network, opts)
	case "surfboard":
		if network == "ws" {
			vmTemplate = fmt.Sprintf(`%s = vmess, %s, %d, username = %s, ws = true, tls = %s, vmess-aead = %s, ws-path = %s, ws-headers = Host:%q, skip-cert-verify = false, tfo = false`,
				name, server, port, uuid, tls, vmessAEAD, escapeHTML(decodedConfig["path"].(string)), decodedConfig["host"].(string))
		} else {
			return ""
		}
	}

	return strings.ReplaceAll(vmTemplate, ",,", ",")
}

func ProcessTrojanClash(decodedConfig map[string]interface{}, outputType string) string {
	name := decodedConfig["hash"].(string)
	if name == "" {
		return ""
	}
	server := decodedConfig["hostname"].(string)
	port, err := getNumber(decodedConfig["port"]) // Assuming port is a number
	if err != nil {
		return ""
	}
	username := decodedConfig["username"].(string)
	sni := ""
	params, found := decodedConfig["params"].(map[string]interface{})
	if found {
		if sniValue, sniFound := params["sni"]; sniFound {
			sni = fmt.Sprintf(`,"sni":"%s"`, sniValue)
		}
	}
	skipCert := "false"
	if allowInsecure, found := params["allowInsecure"]; found {
		if insec, ok := allowInsecure.(bool); ok && insec {
			skipCert = "true"
		}
		if num, ok := allowInsecure.(float64); ok && num > 0 {
			skipCert = "true"
		}
	}

	var trTemplate string

	switch outputType {
	case "clash", "meta":
		trTemplate = fmt.Sprintf(`  - {"name":"%s","type":"trojan","server":"%s","port":%d,"udp":false,"password":"%s"%s,"skip-cert-verify":%s,"network":"tcp","client-fingerprint":"chrome"}`,
			name, server, port, username, sni, skipCert)
	case "surfboard":
		trTemplate = fmt.Sprintf(`%s = trojan, %s, %d, password = %s, udp-delay = true, skip-cert-verify = %s, sni = %s, ws = false`,
			name, server, port, username, skipCert, sni)
	}

	return trTemplate
}

func ProcessShadowsocksClash(decodedConfig map[string]interface{}, outputType string) string {
	preName, found := decodedConfig["name"]
	if !found {
		return ""
	}
	name := preName.(string)
	if name == "" {
		return ""
	}
	server := decodedConfig["server_address"].(string)
	port, err := getNumber(decodedConfig["server_port"]) // Assuming port is a number
	if err != nil {
		return ""
	}
	password := decodedConfig["password"].(string)
	cipher := decodedConfig["encryption_method"].(string)

	var ssTemplate string

	switch outputType {
	case "clash", "meta":
		ssTemplate = fmt.Sprintf(`  - {"name":"%s","type":"ss","server":"%s","port":%d,"password":"%s","cipher":"%s"}`,
			name, server, int(port), password, cipher)
	case "surfboard":
		ssTemplate = fmt.Sprintf(`%s = ss, %s, %d, encrypt-method = %s, password = %s`,
			name, server, int(port), cipher, password)
	}

	return ssTemplate
}

func getPort(decodedConfig map[string]interface{}) int {
	portValue, found := decodedConfig["port"]
	if found {
		res, err := getNumber(portValue)
		if err == nil {
			return int(res)
		}
	}
	return 443
}

func getSNI(decodedConfig map[string]interface{}) string {
	if params, found := decodedConfig["params"].(map[string]interface{}); found {
		sniValue, sniFound := params["sni"]
		if sniFound {
			return fmt.Sprintf(`,"servername":"%s"`, sniValue)
		}
	}
	return ""
}

func getTLS(decodedConfig map[string]interface{}) string {
	if params, found := decodedConfig["params"].(map[string]interface{}); found {
		securityValue, securityFound := params["security"]
		if securityFound && securityValue == "tls" {
			return "true"
		}
	}
	return "false"
}

func getFlow(decodedConfig map[string]interface{}) string {
	if params, found := decodedConfig["params"].(map[string]interface{}); found {
		flowValue, flowFound := params["flow"]
		if flowFound {
			return fmt.Sprintf(`,"flow":"%s"`, flowValue)
		}
	}
	return ""
}

func getNetwork(decodedConfig map[string]interface{}) string {
	if params, found := decodedConfig["params"].(map[string]interface{}); found {
		typeValue, typeFound := params["type"]
		if typeFound {
			return typeValue.(string)
		}
	}
	return "tcp"
}

func getWSOpts(decodedConfig map[string]interface{}) string {
	params, paramsFound := decodedConfig["params"].(map[string]interface{})
	if !paramsFound || params["type"].(string) != "ws" {
		return ""
	}

	path := "/"
	if pathValue, pathFound := params["path"]; pathFound {
		path = escapeHTML(pathValue.(string))
	}

	host := ""
	if hostValue, hostFound := params["host"]; hostFound {
		host = fmt.Sprintf(`,"headers":{"host":"%s"}`, hostValue)
	}

	return fmt.Sprintf(`,"ws-opts":{"path":"%s"%s}`, path, host)
}

func getGrpcOpts(decodedConfig map[string]interface{}) string {
	if params, found := decodedConfig["params"].(map[string]interface{}); found {
		if params["type"].(string) != "grpc" {
			return ""
		}
		serviceNameValue, serviceNameFound := params["serviceName"]
		if serviceNameFound {
			return fmt.Sprintf(`,"grpc-opts":{"grpc-service-name":"%s"}`, serviceNameValue)
		}
	}
	return ""
}

func getClientFingerprint(decodedConfig map[string]interface{}) string {
	if !hasKey(decodedConfig["params"], "fp") {
		return `,"client-fingerprint":"chrome"`
	}
	fp := decodedConfig["params"].(map[string]interface{})["fp"].(string)
	if fp == "random" || fp == "ios" || fp == "android" {
		return `,"client-fingerprint":"chrome"`
	}
	return fmt.Sprintf(`,"client-fingerprint":"%s"`, fp)
}

func getRealityOpts(decodedConfig map[string]interface{}) string {
	if params, found := decodedConfig["params"].(map[string]interface{}); found {
		securityValue, securityFound := params["security"]
		if !securityFound || securityValue != "reality" {
			return ""
		}
		pbk := params["pbk"].(string)
		sidValue, sidFound := params["sid"]
		sid := ""
		if sidFound && sidValue != "" {
			sid = fmt.Sprintf(`,"short-id":"%s"`, sidValue)
		}
		fingerprint := getClientFingerprint(decodedConfig)
		return fmt.Sprintf(`,"reality-opts":{"public-key":"%s"%s%s}`, pbk, sid, fingerprint)
	}
	return ""
}

func getUsername(decodedConfig map[string]interface{}) string {
	if !isValidUUID(decodedConfig["username"].(string)) {
		return ""
	}
	return decodedConfig["username"].(string)
}

func ProcessVLESSClash(decodedConfig map[string]interface{}, outputType string) string {
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
	var opts string
	switch network {
	case "ws":
		opts = getWSOpts(decodedConfig)
	case "grpc":
		opts = getGrpcOpts(decodedConfig)
	}
	fingerprint := getClientFingerprint(decodedConfig)
	realityOpts := getRealityOpts(decodedConfig)

	var vlTemplate string

	switch outputType {
	case "meta":
		vlTemplate = fmt.Sprintf(`  - {"name":"%s","type":"vless","server":"%s","port":%d,"udp":false,"uuid":"%s","tls":%s%s%s%s,"network":"%s"%s%s}`,
			name, server, port, username, tls, sni, flow, network, opts, realityOpts, fingerprint)
	case "clash", "surfboard":
		return ""
	}

	return strings.ReplaceAll(vlTemplate, ",,", ",")
}

func hasKey(m interface{}, key string) bool {
	if m == nil {
		return false
	}
	_, found := m.(map[string]interface{})[key]
	return found
}

func processConvert(config map[string]interface{}, configType, outputType string) string {
	switch configType {
	case "vmess":
		return ProcessVMessClash(config, outputType)
	case "vless":
		return ProcessVLESSClash(config, outputType)
	case "trojan":
		return ProcessTrojanClash(config, outputType)
	case "ss":
		return ProcessShadowsocksClash(config, outputType)
	default:
		return ""
	}
}

func GenerateProxies(input, outputType string) (string, error) {
	var proxies, totalErr strings.Builder

	var v2raySubscription []byte
	if isValidAddress(input) {
		resp, err := http.Get(input)
		if err != nil {
			return "", fmt.Errorf("Could not fetch the provided subscription: %v", err)
		}
		inputData, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("Could not read the provided subscription: %v", err)
		}
		data, err := base64.StdEncoding.DecodeString(string(inputData))
		if err == nil {
			v2raySubscription = data
		} else {
			v2raySubscription = inputData
		}
	} else {
		data, err := base64.StdEncoding.DecodeString(input)
		if err == nil {
			v2raySubscription = data
		} else {
			v2raySubscription = []byte(input)
		}
	}

	configsArray := strings.Split(string(v2raySubscription), "\n")
	suitableConfig := suitableOutput(configsArray, outputType)
	for _, config := range suitableConfig {
		configType := detectType(config)
		decodedConfig, err := ParseConfig(config, configType)
		if err != nil {
			if totalErr.Len() == 0 {
				totalErr.WriteString("One or more errors during the conversion of configurations:\n")
			}
			totalErr.WriteString(fmt.Sprintf("%v\n", err))
			continue
		}
		convertedConfig := processConvert(decodedConfig, configType, outputType)
		if convertedConfig != "" {
			proxies.WriteString(convertedConfig + "\n")
		}
	}

	if proxies.Len() == 0 {
		totalErr.WriteString("No configuration converted\n")
	}

	var outputErr error
	if totalErr.Len() > 0 {
		outputErr = fmt.Errorf("%s", totalErr.String())
	}

	return proxies.String(), outputErr
}

func suitableOutput(input []string, outputType string) []string {
	var suitableConfigs []string

	switch outputType {
	case "clash", "surfboard":
		for _, config := range input {
			if detectType(config) == "vless" || config == "trojan://" || config == "ss://Og==@:" {
				continue
			}
			suitableConfigs = append(suitableConfigs, config)
		}
	case "meta":
		for _, config := range input {
			if config == "trojan://" || config == "ss://Og==@:" {
				continue
			}
			suitableConfigs = append(suitableConfigs, config)
		}
	}

	return suitableConfigs
}

func extractNames(configs, outputType string) string {
	var configsName strings.Builder
	configsArray := strings.Split(configs, "\n")

	switch outputType {
	case "meta", "clash":
		for _, configData := range configsArray {
			if strings.TrimSpace(configData) == "" {
				continue
			}
			pattern := `"name":"(.*?)"`
			matches := extractStringSubmatches(pattern, configData)
			if len(matches) > 0 { // the first match is the whole pattern
				configsName.WriteString(fmt.Sprintf("      - '%s'\n", matches[1]))
			}
		}
	case "surfboard":
		for _, configData := range configsArray {
			configArray := strings.Split(configData, " = ")
			if len(configArray) > 0 {
				configsName.WriteString(configArray[0] + ",")
			}
		}
	}

	return strings.ReplaceAll(configsName.String(), ",,", ",")
}

func extractStringSubmatches(pattern, input string) []string {
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(input)
	return matches
}

func FullConfig(input, configType string) (string, error) {
	configStart := getConfigStart(configType)
	configProxyGroup := getConfigProxyGroup(configType)
	configProxyRules := getConfigProxyRules(configType)

	proxies, err := GenerateProxies(input, configType)
	if len(proxies) == 0 {
		return "", err
	}
	configsName := extractNames(proxies, configType)
	fullConfigs := generateFullConfig(configStart, proxies, configProxyGroup, configProxyRules, configsName, configType)
	return fullConfigs, err
}

func getConfigStart(configType string) []string {
	return map[string][]string{
		"clash": {
			"port: 7890",
			"socks-port: 7891",
			"allow-lan: true",
			"mode: Rule",
			"log-level: info",
			"ipv6: true",
			"external-controller: 127.0.0.1:9090",
		},
		"meta": {
			"port: 7890",
			"socks-port: 7891",
			"allow-lan: true",
			"mode: Rule",
			"log-level: info",
			"ipv6: true",
			"external-controller: 127.0.0.1:9090",
		},
		"surfboard": {
			"",
			"[General]",
			"loglevel = notify",
			"interface = 127.0.0.1",
			"skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, localhost, *.local",
			"ipv6 = true",
			"dns-server = system, 223.5.5.5",
			"exclude-simple-hostnames = true",
			"enhanced-mode-by-rule = true",
		},
	}[configType]
}

func getConfigProxyGroup(configType string) map[string]interface{} {
	return map[string]interface{}{
		"clash": map[string]interface{}{
			"proxy-groups:": map[string]interface{}{
				"MANUAL": []string{
					"  - name: MANUAL",
					"    type: select",
					"    proxies:",
					"      - URL-TEST",
					"      - FALLBACK",
				},
				"URL-TEST": []string{
					"  - name: URL-TEST",
					"    type: url-test",
					"    url: http://www.gstatic.com/generate_204",
					"    interval: 300",
					"    tolerance: 50",
					"    proxies:",
				},
				"FALLBACK": []string{
					"  - name: FALLBACK",
					"    type: fallback",
					"    url: http://www.gstatic.com/generate_204",
					"    interval: 300",
					"    proxies:",
				},
			},
		},
		"meta": map[string]interface{}{
			"proxy-groups:": map[string]interface{}{
				"MANUAL": []string{
					"  - name: MANUAL",
					"    type: select",
					"    proxies:",
					"      - URL-TEST",
					"      - FALLBACK",
				},
				"URL-TEST": []string{
					"  - name: URL-TEST",
					"    type: url-test",
					"    url: http://www.gstatic.com/generate_204",
					"    interval: 60",
					"    tolerance: 50",
					"    proxies:",
				},
				"FALLBACK": []string{
					"  - name: FALLBACK",
					"    type: fallback",
					"    url: http://www.gstatic.com/generate_204",
					"    interval: 60",
					"    proxies:",
				},
			},
		},
		"surfboard": map[string]interface{}{
			"[Proxy Group]": []string{
				"MANUAL = select,URL-TEST,FALLBACK,",
				"URL-TEST = url-test,",
				"FALLBACK = fallback,",
			},
		},
	}[configType].(map[string]interface{})
}

func getConfigProxyRules(configType string) []string {
	return map[string][]string{
		"clash":     {"rules:", " - GEOIP,IR,DIRECT", " - MATCH,MANUAL"},
		"meta":      {"rules:", " - GEOIP,IR,DIRECT", " - MATCH,MANUAL"},
		"surfboard": {"[Rule]", "GEOIP,IR,DIRECT", "FINAL,MANUAL"},
	}[configType]
}

func arrayToString(input []string) string {
	return strings.Join(input, "\n")
}

func reprocess(input string) string {
	input = strings.ReplaceAll(input, "  - ", "")
	proxiesArray := strings.Split(input, "\n")
	var output []string
	for _, proxyJSON := range proxiesArray {
		var proxyArray map[string]interface{}
		if err := json.Unmarshal([]byte(proxyJSON), &proxyArray); err != nil {
			continue
		}
		proxyBytes, _ := json.Marshal(proxyArray)
		output = append(output, "  - "+string(proxyBytes))
	}
	return strings.ReplaceAll(strings.Join(output, "\n"), "  - null", "")
}

func generateFullConfig(
	configStart []string,
	proxies string,
	configProxyGroup map[string]interface{},
	configProxyRules []string,
	configsName string,
	configType string,
) string {
	configStartString := arrayToString(configStart)
	var proxyGroupManual, proxyGroupURLTest, proxyGroupFallback string
	proxyGroupString := ""
	switch configType {
	case "clash", "meta":
		proxies = "proxies:\n" + proxies
		proxyGroupString = "proxy-groups:"
		proxyGroupManual =
			arrayToString(configProxyGroup["proxy-groups:"].(map[string]interface{})["MANUAL"].([]string)) +
				"\n" +
				configsName
		proxyGroupURLTest =
			arrayToString(configProxyGroup["proxy-groups:"].(map[string]interface{})["URL-TEST"].([]string)) +
				"\n" +
				configsName
		proxyGroupFallback =
			arrayToString(configProxyGroup["proxy-groups:"].(map[string]interface{})["FALLBACK"].([]string)) +
				"\n" +
				configsName
	case "surfboard":
		proxies = "\n[Proxy]\nDIRECT = direct\n" + proxies
		proxyGroupString = "[Proxy Group]"
		proxyGroupManual =
			configProxyGroup["[Proxy Group]"].([]string)[0] + configsName + "\n"
		proxyGroupManual = strings.ReplaceAll(proxyGroupManual, ",,", "")
		proxyGroupURLTest =
			configProxyGroup["[Proxy Group]"].([]string)[1] + configsName + "\n"
		proxyGroupURLTest = strings.ReplaceAll(proxyGroupURLTest, ",,", "")
		proxyGroupFallback =
			configProxyGroup["[Proxy Group]"].([]string)[2] + configsName + "\n"
		proxyGroupFallback = strings.ReplaceAll(proxyGroupFallback, ",,", "")
	}
	proxyGroupString += "\n" + proxyGroupManual + proxyGroupURLTest + proxyGroupFallback
	proxyRules := arrayToString(configProxyRules)
	output :=
		configStartString +
			"\n" +
			proxies +
			proxyGroupString +
			proxyRules
	return output
}

func ProcessURL(urlStr, configType, process string) (string, error) {
	if urlStr == "" {
		return "", fmt.Errorf("URL parameter is missing or invalid")
	}

	typeArray := []string{"clash", "meta", "surfboard"}

	if configType == "" || !contains(typeArray, configType) {
		return "", fmt.Errorf("type parameter is missing or invalid")
	}

	var result string
	var err error

	switch process {
	case "name":
		result, err = GenerateProxies(urlStr, configType)
		result = extractNames(result, configType)
		return result, err
	case "full":
		result, err = FullConfig(urlStr, configType)
		result = strings.ReplaceAll(result, "\\", "")
		return result, err
	default:
		return GenerateProxies(urlStr, configType)
	}
}

func contains(arr []string, value string) bool {
	for _, v := range arr {
		if v == value {
			return true
		}
	}
	return false
}

func getNumber(val interface{}) (int64, error) {
	if flt, ok := val.(float64); ok {
		return int64(flt), nil
	}
	if flt, ok := val.(float32); ok {
		return int64(flt), nil
	}
	str := fmt.Sprintf("%v", val)
	return strconv.ParseInt(str, 10, 60)
}
