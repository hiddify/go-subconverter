package converter

import (
	"encoding/base64"
	"fmt"
	"testing"
)

func TestIsValidUUID(t *testing.T) {
	correct := []string{
		"940586c1-62cf-43e2-b71c-b83b24cab019", // V4
		"9a4cda5b-12b5-5e03-822a-7d33af73bcf0", // uuid5(uuid.NAMESPACE_URL, 'https://google.com')
		"BE9A4A95-8E33-50CB-954C-AC8C57722075", // V4
		"940586c162cf43e2b71cb83b24cab019",     // V4 without seperator
	}
	incorrect := []string{
		"940586c1-62cf-43e2-b71c-b83b24cab01",   // V4, less characters
		"940586c1-62cf-43e2-b71c-b83b24cab0190", // too many characters
		"940586c1-62cf-43e2-b71cb83b24cab019",   // Invalid seperator scheme
	}
	for _, v := range correct {
		if !isValidUUID(v) {
			t.Errorf("Valid UUID=%s rejected", v)
		}
	}
	for _, v := range incorrect {
		if isValidUUID(v) {
			t.Errorf("Invalid UUID=%s accepted", v)
		}
	}
}

func TestProcessURLVMESS(t *testing.T) {
	vmessJSON := `{
		"v": "2",
		"ps": "some-random-person",
		"add": "ob.example.com",
		"port": "443",
		"id": "bedc7a2a-df5c-dc6a-cf3c-3b76a303fa28",
		"aid": 0,
		"scy": "",
		"net": "ws",
		"type": "none",
		"host": "ob.example.com",
		"path": "/qTARlasidhfasjkdf",
		"tls": "tls",
		"sni": "ob.example.com"
	}`
	vmessURL := "vmess://" + base64.StdEncoding.EncodeToString([]byte(vmessJSON))
	output, err := ProcessURL(vmessURL, "meta", "")
	fmt.Println("VMESS Result:\n--------------------")
	fmt.Println(output)
	fmt.Println("--------------------\nError: ", err)
	fmt.Println()
}

func TestProcessURLSS(t *testing.T) {
	ssURL := "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpAI0pMS1NGSEtFV1IjUw==@sdfm234.www.outline.network.example.com:804#config-name"
	output, err := ProcessURL(ssURL, "meta", "")
	fmt.Println("SS Result:\n--------------------")
	fmt.Println(output)
	fmt.Println("--------------------\nError: ", err)
	fmt.Println()
}

func TestProcessURLVLESS(t *testing.T) {
	vlessURL := "vless://1d1a7193-61a9-4fc1-9778-dd517cf9f919@1.2.3.4:2083?encryption=none&fp=chrome&host=worker.abcd.workers.dev&path=%2F%3Fed%3D2048&security=tls&sni=worker.abcd.workers.dev&type=ws"
	output, err := ProcessURL(vlessURL, "meta", "")
	fmt.Println("VLESS Result:\n--------------------")
	fmt.Println(output)
	fmt.Println("--------------------\nError: ", err)
	fmt.Println()
}

func TestProcessURLTrojan(t *testing.T) {
	trojanURL := "trojan://telegram-id-1234@5.6.7.8:22222?security=tls&sni=some.example.com&type=tcp"
	output, err := ProcessURL(trojanURL, "meta", "")
	fmt.Println("Trojan Result:\n--------------------")
	fmt.Println(output)
	fmt.Println("--------------------\nError: ", err)
	fmt.Println()
}
