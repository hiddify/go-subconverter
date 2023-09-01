package converter

import "testing"

func TestIsValidUUID(t *testing.T) {
	correct := []string{
		"940586c1-62cf-43e2-b71c-b83b24cab019", // V4
		"9a4cda5b-12b5-5e03-822a-7d33af73bcf0", // uuid5(uuid.NAMESPACE_URL, 'https://google.com')
		"BE9A4A95-8E33-50CB-954C-AC8C57722075", // V4
		"940586c162cf43e2b71cb83b24cab019",     // V4 without seperator
	}
	incorrect := []string{
		"940586c1-62cf-43e2-b71c-b83b24cab01",
		"940586c1-62cf-43e2-b71c-b83b24cab0190",
		"940586c1-62cf-43e2-b71cb83b24cab019",
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
