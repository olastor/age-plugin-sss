package sss

import (
	"reflect"
	"regexp"
	"slices"
	"testing"
)

func TestStanzaFormat(t *testing.T) {
	policy, err := ParsePolicyFromYamlFile("./testdata/policy-simple.yaml")
	if err != nil {
		t.Error("Failed parsing policy")
	}

	wrapKeyB64 := "uSXswLdcd6WGomcONdBFmA"
	wrapKey, err := b64.DecodeString(wrapKeyB64)
	if err != nil {
		t.Error("Failed decoding")
	}

	stanza, err := policy.wrap(wrapKey)
	if err != nil {
		t.Error("Failed creating stanza")
	}

	stanzaMarshal, err := stanza.Marshal()
	if err != nil {
		t.Error("Failed stanza marshal")
	}

	stanzaParsed, err := ParseStanza(stanzaMarshal)
	if err != nil {
		t.Error("Failed parsing stanza")
	}

	if !reflect.DeepEqual(stanza, stanzaParsed) {
		t.Error("Stanza not the same after parsing")
	}

	// make sure the stanza's json only includes the expected fields
	stanza.KeyShare = wrapKey
	stanzaMarshal2, err := stanza.Marshal()
	if err != nil {
		t.Error("Failed stanza marshal")
	}

	jsonString, err := decompress(stanzaMarshal2)
	if err != nil {
		t.Error("Failed decompressing stanza")
	}

	re := regexp.MustCompile(`"[^"]+":`)
	allKeys := re.FindAll(jsonString, -1)
	expectedKeys := []string{`"v":`, `"t":`, `"s":`, `"k":`, `"Type":`, `"Args":`, `"Body":`, `"x":`}
	for _, k := range allKeys {
		if !slices.Contains(expectedKeys[:], string(k)) {
			t.Errorf("Unexpected key in stanza: %s", k)
		}
	}
}
