package sss

import (
  "fmt"
  "strings"
  "regexp"
  "io/ioutil"
  "encoding/json"
  "gopkg.in/yaml.v3"
  "filippo.io/age/plugin"
)

func ParsePolicyFromYamlFile (filePath string) (policy *SSS, err error) {
  yamlFile, err := ioutil.ReadFile(filePath)
  if err != nil {
    return nil, err
  }

  err = yaml.Unmarshal(yamlFile, &policy)
  if err != nil {
    return nil, err
  }

  return
}

func ParseIdentityFromYamlFile (filePath string) (identity *SSSIdentity, err error) {
  yamlFile, err := ioutil.ReadFile(filePath)
  if err != nil {
    return nil, err
  }

  err = yaml.Unmarshal(yamlFile, &identity)
  if err != nil {
    return nil, err
  }

  return
}

func EncodeRecipient (policy *SSS) (recipientStr string, err error) {
  jsonPolicy, err := json.Marshal(policy)
  if err != nil {
    return "", err
  }

  compressed, err := compress(jsonPolicy)
  if err != nil {
    return "", err
  }

  return plugin.EncodeRecipient(PLUGIN_NAME, compressed), nil
}

func EncodeIdentity (identity *SSSIdentity) (identityStr string, err error) {
  jsonIdentity, err := json.Marshal(identity)
  if err != nil {
    return "", err
  }

  compressed, err := compress(jsonIdentity)
  if err != nil {
    return "", err
  }

  return plugin.EncodeIdentity(PLUGIN_NAME, compressed), nil
}

func EncodeStanza (stanza *SSSStanza) (data []byte, err error) {
  jsonStanza, err := json.Marshal(stanza)
  if err != nil {
    return nil, err
  }

  data, err = compress(jsonStanza)
  if err != nil {
    return nil, err
  }

  return
}


func ParseRecipient (recipientString string) (policy *SSS, err error) {
  var data []byte

  _, data, err = plugin.ParseRecipient(recipientString)
  if err != nil {
    return nil, err
  }

  uncompressed, err := decompress(data)
  if err != nil {
    return nil, err
  }

  err = json.Unmarshal(uncompressed, &policy)
  if err != nil {
    return nil, err
  }

  return
}

func ParseIdentity (identityString string) (identity *SSSIdentity, err error) {
  var data []byte

  _, data, err = plugin.ParseIdentity(identityString)
  if err != nil {
    return nil, err
  }

  uncompressed, err := decompress(data)
  if err != nil {
    return nil, err
  }

  err = json.Unmarshal(uncompressed, &identity)
  if err != nil {
    return nil, err
  }

  return
}

func ParseStanza(stanzaData []byte) (stanza *SSSStanza, err error) {
  uncompressed, err := decompress(stanzaData)
  if err != nil {
    return nil, err
  }

  err = json.Unmarshal(uncompressed, &stanza)
  if(err != nil){
    return nil, err
  }

  return
}

func InspectFileHeader(filePath string) error {
  encryptedFile, err := ioutil.ReadFile(filePath)
  if err != nil {
    return err
  }

  re := regexp.MustCompile(`-> sss\n[^>]+`)

  stanzas := re.FindAll(encryptedFile, -1)

  if stanzas == nil {
    fmt.Println("No sss stanzas found.")
    return nil
  }

  for i, stanzaBody := range stanzas {
    if len(stanzas) > 1 {
      fmt.Printf("Stanza %x\n", i + 1)
    }

    stanzaDataB64 := strings.SplitN(string(stanzaBody), "-> sss", 2)[1]
    stanzaDataB64 = strings.SplitN(stanzaDataB64, "-", 2)[0]
    stanzaDataB64 = strings.TrimSpace(stanzaDataB64)

    stanzaData, err := b64.DecodeString(stanzaDataB64)
    if err != nil {
      return err
    }

    stanza, err := ParseStanza(stanzaData)
    if err != nil {
      return err
    }

    stanza.setShareIds()
    stanza.PrintTree()
  }

  return nil
}
