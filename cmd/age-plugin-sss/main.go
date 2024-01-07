package main

import (
  "fmt"
  "log"
  "flag"
  "os"
  "bufio"
  "strings"
  "gopkg.in/yaml.v3"
  "github.com/olastor/age-plugin-sss/pkg/sss"
)

var Version string

func main() {
  var (
    pluginFlag              string
    inspectFlag             string
    generateRecipientFlag   string
    generateIdentityFlag    string
    decodeFlag              bool
    helpFlag                bool
    versionFlag             bool
  )

  flag.StringVar(&pluginFlag, "age-plugin", "", "Used by age for interacting with the plugin.")
  flag.StringVar(&inspectFlag, "inspect", "", "Display the policy structure of `ENCRYPTED_FILE`.")
  flag.StringVar(&generateRecipientFlag, "generate-recipient", "", "Generate a recipient from a YAML policy stored in `FILE`.")
  flag.StringVar(&generateIdentityFlag, "generate-identity", "", "Generate an identity from a YAML policy stored in `FILE`.")
  flag.BoolVar(&decodeFlag, "decode", false, "Decode recipient or identity from STDIN back to YAML.")
  flag.BoolVar(&versionFlag, "v", false, "Show the version.")
  flag.BoolVar(&helpFlag, "h", false, "Show this help message.")
  flag.BoolVar(&helpFlag, "help", false, "Show this help message.")

  flag.Parse()

  if helpFlag {
    flag.Usage()
    os.Exit(0)
  }

  if pluginFlag == "recipient-v1" {
    if err := sss.RecipientV1(); err != nil {
      sss.SendCommand("error", []byte(err.Error()), false)
      os.Exit(1)
    }
    os.Exit(0)
  }

  if pluginFlag == "identity-v1" {
    if err := sss.IdentityV1(); err != nil {
      sss.SendCommand("error", []byte(err.Error()), false)
      os.Exit(1)
    }
    os.Exit(0)
  }

  if generateRecipientFlag != "" {
    policy, err := sss.ParsePolicyFromYamlFile(generateRecipientFlag)
    if err != nil {
      log.Fatal(err)
      os.Exit(1)
    }

    encodedRecipient, err := sss.EncodeRecipient(policy)
    if err != nil {
      log.Fatal(err)
      os.Exit(1)
    }

    fmt.Printf("%s\n", encodedRecipient)
    os.Exit(0)
  }

  if generateIdentityFlag != "" {
    identity, err := sss.ParseIdentityFromYamlFile(generateIdentityFlag)
    if err != nil {
      log.Fatal(err)
      os.Exit(1)
    }

    encodedIdentity, err := sss.EncodeIdentity(identity)
    if err != nil {
      log.Fatal(err)
      os.Exit(1)
    }

    fmt.Printf("%s\n", encodedIdentity)
    os.Exit(0)
  }

  if inspectFlag != "" {
    err := sss.InspectFileHeader(inspectFlag)
    if err != nil {
      fmt.Printf("%s\n", err)
      os.Exit(1)
    }
    os.Exit(0)
  }

  if decodeFlag {
    reader := bufio.NewReader(os.Stdin)
    text, _ := reader.ReadString('\n')
    text = strings.TrimSpace(text)

    recipient, err := sss.ParseRecipient(text)
    if err == nil {
      policy, err := yaml.Marshal(recipient)
      if err != nil {
        log.Fatal(err)
        os.Exit(1)
      }

      fmt.Printf("%s", policy)
      os.Exit(0)
    }

    identity, err := sss.ParseIdentity(text)
    if err == nil {
      identityYaml, err := yaml.Marshal(identity)
      if err != nil {
        log.Fatal(err)
        os.Exit(1)
      }

      fmt.Printf("%s", identityYaml)
      os.Exit(0)
    }

    os.Exit(1)
  }

  if versionFlag && Version != "" {
    fmt.Println(Version)
    os.Exit(0)
  }

  flag.Usage()
  os.Exit(1)
}
