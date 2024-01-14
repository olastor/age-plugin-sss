package sss

import (
  "bufio"
  "bytes"
  "errors"
  "encoding/base64"
  "fmt"
  "os"
  "strings"
  "filippo.io/age/plugin"
)

var PLUGIN_NAME = "SSS"
var b64 = base64.RawStdEncoding.Strict()

// this client UI acts as a proxy between the main controller (age process) and the
// plugin for which age-plugin-sss is the controller.
var PluginTerminalUIProxy = &plugin.ClientUI{
  DisplayMessage: func(name, message string) error {
    err := SendCommand("msg", []byte(message), true)
    if err != nil {
      return err
    }

    return nil
  },
  RequestValue: func(name, message string, _ bool) (s string, err error) {
    defer func() {
      if err != nil {
        msg := fmt.Sprintf("warn: could not read value for age-plugin-%s: %v", name, err)
        SendCommand("msg", []byte(msg), true)
      }
    }()

    return RequestValue(message, true)
  },
  Confirm: func(name, message, yes, no string) (choseYes bool, err error) {
    defer func() {
      if err != nil {
        msg := fmt.Sprintf("could not read value for age-plugin-%s: %v", name, err)
        SendCommand("msg", []byte(msg), true)
      }
    }()

    command := "confirm " + b64.EncodeToString([]byte(yes))
    if no != "" {
      command += " "
      command += b64.EncodeToString([]byte(no))
    }

    SendCommand(command, []byte(message), false)
    scanner := bufio.NewScanner(os.Stdin)
    err = ProtocolHandler(scanner, func (command string, args []string, body []byte) (done bool, err error) {
      switch command {
        case "ok":
          if args[0] == b64.EncodeToString([]byte("yes")) {
            choseYes = true
            return true, nil
          }
          if args[0] == b64.EncodeToString([]byte("no")) {
            choseYes = false
            return true, nil
          }
          return false, fmt.Errorf("invalid confirmation value %s", args[0])
        case "fail":
          return false, errors.New("controller error")
      }

      return false, errors.New("did not receive expected response")
    })

    if err != nil {
      return false, err
    }

    return
  },
  WaitTimer: func(name string) {
    // we do nothing to not spam the user since the other controller already shows waiting messages
  },
}

type CommandHandler func (command string, args []string, body []byte) (done bool, err error)

// generic parser for the protocol flow that can be filled with a custom command handler for each phase
func ProtocolHandler (scanner *bufio.Scanner, commandHandler CommandHandler) error {
  var command string
  var args []string
  body := ""

  for ;; {
    line := strings.TrimSpace(scanner.Text())

    isEmptyLine := len(line) == 0
    isNewCommand := strings.HasPrefix(line, "->")
    isGreaseCommand := strings.HasPrefix(line, "-> grease")
    isLessThanMaxLineSize := len(line) < 64
    hasPendingCommand := len(command) > 0

    if hasPendingCommand && !isEmptyLine && !isNewCommand {
      body += line
    }

    // flush the pending command with the complete body
    //
    // note: if the controller sends data with exactly the max column size per line
    //       and doesn't send any additional empty line or subsequent command, we're stuck!
    if hasPendingCommand && (isEmptyLine || isNewCommand || isLessThanMaxLineSize) {
      bodyData, err := b64.DecodeString(body)
      if err != nil {
        return err
      }

      done, err := commandHandler(command, args, bodyData)

      if err != nil {
        return err
      }

      if done {
        return nil
      }

      command = ""
      body = ""
    }

    if !isGreaseCommand && isNewCommand {
      splitted := strings.Split(strings.TrimPrefix(line, "-> "), " ")
      command, args = splitted[0], splitted[1:]
      body = ""
    }

    // in this special case we know that we can stop
    if command == "done" {
      return nil
    }

    scanner.Scan()
  }
}

// handler for when we expect "ok" after sending a command
func OkHandler (command string, args []string, body []byte) (done bool, err error) {
  if command == "ok" {
    return true, nil
  }

  if command == "fail" {
    return false, errors.New("Controller signalled failure.")
  }

  return false, fmt.Errorf("Expected 'ok' or 'fail' from controller, but received '%s'.", command)
}


// utility for sending a command with or without a body, or just the body without the command
func SendCommand(command string, body []byte, waitForOk bool) error {
  if command != "" {
    msg := fmt.Sprintf("-> %s\n", command)
    if command == "done" {
      // for some reason we need to add an additional newline here
      // don't ask me why...
      msg += "\n"
    }
    os.Stdout.WriteString(msg)
  }

  if body != nil && len(body) > 0 {
    // send data in b64 while respecting the max column size of 64
    buf := bytes.NewBuffer(body)
    for ;; {
      bufLen := buf.Len()
      if bufLen == 0 {
        break
      }
      line := buf.Next(48)
      os.Stdout.WriteString(b64.EncodeToString(line) + "\n")

      if bufLen == 48 {
        // This additional newline if the last buffer fills out the enitire column size is important!
        // If it's not there, the controller doesn't know that the body ended, expects a new line, and
        // gets stuck as a result.
        os.Stdout.WriteString("\n")
      }
    }
  }

  if waitForOk {
    scanner := bufio.NewScanner(os.Stdin)
    err := ProtocolHandler(scanner, OkHandler)
    if err != nil {
      return err
    }
  }

  return nil
}

func RequestValue(message string, secret bool) (value string, err error) {
  cmd := "request-secret"
  if !secret {
    cmd = "request-public"
  }

  SendCommand(cmd, []byte(message), false)
  scanner := bufio.NewScanner(os.Stdin)

  err = ProtocolHandler(scanner, func (command string, args []string, body []byte) (done bool, err error) {
    switch command {
      case "ok":
        value = string(body)
        return true, nil
      case "fail":
        return false, errors.New("controller error")
    }

    return false, errors.New("did not receive expected response")
  })

  if err != nil {
    return "", err
  }

  return
}

func RecipientV1 () error {
  var policy *SSS

  scanner := bufio.NewScanner(os.Stdin)

  err := ProtocolHandler(scanner, func (command string, args []string, body []byte) (done bool, err error) {
    switch command {
      case "add-recipient":
        if policy != nil {
          return false, errors.New("Can only encrypt to one recipient/identity")
        }

        parsedPolicy, err := ParseRecipient(args[0])

        if err != nil {
          return false, err
        }

        policy = parsedPolicy
      case "wrap-file-key":
        stanza, err := policy.Wrap(body)
        if err != nil {
          return false, err
        }

        stanzaMarshal, err := stanza.Marshal()
        if err != nil {
          return false, err
        }

        SendCommand("recipient-stanza 0 sss", stanzaMarshal, true)
    }

    return false, nil
  })

  if err != nil {
    return err
  }

  if policy == nil {
    return fmt.Errorf("missing policy")
  }

  SendCommand("done", nil, true)

  return nil
}

func IdentityV1 () error {
  var identities []*SSSIdentity
  var stanza *SSSStanza

  scanner := bufio.NewScanner(os.Stdin)

  err := ProtocolHandler(scanner, func (command string, args []string, body []byte) (done bool, err error) {
    switch command {
      case "add-identity":
        parsedIdentity, err := ParseIdentity(args[0])
        if err != nil {
          return false, fmt.Errorf("Error parsing identity: %s", err)
        }
        identities = append(identities, parsedIdentity)
      case "recipient-stanza":
        if args[1] != "sss" {
          return false, nil
        }

        if stanza != nil {
          return false, errors.New("Decrypting multiple stanzas not supported")
        }

        stanzaParsed, err := ParseStanza(body)
        if err != nil {
          return false, fmt.Errorf("Error parsing stanza: %s", err)
        }

        stanza = stanzaParsed
    }

    return false, nil
  })

  if err != nil {
    return err
  }

  if identities == nil || len(identities) == 0 {
    return fmt.Errorf("missing identity")
  }

  if stanza == nil {
    return fmt.Errorf("missing stanza")
  }

  for i, id := range identities {
    key, err := stanza.Unwrap(id)
    if err != nil {
      if i == len(identities) - 1 {
        return fmt.Errorf("failed unwrap %s", err)
      }

      continue
    }

    SendCommand("file-key 0", []byte(key), false)
    SendCommand("done", nil, true)
  }

  return nil
}

