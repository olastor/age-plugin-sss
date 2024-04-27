package sss

import (
	"bufio"
	"encoding/base64"
	"errors"
	"filippo.io/age/plugin"
	"fmt"
	"github.com/olastor/age-plugin-controller/pkg/controller"
	"os"
)

var PLUGIN_NAME = "SSS"
var b64 = base64.RawStdEncoding.Strict()

// this client UI acts as a proxy between the main controller (age process) and the
// plugin for which age-plugin-sss is the controller.
var PluginTerminalUIProxy = &plugin.ClientUI{
	DisplayMessage: func(name, message string) error {
		err := controller.SendCommand("msg", []byte(message), true)
		if err != nil {
			return err
		}

		return nil
	},
	RequestValue: func(name, message string, _ bool) (s string, err error) {
		defer func() {
			if err != nil {
				msg := fmt.Sprintf("warn: could not read value for age-plugin-%s: %v", name, err)
				controller.SendCommand("msg", []byte(msg), true)
			}
		}()

		return controller.RequestValue(message, true)
	},
	Confirm: func(name, message, yes, no string) (choseYes bool, err error) {
		defer func() {
			if err != nil {
				msg := fmt.Sprintf("could not read value for age-plugin-%s: %v", name, err)
				controller.SendCommand("msg", []byte(msg), true)
			}
		}()

		command := "confirm " + b64.EncodeToString([]byte(yes))
		if no != "" {
			command += " "
			command += b64.EncodeToString([]byte(no))
		}

		controller.SendCommand(command, []byte(message), false)
		scanner := bufio.NewScanner(os.Stdin)
		err = controller.ProtocolHandler(scanner, func(command string, args []string, body []byte) (done bool, err error) {
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

func RecipientV1() error {
	var policy *SSS

	scanner := bufio.NewScanner(os.Stdin)

	err := controller.ProtocolHandler(scanner, func(command string, args []string, body []byte) (done bool, err error) {
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

			controller.SendCommand("recipient-stanza 0 sss", stanzaMarshal, true)
		}

		return false, nil
	})

	if err != nil {
		return err
	}

	if policy == nil {
		return fmt.Errorf("missing policy")
	}

	controller.SendCommand("done", nil, true)

	return nil
}

func IdentityV1() error {
	var identities []*SSSIdentity
	var stanza *SSSStanza

	scanner := bufio.NewScanner(os.Stdin)

	err := controller.ProtocolHandler(scanner, func(command string, args []string, body []byte) (done bool, err error) {
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
			if i == len(identities)-1 {
				return fmt.Errorf("failed unwrap %s", err)
			}

			continue
		}

		controller.SendCommand("file-key 0", []byte(key), false)
		controller.SendCommand("done", nil, true)
	}

	return nil
}
