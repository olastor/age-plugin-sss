package sss

import (
	"encoding/base64"
	"filippo.io/age/plugin"
)

var PLUGIN_NAME = "SSS"
var b64 = base64.RawStdEncoding.Strict()

// this client UI acts as a proxy between the main controller (age process) and the
// plugin for which age-plugin-sss is the controller.
func getPluginClientUIProxy(p *plugin.Plugin) *plugin.ClientUI {
	return &plugin.ClientUI{
		DisplayMessage: func(name, message string) error {
			return p.DisplayMessage(message)
		},
		RequestValue: func(name, message string, _ bool) (s string, err error) {
			return p.RequestValue(message, true)
		},
		Confirm: func(name, message, yes, no string) (choseYes bool, err error) {
			return p.Confirm(message, yes, no)
		},
		WaitTimer: func(name string) {
			// we do nothing to not spam the user since the other controller already shows waiting messages
		},
	}
}
