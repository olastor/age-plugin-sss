package sss

import (
	"errors"
	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/plugin"
	"fmt"
	"github.com/hashicorp/vault/shamir"
	"strings"
)

type SSS struct {
	Threshold int            `yaml:"threshold,omitempty" json:"t,omitempty"`
	Shares    []*SSS         `yaml:"shares,omitempty"    json:"s,omitempty"`
	Recipient string         `yaml:"recipient,omitempty" json:"r,omitempty"`
	Plugin    *plugin.Plugin `yaml:"-"                   json:"-"`
}

func (policy *SSS) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var recipient string
	if err := unmarshal(&recipient); err == nil {
		policy.Recipient = recipient
		return nil
	}

	// ref: https://abhinavg.net/2021/02/24/flexible-yaml/#make-it-flexible
	type newPolicy SSS
	return unmarshal((*newPolicy)(policy))
}

func (policy *SSS) Wrap(fileKey []byte) (stanza []*age.Stanza, err error) {
	sssStanza, err := policy.wrap(fileKey)
	if err != nil {
		return nil, err
	}

	stanzaBody, err := sssStanza.Marshal()
	if err != nil {
		return nil, err
	}

	return []*age.Stanza{
		&age.Stanza{
			Type: "sss",
			Body: stanzaBody,
		},
	}, nil
}

func (policy *SSS) wrap(fileKey []byte) (stanza *SSSStanza, err error) {
	stanza = &SSSStanza{}
	stanza.Version = 1

	if policy.Shares != nil {
		if policy.Threshold <= 0 {
			return nil, errors.New("Invalid threshold")
		}

		var fileKeyShares [][]byte

		if policy.Threshold == 1 {
			// a threshold of one does not mean splitting, but copying the secret for each child node
			n := len(policy.Shares)
			fileKeyShares = make([][]byte, n)
			for i := 0; i < n; i++ {
				fileKeyShares[i] = fileKey
			}
		} else {
			fileKeyShares, err = shamir.Split(fileKey, len(policy.Shares), policy.Threshold)
			if err != nil {
				return nil, err
			}
		}

		stanza.Threshold = policy.Threshold

		for i, fileKeyShare := range fileKeyShares {
			// The implementation of SSS creates shares that are one byte larger than the
			// original secret, but we need the file key share to be exactly the same size
			// as before (16 bytes). We can remove the last byte and keep that in a separate,
			// public field. This is because the last byte specifies the X value of the share
			// in the polynomial, which does not need to be secret.
			shareWithoutX := make([]byte, 16)
			for i := 0; i < 16; i++ {
				shareWithoutX[i] = fileKeyShare[i]
			}

			subStanza, err := policy.Shares[i].wrap(shareWithoutX)
			if err != nil {
				return nil, err
			}

			if policy.Threshold > 1 {
				subStanza.ShamirX = fileKeyShare[16]
			}

			stanza.Shares = append(stanza.Shares, subStanza)
		}

		return
	}

	if policy.Recipient == "" {
		return nil, errors.New("missing recipient in policy")
	}

	policy.Recipient = strings.TrimSpace(policy.Recipient)

	var wrappedShare []*age.Stanza

	switch {
	case strings.HasPrefix(policy.Recipient, "password-"):
		if policy.Recipient == "password-" {
			return nil, errors.New("missing identifier for password")
		}

		passwordId := policy.Recipient[9:]
		password, err := policy.Plugin.RequestValue(fmt.Sprintf("Please enter password \"%s\":", passwordId), true)
		if err != nil {
			return nil, err
		}

		password2, err := policy.Plugin.RequestValue(fmt.Sprintf("Please confirm password \"%s\":", passwordId), true)
		if err != nil {
			return nil, err
		}

		if password != password2 {
			return nil, errors.New("passwords do not match")
		}

		scriptRecipient, err := age.NewScryptRecipient(password)
		if err != nil {
			return nil, err
		}

		wrappedShare, err = scriptRecipient.Wrap(fileKey)

		if err != nil {
			return nil, err
		}
	case strings.HasPrefix(policy.Recipient, "age1") && strings.Count(policy.Recipient, "1") > 1:
		pluginRecipient, err := plugin.NewRecipient(policy.Recipient, getPluginClientUIProxy(policy.Plugin))
		if err != nil {
			return nil, err
		}

		wrappedShare, err = pluginRecipient.Wrap(fileKey)
		if err != nil {
			return nil, err
		}
	case strings.HasPrefix(policy.Recipient, "age1"):
		x25519Recipient, err := age.ParseX25519Recipient(policy.Recipient)
		if err != nil {
			return nil, err
		}

		wrappedShare, err = x25519Recipient.Wrap(fileKey)
		if err != nil {
			return nil, err
		}
	case strings.HasPrefix(policy.Recipient, "ssh-"):
		sshRecipient, err := agessh.ParseRecipient(policy.Recipient)
		if err != nil {
			return nil, err
		}

		wrappedShare, err = sshRecipient.Wrap(fileKey)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported recipient %s", policy.Recipient)
	}

	if wrappedShare == nil {
		return nil, fmt.Errorf("could not encrypt to recipient %s", policy.Recipient)
	}

	stanza.Stanza = wrappedShare

	return
}
