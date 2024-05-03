package sss

import (
	"errors"
	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/plugin"
	"fmt"
	"github.com/hashicorp/vault/shamir"
	"github.com/olastor/age-plugin-controller/pkg/controller"
	"golang.org/x/crypto/ssh"
	"slices"
	"sort"
	"strconv"
	"strings"
)

type SSSStanza struct {
	Version   int           `json:"v"`
	Threshold int           `json:"t,omitempty"`
	Shares    []*SSSStanza  `json:"s,omitempty"`
	Stanza    []*age.Stanza `json:"k,omitempty"`
	ShamirX   byte          `json:"x,omitempty"`

	// exclude from stanza data, only used for decryption
	ShareId  int    `json:"-"`
	KeyShare []byte `json:"-"`
}

type SSSIdentityItem struct {
	ShareId     int          `yaml:"share_id,omitempty"  json:"sid,omitempty"`
	IdentityStr string       `yaml:"identity"            json:"i"`
	Identity    age.Identity `yaml:"-"                   json:"-"`
}

type SSSIdentity struct {
	Identities []*SSSIdentityItem `yaml:"identities" json:"ids"`
}

func (identityItem *SSSIdentityItem) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var identity string
	if err := unmarshal(&identity); err == nil {
		identityItem.IdentityStr = identity
		return nil
	}

	// ref: https://abhinavg.net/2021/02/24/flexible-yaml/#make-it-flexible
	type newIdentityItem SSSIdentityItem
	return unmarshal((*newIdentityItem)(identityItem))
}

func (stanza *SSSStanza) setShareIds() {
	var lastId int
	stanza.setShareIdsRec(&lastId)
}

func (stanza *SSSStanza) setShareIdsRec(lastId *int) {
	if stanza.Stanza != nil {
		*lastId += 1
		stanza.ShareId = *lastId
	} else if stanza.Shares != nil {
		for _, subStanza := range stanza.Shares {
			subStanza.setShareIdsRec(lastId)
		}
	}
}

func (stanza *SSSStanza) recoverSecret() (fileKey []byte, err error) {
	var shares [][]byte

	for _, share := range stanza.Shares {
		var keyShare []byte

		if share.KeyShare != nil {
			keyShare = share.KeyShare
		} else if share.Threshold > 0 {
			keyShare, _ = share.recoverSecret()
		}

		if keyShare != nil {
			if stanza.Threshold == 1 {
				// the share is the secret
				return keyShare, nil
			}

			shares = append(shares, getShareWithX(keyShare, share))
		}
	}

	return shamir.Combine(shares)
}

func (stanza *SSSStanza) unwrapKeyShare(identity *SSSIdentityItem) (success bool) {
	if stanza.Threshold > 0 {
		// recursion
		for _, share := range stanza.Shares {
			success = share.unwrapKeyShare(identity)
			if success {
				// it's assumed that one item only unwraps one share. stop early to prevent
				// unnecessary user interactions (password, plugin). to use the same identity
				// to unwrap multiple shares, the user must provide multiple items with the same
				// identity.
				return true
			}
		}

		return false
	}

	if stanza.KeyShare != nil {
		// already unwrapped
		return false
	}

	if identity.ShareId > 0 && stanza.ShareId != identity.ShareId {
		// id mismatch
		return false
	}

	share, err := identity.Identity.Unwrap(stanza.Stanza)
	if err != nil {
		return false
	}

	stanza.KeyShare = share

	return true
}

func (stanza *SSSStanza) getUnecryptedIdsByType() (idsByType map[string][]int) {
	idsByType = make(map[string][]int)

	for _, share := range stanza.Shares {
		if share.Threshold > 0 {
			for key, items := range share.getUnecryptedIdsByType() {
				idsByType[key] = append(idsByType[key], items...)
			}
		} else if share.KeyShare == nil {
			stanzaType := strings.ToLower(share.Stanza[0].Type)
			idsByType[stanzaType] = append(idsByType[stanzaType], share.ShareId)
		}
	}

	return
}

func (stanza *SSSStanza) Unwrap(identity *SSSIdentity) (data []byte, err error) {
	stanza.setShareIds()

	identities := identity.Identities

	// sort identities by "expected amount of user interaction" ascending
	getRank := func(item any) int {
		switch item.(type) {
		case *age.X25519Identity:
			return 1
		case *plugin.Identity:
			return 3
		case *age.ScryptIdentity:
			return 4
		default:
			return 2
		}
	}

	sort.Slice(identities, func(i, j int) bool {
		return getRank(identities[i]) < getRank(identities[j])
	})

	for i, id := range identities {
		remainingStanzaIdsByType := stanza.getUnecryptedIdsByType()

		switch {
		case strings.HasPrefix(id.IdentityStr, "password"):
			msg := "Please enter the password:"

			// the slug is only "nice to have" for decryption, so it shouldn't be enforced
			if len(id.IdentityStr) > 9 {
				passwordId := id.IdentityStr[9:]
				msg = fmt.Sprintf("Please enter password \"%s\":", passwordId)
			}

			// ask for the password
			password, err := controller.RequestValue(msg, true)
			if err != nil {
				return nil, err
			}

			id.Identity, err = age.NewScryptIdentity(password)
			if err != nil {
				return nil, err
			}
		case strings.HasPrefix(id.IdentityStr, "AGE-PLUGIN-"):
			id.Identity, err = plugin.NewIdentity(id.IdentityStr, PluginTerminalUIProxy)
			if err != nil {
				return nil, err
			}

			if id.ShareId == 0 {
				// find the matching stanza
				shareIds := remainingStanzaIdsByType[strings.ToLower(id.Identity.(*plugin.Identity).Name())]
				if len(shareIds) == 1 {
					id.ShareId = shareIds[0]
				} else {
					selectedId, err := stanza.getUserSelectedShareId(i, func(shareId int) string {
						// if there are no matching types, show all remaining ids
						if len(shareIds) > 0 && !slices.Contains(shareIds, shareId) {
							// plugins could handle different types of stanzas
							return ""
						}

						return fmt.Sprintf(" [id=%x]", shareId)
					})

					if err != nil {
						return nil, err
					}

					id.ShareId = selectedId
				}
			}
		case strings.HasPrefix(id.IdentityStr, "AGE-SECRET-KEY-1"):
			id.Identity, err = age.ParseX25519Identity(id.IdentityStr)
			if err != nil {
				return nil, err
			}
		default:
			// check if it's an SSH identity
			pemBytes := []byte(strings.TrimSpace(id.IdentityStr))
			id.Identity, err = agessh.ParseIdentity(pemBytes)
			if err != nil {
				switch v := err.(type) {
				case *ssh.PassphraseMissingError:
					if v.PublicKey == nil {
						// we need the pubkey to unlock the ssh key
						return nil, err
					}

					id.Identity, err = agessh.NewEncryptedSSHIdentity(v.PublicKey, pemBytes, func() ([]byte, error) {
						passphrase, err := controller.RequestValue("Please enter the password for your SSH key:", true)
						if err != nil {
							return nil, err
						}

						return []byte(passphrase), nil
					})

					if err != nil {
						return nil, err
					}
				default:
					return nil, err
				}
			}

			if id.Identity == nil {
				return nil, fmt.Errorf("Unknown identity at index %x of list", i)
			}
		}

		stanza.unwrapKeyShare(id)

		// try to return the recovered secret as early as possible
		fileKeyShare, _ := stanza.recoverSecret()
		if fileKeyShare != nil {
			return fileKeyShare, nil
		}
	}

	return stanza.recoverSecret()
}

func (stanza *SSSStanza) getUserSelectedShareId(identityIndex int, printIdFn PrintIdFunction) (selectedId int, err error) {
	message := fmt.Sprintf("\n\nEncountered multiple options for identity #%d.", identityIndex+1)
	message += "\n\n" + stanza.getTreeAsString(0, printIdFn) + "\n"

	err = controller.SendCommand("msg", []byte(message), true)
	if err != nil {
		return 0, err
	}

	selectedIdStr, err := controller.RequestValue("Please choose the share id to use:", false)
	if err != nil {
		return 0, err
	}

	selectedId, err = strconv.Atoi(selectedIdStr)

	return
}

func (stanza *SSSStanza) Marshal() (data []byte, err error) {
	return EncodeStanza(stanza)
}

type PrintIdFunction func(shareId int) string

func (stanza *SSSStanza) getTreeAsString(indent int, printIdFn PrintIdFunction) (tree string) {
	line_indent := 1

	if stanza.Threshold > 0 && len(stanza.Shares) > 0 {
		if indent == 0 {
			tree += fmt.Sprintf("%ssss (t=%x)\n", strings.Repeat(" ", indent), stanza.Threshold)
		}

		for i, share := range stanza.Shares {
			box_char := "├─"
			if i == len(stanza.Shares)-1 {
				box_char = "└─"
			}

			id := ""
			if share.ShareId > 0 {
				id = printIdFn(share.ShareId)
			}

			stanzaType := "unknown"
			if share.Stanza != nil {
				stanzaType = strings.ToLower(share.Stanza[0].Type)
			} else if share.Shares != nil {
				stanzaType = fmt.Sprintf("sss (t=%x)", share.Threshold)
			}

			tree += fmt.Sprintf("%s%s %s%s\n", strings.Repeat(" ", line_indent+indent), box_char, stanzaType, id)

			if share.Shares != nil {
				tree += share.getTreeAsString(indent+4, printIdFn)
			}
		}
	}

	return
}

func (stanza *SSSStanza) PrintTree() {
	fmt.Printf(stanza.getTreeAsString(0, func(shareId int) string {
		return fmt.Sprintf(" [id=%x]", shareId)
	}))
}
