package main

import (
	"bufio"
	"filippo.io/age"
	page "filippo.io/age/plugin"
	"flag"
	"fmt"
	"github.com/olastor/age-plugin-sss/pkg/sss"
	"gopkg.in/yaml.v3"
	"log"
	"os"
	"strings"
)

var Version string

const USAGE = `Usage:
  age-plugin-sss --generate-recipient <YAML policy file>
  age-plugin-sss --generate-identity <YAML identities file>
  age-plugin-sss --inspect <encrypted file>
  echo <recipient or identity string> | age-plugin-sss --decode

Options:
    --generate-recipient <PATH>   Generate an recipient from a YAML policy file.
    --generate-identity <PATH>    Generate an identity from a YAML file.
    --inspect <PATH>              Display the policy structure of an encrypted file.
    -x, --decode                  Decode recipient or identity from STDIN back to YAML.
    -v, --version                 Show the version.
    -h, --help                    Show this help message.

Examples:

(Encryption)

  $ cat <<EOF > policy.yaml
threshold: 2
shares:
  - age1q4ser2a5lu7ylu76ld07g2mn58sx5tqmtagmrucpdgcvv6zzyfds6ajx7z
  - age1u9pucxxkr9fh37e65wxf9nzf49pusq4ud9thd2m9xw5dxscdzg8sagm0jk
  # deep nesting and t=1 are possible
  - threshold: 1
    shares:
      - age1qdwjfqukwc0e0p6yg8k392t22ewkfgy9nttrl3hqm0zcmsswcqsqtg3uyn
      - age13csecsv5298ww6q5ky9n02heumdjxnekkvr8v64azaq5c3ps299qxupkqz
EOF
  $ age-plugin-sss --generate-recipient policy.yaml > recipient.txt
  $ echo 'secret' | age -R recipient.txt -o secret.enc


(Decryption)

  $ cat <<EOF > identity.yaml
# list of enough (not all) identities to meet the root threshold
identities:
  - AGE-SECRET-KEY-1E7T...
  # you can pin the identity to a specific share id (identifies the matching recipient node/leaf)
  # share ids are shown when using the --inspect flag on an encrypted file
  - share_id: 3
    identity: AGE-SECRET-KEY-1E7T
EOF
  $ age-plugin-sss --generate-identity identity.yaml > identity.txt
  $ age -d -i identity.txt secret.enc`

func main() {
	var (
		pluginFlag            string
		inspectFlag           string
		generateRecipientFlag string
		generateIdentityFlag  string
		decodeFlag            bool
		helpFlag              bool
		versionFlag           bool
	)

	flag.Usage = func() { fmt.Fprintf(os.Stderr, "%s\n", USAGE) }
	flag.StringVar(&pluginFlag, "age-plugin", "", "")
	flag.StringVar(&inspectFlag, "inspect", "", "")
	flag.StringVar(&generateRecipientFlag, "generate-recipient", "", "")
	flag.StringVar(&generateIdentityFlag, "generate-identity", "", "")
	flag.BoolVar(&decodeFlag, "x", false, "")
	flag.BoolVar(&decodeFlag, "decode", false, "")
	flag.BoolVar(&versionFlag, "v", false, "")
	flag.BoolVar(&helpFlag, "h", false, "")
	flag.BoolVar(&helpFlag, "help", false, "")

	flag.Parse()

	if helpFlag {
		flag.Usage()
		os.Exit(0)
	}

	if pluginFlag == "recipient-v1" {
		p, err := page.New("sss")
		if err != nil {
			os.Exit(1)
		}
		p.HandleRecipient(func(data []byte) (age.Recipient, error) {
			r, err := sss.ParseRecipient(page.EncodeRecipient("sss", data))

			var addPlugin func(s *sss.SSS)
			addPlugin = func(s *sss.SSS) {
				s.Plugin = p
				if s.Shares != nil {
					for _, ss := range s.Shares {
						addPlugin(ss)
					}
				}
			}

			addPlugin(r)

			if err != nil {
				return nil, err
			}
			return r, nil
		})
		if exitCode := p.RecipientV1(); exitCode != 0 {
			os.Exit(exitCode)
		}
		os.Exit(0)
	}

	if pluginFlag == "identity-v1" {
		p, err := page.New("sss")
		if err != nil {
			os.Exit(1)
		}
		p.HandleIdentity(func(data []byte) (age.Identity, error) {
			i, err := sss.ParseIdentity(page.EncodeIdentity("sss", data))
			i.Plugin = p
			if err != nil {
				return nil, err
			}
			return i, nil
		})
		if exitCode := p.IdentityV1(); exitCode != 0 {
			os.Exit(exitCode)
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
