# age-plugin-sss

⚠️ Consider this plugin to be experimental until the version v1.0.0 is published! ⚠️

---

:scissors: Split encryption keys and encrypt key shares with different [age](https://github.com/FiloSottile/age) (licensed BSD 3-Clause) recipients.

:passport_control: Create (complex) policies about which combinations of identites can decrypt the file.

:pushpin: Uses Hashicorp Vault's [implementation](https://github.com/hashicorp/vault/blob/main/shamir/shamir.go) of Shamir's Secret Sharing (licensed MPL-2.0).

:memo: See [SPEC.md](https://github.com/olastor/age-plugin-sss/blob/main/SPEC.md) for more details.

---

## Installation

### Requirements

- [age](https://github.com/FiloSottile/age) (>= 1.1.0) or [rage](https://github.com/str4d/rage)

### Build from source

Run

```bash
go build -v ./cmd/...
```
and copy `age-plugin-sss` to a directory of your `$PATH`.

## Usage

### Basic Usage

#### Encryption

First, define a policy in YAML format:

```yaml
threshold: 2
shares:
  - age1t7cexdfjmkk4fgsf6pgzhn0skk0qewxr9y7tdu3l639fdmptcaxqv3nznt
  - age1jcq99v6f74gwstqhg2vsll5s3rckdys8ttr2nnrzpegxu0y533vqnf7d2u
  - age1zunvd6ztdeljcxzhe70370cx5q54czyhy2qjgsnju9rsyjaexqqqfrxg2w
```

In this case, the file key will be split into three shares, each of which will be encrypted with one of the three recipients in the `shares` array. The `threshold` specifies how many of the shares are required to decrypt the file again. For our example, any two identities that correspond to a recipient in the list will suffice. 

Next, generate a new recipient from this policy file:

```bash
$ age-plugin-sss --generate-recipient policy.yaml
age1sss1r79ssqqqqqqqqq8l2nxy6m5yyq2qpc9mkz0q2pv4uf2e5tsv0urpec5rqupvdwmhm8xqt05mypvanzmyktldcfy3j4kvul9p2znxn67ly9xdvedmn3hwey0xzq5f32e9myz74s50s496hhe842k5ret3gsjvl6ul7y92ftytzkfmkvkzaevvm3e3v709f5pa0u3jv9nrr2nhrtws8ee4ug2659vljczx392j7qa48x7x5cehsfeyz4vmvx0df6rmvls9mr47ez2thh6vqvqfhxnrzauha8alqqqqplll80huf5hzqqqqq3csvcr
```

As you can see, recipients for this plugin can be quite long because they contain multiple other recipients used for encrypting key shares.

Now you can use this recipient to encrypt anything, e.g.

```bash
echo "it works" | age -r age1sss1r79ssqqqqqqqqq8l2nxy6m5yyq2qpc9mkz0q2pv4uf2e5tsv0urpec5rqupvdwmhm8xqt05mypvanzmyktldcfy3j4kvul9p2znxn67ly9xdvedmn3hwey0xzq5f32e9myz74s50s496hhe842k5ret3gsjvl6ul7y92ftytzkfmkvkzaevvm3e3v709f5pa0u3jv9nrr2nhrtws8ee4ug2659vljczx392j7qa48x7x5cehsfeyz4vmvx0df6rmvls9mr47ez2thh6vqvqfhxnrzauha8alqqqqplll80huf5hzqqqqq3csvcr -o testing.enc
```

#### Decryption

First, define a new YAML file containing the identities to use for decryption with the following structure:

```yaml
identities:
  - AGE-SECRET-KEY-1XUR5...
  - AGE-SECRET-KEY-17FXT...
```

This file only contains a flat list of identities. The structure of the policy (or order of shares) is not replicated here and thresholds or other information do not need to be included. There must be enough valid identities to meet the secret splitting threshold, though.

Next, generate an identity from the YAML file (similarly as done for recipients):

```bash
age-plugin-sss --generate-identity example-id.yaml > id.txt
```

Finally, the encrypted file can be decrypted with the generated identity:

```bash
$ age -d -i id.txt testing.enc
it works
```

####

### Advanced Usage

#### (More) Complex Policies

