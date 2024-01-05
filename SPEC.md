# age-plugin-sss

- Version: 1.0.0
- Status: Draft

## Basic Concepts

### Shamir's Secret Sharing (SSS)

Shamir's Secret Sharing (SSS) [1] is a cryptographic scheme in which a secret _s_ is split into _n_ pieces/shares of equal size. The original secret can only be recovered from any _t_ (the chosen "threshold") combinations of the shares, but not less. The threshold must neither be smaller than 2 nor greater than n.

### Policies based on SSS

Recursive application of SSS enables more complex secret sharing structures in which shares themselves are splitted. This allows for the definition of arbitrarily complex trees that define sophisticated policies about which combinations of shares are eligble for secret recovery, and which are not. See [3] for an existing implementation. 

#### Example

In the following example the secret is split into 4 shares.

- secret (splitted t=2)
  - **share 1**
  - share 2 (splitted t=2)
    - **share 2.1**
    - **share 2.2**
    - **share 2.3**

The first share is mandatory for recovery of the secret and must be combined with any two of the remaining three shares (2.1-2.3). Notice that _share 2_ is only temporary and must be discarded.

#### Special Case t=1

Pure SSS requires a minimum threshold t=2, but supporting a minimum of t=1 is desirable for practicality and flexibility. The special case t=1 means "each share is a copy of the secret", thus no secret splitting is done. However, it is not an uncommon use case to wrap the same secret with multiple keys. Choosing a threshold t=1 for the root secret (the file key) is equivalent to encrypting the file with each share key separately. Therefore, choosing t=1 is more useful if it's done in a nested policy.

## Recipient Format

Recipients are derived from a user-defined YAML policy.

### Policy YAML Format

The user must define a policy of the following structure:

```
type Policy = {
  threshold: <integer{1-255}>
  shares: <(RecipientShare | Policy)[]>
}

type RecipientShare = {
  recipient: <string>
}
```

The recipient in `RecipientShare` defines a native or plugin recipient with which the key share shall be encrypted. For convenience, the user may provide a single string instead.

**Example:**

```yaml
threshold: 2
shares:
  - age18gqvfe9serg95m703cs6znytzvkzv4jkcgl0ryrmlj4z54kexpyqe8rmaf
  - threshold: 1
    shares:
      - recipient: age1pnp983ttagwpzh6kdc99s2cp2d54zmzppwnk88jqy6z7hjfnca5q2aujqd
      - age1ef0z9z8xwykahmvcuqxejr97e05lurar4tuzt4fkqkwxk5xq85eqrtehcm
```

SSS-recipients are derived from a YAML policy by Bech32-encoding a gzip-compressed JSON representation of the policy. The following field mapping MUST be used as a replacement to help reduce the size:

- `threshold`: `t`
- `shares`: `s`
- `recipient`: `r`

### Considerations

- The gzip compression is applied to reduce the string length of SSS recipients since they include multiple other recipients and may encode complex policies.
- Serialization using JSON was chosen in favor of a byte-level encoding of the policy for practical reasons and simplicity. A more sophisticated encoding strategy may be considered in future versions.

### Supported Recipients

The following lists the types of recipients that may be used to wrap a share.

#### X25519

Wrapping to native X25519 recipients MUST be supported using the existing interface.

#### Password/Scrypt

Encryption to native Scrypt recipients requires the user to enter a password. The plugin MUST recognize the special recipient of the form `password-<mandatory-slug-or-id>` for this. The slug/id is not included in the stanza and only used in the prompt that asks for the password. Its purpose is to remind the user of the location of password in the policy during encryption and prevent confusing passwords if there are multiple.

#### Plugin Recipients

In order to support plugin recipients, the sss plugin must act as a controller to perform the necessary protocol steps for wrapping the file key share. For displaying messages to the user or requesting values / confirmations, the sss plugin must proxy the messages between the main age controller and the downstream plugin.

```
age <---> age-plugin-sss <---> age-plugin-x
```

#### SSH Recipients

TBA

### Conversion to YAML

The plugin MUST offer a way to generate a YAML policy from a recipient/identity string. Generating a recipient/identity from a YAML policy and converting it back to a YAML policy MUST always yield the exact same policy.

## Identity Format

An identity is likewise generated from a YAML file containing a flat list of identites to use for unwrapping. The user is responsible for adding enough identities to meet the threshold(s).

### YAML Format

The YAML representation is a simple flat list of identities under the top-level key `identities`. Each item is either the identity string, or an object with the mandatory field `identity` and an optional field `share_id` to specify the exact share in the stanza that should be encrypted with the identity. The `share_id` can be used to eliminate ambiguities which might lead to unnecessary user interactions (e.g., with hardware tokens). The `share_id` can be determined via the stanza inspection feature.

**Example:**

```yaml
identities:
  - AGE-SECRET-KEY...a
  - identity: AGE-SECRET-KEY...b
  - share_id: 2
    identity: AGE-PLUGIN-FIDO2-HMAC...c
  - share_id: 4
    identity: AGE-PLUGIN-FIDO2-HMAC...d
```

## Stanza Format

The stanza data is the base64-encoded, gzip-compressed JSON representation of the following recursive data structure

```
type Stanza = {
  v: 1,
  t: <integer>,
  s: <Stanza[]>,
  k: <string>
  x: <integer>
}
```

with either the keyset `v`, `t`, `s` (share list) or `k`, `x` (one share), where

- `v` is a fixed version identitfier for the stanza format,
- `t` is the threshold of SSS,
- `s` is the array of shares,
- `k` is the base64-encoded native or third-party plugin stanza wrapping the share,
- `x` is the public X value of the share in the polynomial used for SSS (see [2]).

The stanza reflects the recipient's policy structure, but includes the wrapped shares.

### Share IDs

In order to reference a single leaf in the policy tree, the plugin must offer a way to display the structure of a policy of an encrypted file (by parsing the sss-stanza) with unique IDs. The IDs are assigned as unique positive integers to each leaf.

## Encryption

1. Split the file key into `n` key shares with a threshold of `t` using the recipient policy.
2. For each share item in the policy:
  1. If the item is a policy: Recursive application of this routine using the key share as the file key.
  2. If the item is a recipient:
      - Split the byte of the X coordinate off the key share and store it in the dedicated field.
      - Encrypt the key share (without the X byte) with the recipient.
      - Store the resulting stanza wrapping the key share in the dedicated field.

## Decryption

1. Sort identities by type, i.e., by expected amount of user interactions (ascending): `X25519`, `<any unmentioned types>`, `plugin`,`password`.
1. For each identity in the sorted list:
  - Try unwrapping a key share in the stanza:
    - If a fixed share ID exists: find this leaf in the tree and try unwrap it.
    - Otherwise:
      - If the identity type is `X25519`: try all `X25519` stanzas that have not been unwrapped.
      - If the identity type is `Scrypt`: ask for the password, then try all unwrapped `Scrypt` stanzas.
      - If it's a plugin identity:
        - If there is exactly one stanza type matching the plugin's name in the policy: try unwrapping this one.
        - Otherwise, ask the user which stanza to unwrap with this identity interactively.
  - Try recovery of the key, return if possible.

## References

[1] ["How to Share a Secret" (Adi Shamir, MIT 1979)](https://web.mit.edu/6.857/OldStuff/Fall03/ref/Shamir-HowToShareASecret.pdf)

[2] [Hashicorp Vault's SSS implementation (licensed MPL-2.0)](https://github.com/hashicorp/vault/blob/1c04c8ab627f7e00c93ae5b623fc86efd4b028fa/shamir/shamir.go#L139)

[3] ["SSS PIN" of the encryption tool clevis](https://github.com/latchset/clevis?tab=readme-ov-file#pin-shamir-secret-sharing).
