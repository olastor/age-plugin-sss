# age-plugin-sss

⚠️ Consider this plugin to be experimental until the version v1.0.0 is published! ⚠️

---

:scissors: Split encryption keys and encrypt key shares with different [age](https://github.com/FiloSottile/age) (licensed BSD 3-Clause) recipients.

:memo: Create (complex) policies about how which combinations of identites can decrypt the file.

:pushpin: Uses Hashicorp Vault's [implementation](https://github.com/hashicorp/vault/blob/main/shamir/shamir.go) of Shamir's Secret Sharing (licensed MPL-2.0).

---

## Installation

### Build from source

Run

```bash
go build -v ./cmd/...
```
and copy `age-plugin-sss` to a directory of your `$PATH`.
