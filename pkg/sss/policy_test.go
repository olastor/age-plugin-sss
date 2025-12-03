package sss

import (
	cryptoRand "crypto/rand"
	"math/rand"
	"reflect"

	"filippo.io/age"

	"testing"
)

type TestPolicy struct {
	Threshold int
	Shares    []*TestPolicy
	Identity  *age.X25519Identity
}

func testPolicyToRealPolicy(testPolicy *TestPolicy) *SSS {
	sss := &SSS{}

	if testPolicy.Identity != nil {
		sss.Recipient = testPolicy.Identity.Recipient().String()
		return sss
	}

	sss.Threshold = testPolicy.Threshold
	for _, t := range testPolicy.Shares {
		sss.Shares = append(sss.Shares, testPolicyToRealPolicy(t))
	}

	return sss
}

const (
	SELECT_ALL = iota
	SELECT_MIN
	SELECT_SUFFICIENT
	SELECT_INSUFFICIENT
)

func selectIdentities(node *TestPolicy, rng *rand.Rand, mode int) []*age.X25519Identity {
	if node.Threshold == 0 {
		return []*age.X25519Identity{node.Identity}
	}

	result := []*age.X25519Identity{}
	var maxCount int
	switch mode {
	case SELECT_ALL:
		maxCount = len(node.Shares)
	case SELECT_MIN:
		maxCount = node.Threshold
	case SELECT_SUFFICIENT:
		maxCount = max(rng.Intn(len(node.Shares)+1), node.Threshold)
	case SELECT_INSUFFICIENT:
		maxCount = rng.Intn(node.Threshold)
	default:
		panic("unknown mode")
	}

	selectedCount := 0

	for _, i := range rand.Perm(len(node.Shares))[0:maxCount] {
		result = append(result, selectIdentities(node.Shares[i], rng, mode)...)
		selectedCount += 1
	}

	return result
}

func testPolicyToIdentity(rng *rand.Rand, testPolicy *TestPolicy, mode int) *SSSIdentity {
	identities := []*age.X25519Identity{}

	var pickIdentities = func(node *TestPolicy) {
		if node.Threshold == 0 {
			identities = append(identities, node.Identity)
			return
		}

		identities = append(identities, selectIdentities(node, rng, mode)...)
	}

	pickIdentities(testPolicy)

	sssIdentity := &SSSIdentity{
		Identities: []*SSSIdentityItem{},
	}

	for _, id := range identities {
		sssIdentity.Identities = append(sssIdentity.Identities, &SSSIdentityItem{
			IdentityStr: id.String(),
			Identity:    id,
		})
	}

	return sssIdentity
}

const MAX_DEPTH = 5

func generateRandomTestPolicy(rng *rand.Rand, maxBranching, currentDepth int) *TestPolicy {
	node := &TestPolicy{}

	var numChildren int
	if currentDepth == 0 {
		// root must have at least one child
		numChildren = max(1, rng.Intn(maxBranching+1))
	} else if currentDepth >= MAX_DEPTH {
		numChildren = 0
	} else {
		numChildren = rng.Intn(maxBranching + 1)
	}

	for i := 0; i < numChildren; i++ {
		child := generateRandomTestPolicy(rng, maxBranching, currentDepth+1)
		if child != nil {
			node.Shares = append(node.Shares, child)
		}
	}

	if len(node.Shares) == 0 {
		node.Identity, _ = age.GenerateX25519Identity()
		return node
	}

	node.Threshold = rng.Intn(len(node.Shares)) + 1
	return node
}

func FuzzRandomPolicies(f *testing.F) {
	f.Fuzz(func(t *testing.T, seed int64) {
		rng := rand.New(rand.NewSource(seed))
		testPolicy := generateRandomTestPolicy(rng, 5, 0)
		policy := testPolicyToRealPolicy(testPolicy)

		validIdentities := []*SSSIdentity{
			testPolicyToIdentity(rng, testPolicy, SELECT_ALL),
			testPolicyToIdentity(rng, testPolicy, SELECT_MIN),
			testPolicyToIdentity(rng, testPolicy, SELECT_SUFFICIENT),
		}
		invalidIdentity := testPolicyToIdentity(rng, testPolicy, SELECT_INSUFFICIENT)

		fileKey := make([]byte, 16)
		if _, err := cryptoRand.Read(fileKey); err != nil {
			t.Error(err)
		}
		stanzas, err := policy.Wrap(fileKey)
		if err != nil {
			t.Error(err)
		}

		for _, id := range validIdentities {
			unwrapped, err := id.Unwrap(stanzas)
			if err != nil {
				t.Error(err)
			}
			if !reflect.DeepEqual(fileKey, unwrapped) {
				t.Logf("fileKey: %v, unwrapped: %v\n", fileKey, unwrapped)
				t.Error("File keys do not match")
			}
		}

		unwrapped, err := invalidIdentity.Unwrap(stanzas)
		if err.Error() != "incorrect identity for recipient block" {
			t.Error(err)
		}
		if reflect.DeepEqual(fileKey, unwrapped) {
			t.Logf("fileKey: %v, unwrapped: %v\n", fileKey, unwrapped)
			t.Error("File keys should not match")
		}
	})
}
