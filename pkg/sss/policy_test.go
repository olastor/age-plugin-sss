package sss

import (
	cryptoRand "crypto/rand"
	"math/rand"
	"reflect"
	"slices"

	"filippo.io/age"

	"testing"
)

type TestPolicy struct {
	Threshold int
	Shares    []*TestPolicy
	Identity  *age.X25519Identity
}

// testRecipientInfo holds both classic and PQ recipient/identity for a leaf share
type testRecipientInfo struct {
	x25519Identity *age.X25519Identity
	hybridIdentity *age.HybridIdentity
	isPQ           bool
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

// makeRecipients generates n recipient infos, with the given indices being PQ.
func makeRecipients(t *testing.T, n int, pqIndices []int) []testRecipientInfo {
	t.Helper()
	recipients := make([]testRecipientInfo, n)
	for i := 0; i < n; i++ {
		isPQ := slices.Contains(pqIndices, i)
		if isPQ {
			id, err := age.GenerateHybridIdentity()
			if err != nil {
				t.Fatalf("GenerateHybridIdentity: %v", err)
			}
			recipients[i] = testRecipientInfo{hybridIdentity: id, isPQ: true}
		} else {
			id, err := age.GenerateX25519Identity()
			if err != nil {
				t.Fatalf("GenerateX25519Identity: %v", err)
			}
			recipients[i] = testRecipientInfo{x25519Identity: id, isPQ: false}
		}
	}
	return recipients
}

func recipientString(r testRecipientInfo) string {
	if r.isPQ {
		return r.hybridIdentity.Recipient().String()
	}
	return r.x25519Identity.Recipient().String()
}

func buildFlatPolicy(threshold int, recipients []testRecipientInfo) *SSS {
	policy := &SSS{Threshold: threshold}
	for _, r := range recipients {
		policy.Shares = append(policy.Shares, &SSS{Recipient: recipientString(r)})
	}
	return policy
}

func TestWrapWithLabels_AllClassic(t *testing.T) {
	recipients := makeRecipients(t, 3, nil)
	policy := buildFlatPolicy(2, recipients)

	fileKey := make([]byte, 16)
	cryptoRand.Read(fileKey)

	_, labels, err := policy.WrapWithLabels(fileKey)
	if err != nil {
		t.Fatalf("WrapWithLabels: %v", err)
	}
	if slices.Contains(labels, "postquantum") {
		t.Error("all-classic policy should not have postquantum label")
	}
}

func TestWrapWithLabels_AllPQ(t *testing.T) {
	recipients := makeRecipients(t, 3, []int{0, 1, 2})
	policy := buildFlatPolicy(2, recipients)

	fileKey := make([]byte, 16)
	cryptoRand.Read(fileKey)

	_, labels, err := policy.WrapWithLabels(fileKey)
	if err != nil {
		t.Fatalf("WrapWithLabels: %v", err)
	}
	if !slices.Contains(labels, "postquantum") {
		t.Error("all-PQ policy should have postquantum label")
	}
}

func TestWrapWithLabels_MixedBelowThreshold(t *testing.T) {
	// 2-of-3 with 2 PQ and 1 classic: nonPQ=1 < threshold=2 → PQ
	recipients := makeRecipients(t, 3, []int{0, 1})
	policy := buildFlatPolicy(2, recipients)

	fileKey := make([]byte, 16)
	cryptoRand.Read(fileKey)

	_, labels, err := policy.WrapWithLabels(fileKey)
	if err != nil {
		t.Fatalf("WrapWithLabels: %v", err)
	}
	if !slices.Contains(labels, "postquantum") {
		t.Error("2-of-3 with 2 PQ shares: nonPQ(1) < threshold(2), should be PQ")
	}
}

func TestWrapWithLabels_MixedAtThreshold(t *testing.T) {
	// 2-of-3 with 1 PQ and 2 classic: nonPQ=2 >= threshold=2 → not PQ
	recipients := makeRecipients(t, 3, []int{0})
	policy := buildFlatPolicy(2, recipients)

	fileKey := make([]byte, 16)
	cryptoRand.Read(fileKey)

	_, labels, err := policy.WrapWithLabels(fileKey)
	if err != nil {
		t.Fatalf("WrapWithLabels: %v", err)
	}
	if slices.Contains(labels, "postquantum") {
		t.Error("2-of-3 with 1 PQ share: nonPQ(2) >= threshold(2), should not be PQ")
	}
}

func TestWrapWithLabels_ThresholdOne(t *testing.T) {
	// 1-of-3: any single share can decrypt, so even one classic share breaks PQ.
	// Only PQ if ALL shares are PQ.

	// Mixed: not PQ
	recipients := makeRecipients(t, 3, []int{0, 1})
	policy := buildFlatPolicy(1, recipients)

	fileKey := make([]byte, 16)
	cryptoRand.Read(fileKey)

	_, labels, err := policy.WrapWithLabels(fileKey)
	if err != nil {
		t.Fatalf("WrapWithLabels: %v", err)
	}
	if slices.Contains(labels, "postquantum") {
		t.Error("1-of-3 with any classic share should not be PQ")
	}

	// All PQ: is PQ
	recipients2 := makeRecipients(t, 3, []int{0, 1, 2})
	policy2 := buildFlatPolicy(1, recipients2)

	_, labels2, err := policy2.WrapWithLabels(fileKey)
	if err != nil {
		t.Fatalf("WrapWithLabels: %v", err)
	}
	if !slices.Contains(labels2, "postquantum") {
		t.Error("1-of-3 all PQ should be PQ")
	}
}

func TestWrapWithLabels_Nested(t *testing.T) {
	// Outer: 2-of-2
	//   Share 1: PQ recipient (leaf)
	//   Share 2: inner 1-of-2 with 2 classic recipients (not PQ)
	// Outer: nonPQ=1 (the inner group) < threshold=2 → PQ

	pqId, _ := age.GenerateHybridIdentity()
	classicId1, _ := age.GenerateX25519Identity()
	classicId2, _ := age.GenerateX25519Identity()

	policy := &SSS{
		Threshold: 2,
		Shares: []*SSS{
			{Recipient: pqId.Recipient().String()},
			{
				Threshold: 1,
				Shares: []*SSS{
					{Recipient: classicId1.Recipient().String()},
					{Recipient: classicId2.Recipient().String()},
				},
			},
		},
	}

	fileKey := make([]byte, 16)
	cryptoRand.Read(fileKey)

	_, labels, err := policy.WrapWithLabels(fileKey)
	if err != nil {
		t.Fatalf("WrapWithLabels: %v", err)
	}
	if !slices.Contains(labels, "postquantum") {
		t.Error("outer 2-of-2 with 1 PQ leaf + 1 classic group: nonPQ(1) < threshold(2), should be PQ")
	}
}

func TestWrapWithLabels_NestedNotPQ(t *testing.T) {
	// Outer: 1-of-2
	//   Share 1: inner 2-of-2 with 2 PQ recipients (PQ group)
	//   Share 2: classic recipient (leaf)
	// Outer: nonPQ=1 >= threshold=1 → not PQ

	pq1, _ := age.GenerateHybridIdentity()
	pq2, _ := age.GenerateHybridIdentity()
	classicId, _ := age.GenerateX25519Identity()

	policy := &SSS{
		Threshold: 1,
		Shares: []*SSS{
			{
				Threshold: 2,
				Shares: []*SSS{
					{Recipient: pq1.Recipient().String()},
					{Recipient: pq2.Recipient().String()},
				},
			},
			{Recipient: classicId.Recipient().String()},
		},
	}

	fileKey := make([]byte, 16)
	cryptoRand.Read(fileKey)

	_, labels, err := policy.WrapWithLabels(fileKey)
	if err != nil {
		t.Fatalf("WrapWithLabels: %v", err)
	}
	if slices.Contains(labels, "postquantum") {
		t.Error("1-of-2 with PQ group + classic leaf: nonPQ(1) >= threshold(1), should not be PQ")
	}
}

func TestWrapWithLabels_NestedPQInner(t *testing.T) {
	// Outer: 1-of-2
	//   Share 1: inner 2-of-2 all PQ (PQ group)
	//   Share 2: inner 2-of-2 all PQ (PQ group)
	// Outer: nonPQ=0 < threshold=1 → PQ

	pq1, _ := age.GenerateHybridIdentity()
	pq2, _ := age.GenerateHybridIdentity()
	pq3, _ := age.GenerateHybridIdentity()
	pq4, _ := age.GenerateHybridIdentity()

	policy := &SSS{
		Threshold: 1,
		Shares: []*SSS{
			{
				Threshold: 2,
				Shares: []*SSS{
					{Recipient: pq1.Recipient().String()},
					{Recipient: pq2.Recipient().String()},
				},
			},
			{
				Threshold: 2,
				Shares: []*SSS{
					{Recipient: pq3.Recipient().String()},
					{Recipient: pq4.Recipient().String()},
				},
			},
		},
	}

	fileKey := make([]byte, 16)
	cryptoRand.Read(fileKey)

	_, labels, err := policy.WrapWithLabels(fileKey)
	if err != nil {
		t.Fatalf("WrapWithLabels: %v", err)
	}
	if !slices.Contains(labels, "postquantum") {
		t.Error("1-of-2 where both inner groups are PQ should be PQ")
	}
}

// Test that PQ recipients can actually be wrapped and unwrapped through SSS
func TestPQRoundtrip(t *testing.T) {
	pqId1, _ := age.GenerateHybridIdentity()
	pqId2, _ := age.GenerateHybridIdentity()
	pqId3, _ := age.GenerateHybridIdentity()

	policy := &SSS{
		Threshold: 2,
		Shares: []*SSS{
			{Recipient: pqId1.Recipient().String()},
			{Recipient: pqId2.Recipient().String()},
			{Recipient: pqId3.Recipient().String()},
		},
	}

	fileKey := make([]byte, 16)
	cryptoRand.Read(fileKey)

	stanzas, labels, err := policy.WrapWithLabels(fileKey)
	if err != nil {
		t.Fatalf("WrapWithLabels: %v", err)
	}
	if !slices.Contains(labels, "postquantum") {
		t.Error("all-PQ policy should have postquantum label")
	}

	// Unwrap with 2 of 3 identities
	identity := &SSSIdentity{
		Identities: []*SSSIdentityItem{
			{IdentityStr: pqId1.String(), Identity: pqId1},
			{IdentityStr: pqId2.String(), Identity: pqId2},
		},
	}

	unwrapped, err := identity.Unwrap(stanzas)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !reflect.DeepEqual(fileKey, unwrapped) {
		t.Error("round-trip file key mismatch")
	}
}

// Test mixed PQ/classic round-trip
func TestMixedPQClassicRoundtrip(t *testing.T) {
	pqId, _ := age.GenerateHybridIdentity()
	classicId, _ := age.GenerateX25519Identity()

	policy := &SSS{
		Threshold: 2,
		Shares: []*SSS{
			{Recipient: pqId.Recipient().String()},
			{Recipient: classicId.Recipient().String()},
		},
	}

	fileKey := make([]byte, 16)
	cryptoRand.Read(fileKey)

	stanzas, labels, err := policy.WrapWithLabels(fileKey)
	if err != nil {
		t.Fatalf("WrapWithLabels: %v", err)
	}
	// nonPQ=1 < threshold=2 → PQ
	if !slices.Contains(labels, "postquantum") {
		t.Error("2-of-2 with 1 PQ: should be PQ")
	}

	// Need both identities for 2-of-2
	identity := &SSSIdentity{
		Identities: []*SSSIdentityItem{
			{IdentityStr: pqId.String(), Identity: pqId},
			{IdentityStr: classicId.String(), Identity: classicId},
		},
	}

	unwrapped, err := identity.Unwrap(stanzas)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !reflect.DeepEqual(fileKey, unwrapped) {
		t.Error("round-trip file key mismatch")
	}
}
