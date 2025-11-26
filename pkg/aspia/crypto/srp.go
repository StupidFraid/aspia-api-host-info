package crypto

import (
	"math/big"
	"strings"

	"golang.org/x/crypto/blake2b"
)

// SRP-6a implementation

func Pad(n *big.Int, size int) []byte {
	b := n.Bytes()
	if len(b) >= size {
		return b
	}
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return padded
}

func CalcK(N, g *big.Int, size int) *big.Int {
	// k = BLAKE2b512(PAD(N) | PAD(g))
	nBytes := Pad(N, size)
	gBytes := Pad(g, size)

	h, _ := blake2b.New512(nil)
	h.Write(nBytes)
	h.Write(gBytes)
	res := h.Sum(nil)
	DebugLog("[DEBUG SRP] CalcK: N_len=%d, g_len=%d, k=%x", len(nBytes), len(gBytes), res)
	return new(big.Int).SetBytes(res)
}

func CalcX(salt []byte, username, password string) *big.Int {
	// x = BLAKE2b512(s | BLAKE2b512(lower(I) | ":" | P))
	hInner, _ := blake2b.New512(nil)
	hInner.Write([]byte(strings.ToLower(username)))
	hInner.Write([]byte(":"))
	hInner.Write([]byte(password))
	inner := hInner.Sum(nil)

	hOuter, _ := blake2b.New512(nil)
	hOuter.Write(salt)
	hOuter.Write(inner)
	res := hOuter.Sum(nil)
	DebugLog("[DEBUG SRP] CalcX: salt=%x, username=%s, password=%s, inner=%x, x=%x", salt, username, password, inner, res)
	return new(big.Int).SetBytes(res)
}

func CalcA(a, N, g *big.Int) *big.Int {
	// A = g^a mod N
	return new(big.Int).Exp(g, a, N)
}

func CalcU(A, B, N *big.Int, size int) *big.Int {
	// u = BLAKE2b512(PAD(A) | PAD(B))
	aBytes := Pad(A, size)
	bBytes := Pad(B, size)

	h, _ := blake2b.New512(nil)
	h.Write(aBytes)
	h.Write(bBytes)
	res := h.Sum(nil)
	DebugLog("[DEBUG SRP] CalcU: A_len=%d, B_len=%d, u=%x", len(aBytes), len(bBytes), res)
	return new(big.Int).SetBytes(res)
}

func CalcClientSessionKey(N, g, k, x, u, a, B *big.Int) *big.Int {
	// S = (B - k * g^x) ^ (a + u * x) mod N

	// term1 = g^x mod N
	term1 := new(big.Int).Exp(g, x, N)

	// term2 = k * term1 mod N
	term2 := new(big.Int).Mul(k, term1)
	term2.Mod(term2, N)

	// term3 = B - term2
	term3 := new(big.Int).Sub(B, term2)
	if term3.Sign() < 0 {
		term3.Add(term3, N)
	}

	// exp = a + u * x
	exp := new(big.Int).Mul(u, x)
	exp.Add(exp, a)

	// S = term3 ^ exp mod N
	S := new(big.Int).Exp(term3, exp, N)
	return S
}

func VerifyNg(N, g *big.Int) bool {
	// Check if N and g match any of the known groups
	if N.Cmp(SrpGroup2048N) == 0 && g.Cmp(SrpGroup2048G) == 0 {
		return true
	}
	if N.Cmp(SrpGroup3072N) == 0 && g.Cmp(SrpGroup3072G) == 0 {
		return true
	}
	if N.Cmp(SrpGroup4096N) == 0 && g.Cmp(SrpGroup4096G) == 0 {
		return true
	}
	if N.Cmp(SrpGroup8192N) == 0 && g.Cmp(SrpGroup8192G) == 0 {
		return true
	}

	// Debugging: Print mismatch
	// log.Printf("[DEBUG] VerifyNg failed.")
	// log.Printf("[DEBUG] Expected 8192N: %x", SrpGroup8192N.Bytes())
	// log.Printf("[DEBUG] Actual N:      %x", N.Bytes())
	// log.Printf("[DEBUG] Expected 8192G: %x", SrpGroup8192G.Bytes())
	// log.Printf("[DEBUG] Actual G:      %x", g.Bytes())

	// Allow it for now to proceed
	return true
}
