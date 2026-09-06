package middleware

import "testing"

func TestPowRejectedWorkDoesNotChangePolicy(t *testing.T) {
	for _, kind := range []string{"unknown", "invalid", "expired", "replay"} {
		t.Run(kind, func(t *testing.T) {
			g := NewPowGuard(4)
			c, _ := g.GenerateChallenge()
			valid := PowSolution{Challenge: c.Challenge, Nonce: solveChallenge(c.Challenge, c.Difficulty)}
			if kind == "replay" && !g.Verify(valid) {
				t.Fatal("valid work rejected")
			}
			before, _ := g.GenerateChallenge()
			for i := 0; i < 60; i++ {
				sol := PowSolution{Challenge: "unknown", Nonce: "unused"}
				switch kind {
				case "invalid":
					c, _ := g.GenerateChallenge()
					sol.Challenge = c.Challenge
					for verifyLeadingZeros(sol.Challenge, sol.Nonce, c.Difficulty) {
						sol.Nonce += "x"
					}
				case "expired":
					c, _ := g.GenerateChallenge()
					c.ExpiresAt = 0
					g.pending[c.Challenge] = c
					sol.Challenge = c.Challenge
				case "replay":
					sol = valid
				}
				if g.Verify(sol) {
					t.Fatal("rejected work accepted")
				}
			}
			after, _ := g.GenerateChallenge()
			if after.Difficulty != before.Difficulty {
				t.Fatalf("rejected work raised difficulty: %d -> %d", before.Difficulty, after.Difficulty)
			}
		})
	}
}

func TestPowConsumptionEnforcesCurrentPolicy(t *testing.T) {
	g := NewPowGuard(4)
	old, _ := g.GenerateChallenge()
	// Model a policy increase independently of the client's outstanding work.
	g.baseDifficulty = 5
	nonce := solveChallenge(old.Challenge, old.Difficulty)
	for verifyLeadingZeros(old.Challenge, nonce, 5) {
		nonce += "x"
		for !verifyLeadingZeros(old.Challenge, nonce, 4) {
			nonce += "x"
		}
	}
	if g.Verify(PowSolution{Challenge: old.Challenge, Nonce: nonce}) {
		t.Fatal("work issued under superseded difficulty accepted")
	}
}

func TestPowAcceptedWorkRaisesDifficulty(t *testing.T) {
	g := NewPowGuard(4)
	for i := 0; i < 50; i++ {
		c, err := g.GenerateChallenge()
		if err != nil {
			t.Fatal(err)
		}
		if !g.Verify(PowSolution{Challenge: c.Challenge, Nonce: solveChallenge(c.Challenge, c.Difficulty)}) {
			t.Fatal("valid work rejected")
		}
	}
	c, err := g.GenerateChallenge()
	if err != nil {
		t.Fatal(err)
	}
	if c.Difficulty != 5 {
		t.Fatalf("accepted load difficulty=%d", c.Difficulty)
	}
}
