// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

// WHETHER THE CODE LEFT THE BUILDING, kept here rather than inferred anywhere else.
//
// The engine mints a code, hashes it onto the challenge and hands the plaintext to the external
// outbox. Everything after that happens in another process: the forward-dispatcher drains the outbox
// and offers each item to the text-adapter, which offers it to a carrier. When that fails the
// dispatcher retries, and when it stops retrying the item was simply DELETED — so the login the item
// belonged to was left in the only state it had, "a challenge exists", which is also the state of a
// login whose code is sitting on somebody's phone. The browser said "we sent a code" and meant it
// about a code that was given up on a minute earlier.
//
// The verdict therefore lives on the challenge, where the authority already is: the dispatcher
// REPORTS an outcome over the trusted hub and Go decides what to store. Three states and no more —
// pending, sent, failed — because that is the whole of what a waiting client can act on.
//
// WHAT CROSSES THE WIRE IS THE STATE ALONE. DeliveryError and DeliveryTries are written for an
// operator reading the store, and handleMfaDelivery does not return them: "the provider has no
// credentials" is a fact about this deployment, and the caller holding a challenge is not the party
// it is owed to.
const (
	// deliveryPending is the ZERO VALUE on purpose. Every challenge written before this existed, and
	// every one written since by a path that does not know about delivery, reads as pending — which
	// is true of them, and is the safe direction for the reader to be wrong in.
	deliveryPending = ""
	deliverySent    = "sent"
	deliveryFailed  = "failed"
	// deliveryPendingWire is what pending is CALLED on the wire. An empty string would make a client
	// distinguish "pending" from "the field is missing", and those are the same thing here.
	deliveryPendingWire = "pending"
)

// deliveryErrorClass narrows a reported failure class to the closed vocabulary the text-adapter
// already speaks (backend/textadapter/errors.py's ERROR_CLASSES) plus "unreachable", which is the
// dispatcher's own word for an adapter that did not answer at all. Anything else becomes "other",
// exactly as AdapterError coerces an unknown class, so a caller cannot write arbitrary text into the
// state file through the hub. The empty class stays empty: a success reports no class.
func deliveryErrorClass(class string) string {
	switch class {
	case "":
		return ""
	case "auth", "bad_request", "rate_limit", "timeout", "provider_5xx", "unreachable":
		return class
	default:
		return "other"
	}
}

// markChallengeDelivery stamps a verdict on the challenge an outbound item belonged to, and reports
// whether there was one to stamp. It is called INSIDE the exclusive hold by the hub's outbound ops,
// so the verdict and the item's removal are one durable snapshot — the same discipline
// enqueueOutboundMFA follows on the way in.
//
// A missing challenge is not an error: an item may outlive its challenge (an expiry sweep, a
// completed verification racing a give-up), and in that case there is nothing left to tell.
func (s *Server) markChallengeDelivery(challengeID, delivery, errorClass string, attempts int) bool {
	if challengeID == "" || s.forest.MFAChallenges == nil {
		return false
	}
	challenge, found := s.forest.MFAChallenges[challengeID]
	if !found {
		return false
	}
	challenge.Delivery = delivery
	challenge.DeliveryError = deliveryErrorClass(errorClass)
	challenge.DeliveryTries = attempts
	challenge.DeliveryAt = time.Now().Unix()
	s.forest.MFAChallenges[challengeID] = challenge
	return true
}

// clearChallengeDelivery returns a challenge to pending. A resend puts a NEW code on the outbox, and
// the old code's verdict says nothing about it — left in place, a client polling after a successful
// resend would read the previous failure and conclude the resend had failed too.
func clearChallengeDelivery(challenge *core.MFAChallenge) {
	challenge.Delivery = deliveryPending
	challenge.DeliveryError = ""
	challenge.DeliveryTries = 0
	challenge.DeliveryAt = 0
}

// challengeDelivery answers the delivery state behind an mfa_pending bearer.
//
// IT IS A READ AND ONLY A READ. A client polls this while it waits, so a changeForest here would
// make every poll a full serialize-and-flush of the forest; an expired challenge is therefore
// reported, not swept — the sweeps in beginMFAChallenge and consumeMFAChallenge already own that.
func (s *Server) challengeDelivery(challengeToken string) (string, error) {
	claims, err := s.parseMFAChallengeToken(challengeToken)
	if err != nil {
		return "", err
	}
	state := deliveryPending
	var outcome *apiError
	s.readForest(func() {
		challenge, found := s.forest.MFAChallenges[claims.ChallengeID]
		if !found || challenge.ExpiresAt <= time.Now().Unix() {
			// THE SAME SENTENCE the verify path answers an unknown challenge with. A distinct one
			// here would turn this route into an oracle for which challenge ids are live.
			outcome = apiErrorf(http.StatusUnauthorized, "Invalid or expired challenge")
			return
		}
		state = challenge.Delivery
	})
	if outcome != nil {
		return "", outcome
	}
	if state == deliveryPending {
		return deliveryPendingWire, nil
	}
	return state, nil
}

// handleMfaDelivery is POST /mfa/delivery: has the code for this challenge gone out yet?
//
// Public for the reason /mfa/verify and /mfa/start are — the caller holds a challenge and no session,
// and the challenge is the credential it presents. POST rather than GET because the bearer travels
// in the body: a challenge in a query string is a credential in a referrer header and an access log.
//
// IT SPENDS NO GUESS AND CANNOT. There is no code in the request, so nothing here touches
// MFAChallenge.Attempts and no lockout can be driven from it — which is what lets a client poll it.
//
// It does NOT call logger.Enter/Exit. Every other handler does, and every other handler is called
// once per user action; this one is called on a timer while somebody waits for a text, and a
// BEGIN/END pair every two seconds would bury the log the give-up warning is written to.
func (s *Server) handleMfaDelivery(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Challenge string `json:"challenge"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	state, err := s.challengeDelivery(input.Challenge)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	// mfa_required rides along so the answer is the same family as /login's challenge and
	// /mfa/start's resend, and a client can read one field to know it is still mid-exchange.
	json.NewEncoder(w).Encode(map[string]interface{}{"mfa_required": true, "delivery": state})
}
