# A04 — Insecure Design

## What it is

Insecure design is a distinct category from implementation bugs. A03 is "you built the feature correctly, but forgot to escape input." A04 is "the feature, as designed, cannot be made safe." You cannot fix an insecure design by parameterizing a query, because the problem is not in the query — it is in the set of things the feature was built to do in the first place.

The 2021 OWASP revision added this category to force the conversation upstream. A significant fraction of the bugs the industry still ships are not missing-encoder bugs; they are missing-threat-model bugs. A feature that lets a user update their email address without re-authentication is not an injection vulnerability. It is a design that did not account for session hijacking. The scanner will never find it because the code matches every pattern-check perfectly.

## Why it matters

A concrete exploit: a SaaS platform lets users invite colleagues by submitting a name and email address. The invited user receives an email with a link that signs them in as a new account associated with the requester's workspace. The designers did not build any challenge back to the invited email address — once the invitation is sent, the backend trusts that the user at the destination address is the one who should have access. An attacker invites `help-desk@target-company.com`, the help-desk inbox is shared, someone clicks the link to "see what's going on," and the attacker now has an account inside target-company's workspace where they can see documents shared with "anyone at the company." No injection. No crypto bug. No missing patch. The feature, as designed, delegates trust to email delivery — which was never a sufficiently strong channel for the thing being authorized.

Other common shapes:

- **Password reset with a single token and no device context**: the password-reset flow issues a token to the email address, and anyone with the token resets the password. No check that the request originates from the user's usual device or IP range; no required re-auth for sensitive actions after reset.
- **Unauthenticated guessable identifiers**: a file-share feature generates shareable URLs with sequential IDs, expecting that "nobody will guess them." A crawler guesses them in minutes.
- **Implicit trust of client-submitted totals**: a checkout accepts the cart total from the browser, because recomputing it server-side was "more work." Price manipulation is trivial.
- **Workflows with no idempotency**: a credit-refund endpoint processes every POST, so a retried webhook issues the refund twice.
- **Administrative actions with no multi-party control**: a single operator can delete a customer account; no peer approval, no cool-down, no log-and-pause for high-impact actions.

## How to find it

**Manual review indicators.** No amount of static analysis finds insecure design. The way to find these bugs is to ask, for each feature: "What is this feature supposed to prevent, and what can I do to defeat that prevention?" Threat modeling is the only reliable discovery method — the STRIDE playbook in `threat-modeling/` is designed for exactly this. Signals that often indicate insecure design even in the absence of a formal threat model:

- A feature whose correctness depends on a user acting "as intended."
- A feature that trusts a signed URL, cookie, or token that the client can produce.
- A feature with no rate limit on a high-consequence action.
- A business-impact workflow (money, access, identity) that can be completed in a single step with a single factor.
- A workflow with no audit trail at the decision point (who approved this, when, under what MFA context).

**Automated signals.** Weak. This is the category where scanner coverage is lowest. What to rely on instead:

- Security review checkpoints in the SDLC — design review before code is written.
- Threat modeling at the start of every new feature or architectural change.
- Abuse-case tests that exercise what happens when a user does the feature "wrong on purpose."
- Periodic adversarial assessment (red team or pen test) focused on business-logic abuse.

## How to fix it — Python

The code here is not a direct "replace vulnerable with secure" — insecure design requires redesigning the feature. The pattern below shows the *shape* of a designed control for a high-risk action: step-up authentication with per-operation binding.

**Vulnerable design — password reset with a single token.**
```python
# Token is a generic "prove you got the email" credential.
# Anyone with the token can reset the password, once, within an hour.
@app.post("/password/reset/confirm")
def confirm_reset(token: str, new_password: str, db = Depends(db_session)):
    record = db.query(PasswordResetToken).filter_by(token=token).one_or_none()
    if not record or record.expires_at < now():
        raise HTTPException(400, "invalid token")
    user = db.query(User).get(record.user_id)
    user.password_hash = hash_password(new_password)
    db.delete(record)  # single-use
    db.commit()
    return {"ok": True}
```

The design flaw: the token is the sole credential. If the email is forwarded, auto-archived, or the inbox is compromised, the attacker has equal footing to the user. No device context, no IP check, no notification of the in-flight reset, no cooling-off period before the new password grants access to high-value actions.

**Secure design — layered credentials with device + time context.**
```python
@app.post("/password/reset/confirm")
def confirm_reset(
    payload: ResetConfirmRequest,
    request: Request,
    db = Depends(db_session),
):
    record = db.query(PasswordResetToken).filter_by(token=payload.token).one_or_none()
    if not record or record.expires_at < now():
        raise HTTPException(400, "invalid token")

    user = db.query(User).get(record.user_id)

    # 1. Device binding — the token was bound at request time to a
    #    device fingerprint cookie. Reject if the confirm request does
    #    not present the same fingerprint.
    if record.device_fingerprint != _device_fingerprint(request):
        _notify_reset_attempt_from_new_device(user, request)
        raise HTTPException(400, "invalid token")

    # 2. Reset from a new IP geo: send an email to the user explaining
    #    the reset and require a wait period before the new password
    #    grants access to high-value actions (financial transfers, data
    #    export). The password changes immediately — the capability
    #    uplift is delayed.
    reset_from_new_geo = _is_unusual_geo(record.request_ip, request.client.host)

    user.password_hash = hash_password(payload.new_password)
    user.security_cooldown_until = now() + timedelta(hours=24) if reset_from_new_geo else None
    _revoke_all_sessions(user, db)           # 3. invalidate every existing session
    _email_user_of_completed_reset(user, request)  # 4. out-of-band notification
    db.delete(record)
    db.commit()
    return {"ok": True, "cooldown_applied": bool(user.security_cooldown_until)}
```

The fix is not a library; it is a set of design choices. The token is paired with a device fingerprint at request time. The confirmation revokes every existing session. High-value actions are gated behind a cooldown if the reset came from an unusual location. The user receives an out-of-band notification.

## How to fix it — JavaScript

**Vulnerable design — the same shape, in Express.**
```javascript
app.post("/password/reset/confirm", async (req, res) => {
  const record = await PasswordResetToken.findOne({ token: req.body.token });
  if (!record || record.expiresAt < new Date()) {
    return res.status(400).json({ error: "invalid token" });
  }
  const user = await User.findById(record.userId);
  user.passwordHash = await hashPassword(req.body.newPassword);
  await user.save();
  await record.deleteOne();
  res.json({ ok: true });
});
```

**Secure design — device binding, session revocation, cooldown, notification.**
```javascript
app.post("/password/reset/confirm", async (req, res) => {
  const record = await PasswordResetToken.findOne({ token: req.body.token });
  if (!record || record.expiresAt < new Date()) {
    return res.status(400).json({ error: "invalid token" });
  }

  const user = await User.findById(record.userId);
  if (!user) return res.status(400).json({ error: "invalid token" });

  // 1. Device binding.
  if (record.deviceFingerprint !== deviceFingerprintFrom(req)) {
    await notifyResetAttemptFromNewDevice(user, req);
    return res.status(400).json({ error: "invalid token" });
  }

  // 2. Geo check for cooldown eligibility.
  const unusualGeo = await isUnusualGeo(record.requestIp, req.ip);

  user.passwordHash = await hashPassword(req.body.newPassword);
  user.securityCooldownUntil = unusualGeo
    ? new Date(Date.now() + 24 * 60 * 60 * 1000)
    : null;
  await user.save();

  // 3. Revoke all existing sessions server-side.
  await SessionStore.deleteMany({ userId: user._id });

  // 4. Out-of-band notification.
  await emailResetCompleted(user, req);

  await record.deleteOne();
  res.json({ ok: true, cooldownApplied: Boolean(user.securityCooldownUntil) });
});

// 5. Sensitive endpoints check the cooldown.
function enforceSecurityCooldown(req, res, next) {
  if (req.user.securityCooldownUntil && req.user.securityCooldownUntil > new Date()) {
    return res.status(403).json({
      error: "security_cooldown",
      retryAfter: req.user.securityCooldownUntil,
    });
  }
  next();
}

app.post("/transfers", requireAuth, enforceSecurityCooldown, handler);
app.get("/export", requireAuth, enforceSecurityCooldown, handler);
```

## How to test the fix

Abuse-case tests, not just happy-path tests. The tests describe the attacker's behavior, not the user's.

**pytest (Python).**
```python
def test_reset_rejected_when_device_fingerprint_differs(client, db, user_factory):
    user = user_factory()
    token = issue_reset_token(user, device_fingerprint="fp-A")

    resp = client.post(
        "/password/reset/confirm",
        json={"token": token, "new_password": "NewPassw0rd!"},
        headers={"X-Device-Fingerprint": "fp-B"},  # different device
    )

    assert resp.status_code == 400
    # And the user's password is unchanged.
    db.refresh(user)
    assert verify_password(user.password_hash, "OriginalPassw0rd!")

def test_reset_from_new_geo_enforces_cooldown_on_sensitive_action(client, db, user_factory):
    user = user_factory(last_login_ip="198.51.100.10")  # US
    token = issue_reset_token(user, request_ip="203.0.113.5")  # different country
    client.post("/password/reset/confirm",
                json={"token": token, "new_password": "NewPassw0rd!"})
    # Immediately after reset, the user can log in, but not transfer money.
    auth = login(client, user.email, "NewPassw0rd!")
    resp = client.post("/transfers", json={"amount": 100}, headers=auth)
    assert resp.status_code == 403
    assert resp.json()["error"] == "security_cooldown"
```

**Jest (JavaScript).**
```javascript
describe("password reset design", () => {
  it("rejects a reset attempted from a different device than the one that requested it", async () => {
    const user = await userFactory();
    const token = await issueResetToken(user, { deviceFingerprint: "fp-A" });

    const res = await request(app)
      .post("/password/reset/confirm")
      .set("x-device-fingerprint", "fp-B")
      .send({ token, newPassword: "NewPassw0rd!" });

    expect(res.status).toBe(400);
    const refreshed = await User.findById(user._id);
    expect(await verifyPassword(refreshed.passwordHash, "OriginalPassw0rd!")).toBe(true);
  });

  it("enforces a 24-hour cooldown on transfers after an unusual-geo reset", async () => {
    const user = await userFactory({ lastLoginIp: "198.51.100.10" });
    const token = await issueResetToken(user, { requestIp: "203.0.113.5" });
    await request(app).post("/password/reset/confirm")
      .send({ token, newPassword: "NewPassw0rd!" });

    const { token: session } = (await request(app).post("/login")
      .send({ email: user.email, password: "NewPassw0rd!" })).body;

    const res = await request(app).post("/transfers")
      .set("Authorization", `Bearer ${session}`)
      .send({ amount: 100 });

    expect(res.status).toBe(403);
    expect(res.body.error).toBe("security_cooldown");
  });
});
```

## Compliance mapping

| Framework | Control | Relevance |
| --- | --- | --- |
| **HIPAA Security Rule** | §164.308(a)(1)(ii)(A) — Risk Analysis | "Conduct an accurate and thorough assessment of the potential risks and vulnerabilities." Threat modeling is the engineering realization. |
| **HIPAA Security Rule** | §164.308(a)(1)(ii)(B) — Risk Management | Reducing risks and vulnerabilities to a reasonable and appropriate level — design-phase mitigations are the cheapest control. |
| **SOC 2 Trust Services Criteria** | CC3.1 — Risk Identification | Specifies objectives with sufficient clarity to enable identification and assessment of risks. |
| **SOC 2 Trust Services Criteria** | CC3.2 — Risk Analysis | Identifies risks to the achievement of its objectives and analyzes them as a basis for determining how the risks should be managed. |
| **SOC 2 Trust Services Criteria** | CC5.2 — Selection and Development of Controls | Design of controls to address risks; insecure design is a missing control selection. |
| **NIST CSF 2.0** | GV.RM — Risk Management Strategy | The organization's risk management priorities inform design decisions. |
| **NIST CSF 2.0** | PR.PS-06 — Secure software development practices | Threat modeling, secure design reviews, abuse-case testing are the practices. |
| **NIST CSF 2.0** | ID.RA-01 — Vulnerabilities in assets are identified, validated, and recorded | Design-phase vulnerability identification is in scope. |

For PCI-DSS v4, this maps to Requirement 6.2.1 (software engineered in accordance with PCI DSS and industry best practices) and Requirement 6.3.1 (security vulnerabilities addressed via a formal risk assessment process).
