Terminology
===
 - **Card**: member card
 - **Programmer**: device that sets up cards
 - **Controller**: device that checks card access to a physical object, e.g. door, machinery, etc.
 - **Deploy**: process of setting up a card for the first time
 - **Enrollment**: process of setting up a controller for the first time
 - **Encrypted (file)**: a file which is encrypted on the card in the Mifare sense, i.e. the file can only be accessed with
   a symmetric key and is not clonable.
 - **Simple Authentication**: authentication using the root key of the card, which is derived from the card UID.
 - **Secure Channel**: secure communication channel, where data is encrypted to the recipient and signed by the sender
   using asymmetric crypto.
 - **Deploy Certificate**: a certificate consisting of at least CONTROLLER_ID, UID and USERNAME expressing the intent to
   deploy a Card identified by UID for user USERNAME at Controller CONTROLLER_ID. Trasmitted through Secure Channel.
 - **Master Key**: key that allows to access and edit the card. This is derived from the card UID



 - **UID**: unique ID of the card, provided by the manufacturer
 - **USERNAME**: identifier of the user associated to the card

 - **K_UID**: secret shared between Controllers and Programmer, generated by the Programmer at first Deploy. Used to
   validate UID.
 - **SALT_UID**: salt written on the card at the first Deploy. Used to validate UID; the purpose is to prevent spoofing
   cards that have not been seen by the attacker even if the Controller is compromised.
 - **ANTISPOOF_ENC_FILE**: file encrypted with `KDF(UID|K_UID|SALT_UID)` on the card, containing UID. Used to prevent
   spoofing of the card UID.
 - **ANTISPOOF_SALT_FILE**: file readable upon Simple Authentication that contains a salt unique to each card set up by the
   Programmer upon first Deploy. Used to prevent that a compromised Controller is able to spoof every card.
 - **ANTISPOOF_APP**: app on the card used for validating the UID of the card.

 - **K_CONTROLLER**: secret known only to the controller, generated upon Enrollment.
 - **CONTROLLER_APP**: app on the card used for authenticating the card at a given Controller.
 - **CONTROLLER_ENC_FILE**: file encrypted with `KDF(UID|K_CONTROLLER)` on the card, containing USERNAME. Generated by the
   Controller upon first attempted access, if a Deploy Certificate is present.

Card layout
===
Master Key: `KDF(UID)`.
  - App ANTISPOOF_APP: readonly
    - ANTISPOOF_SALT_FILE: contains SALT_UID, readonly, publicly readable using the Master Key
    - ANTISPOOF_ENC_FILE: contains UID, readonly, encrypted with `KDF(UID|K_UID|SALT_UID)`
  - App CONTROLLER_APP: readonly, one for each Controller
    - CONTROLLER_ENC_FILE: contains USERNAME, read-write, encrypted with `KDF(UID|K_CONTROLLER)`


First Deploy (actor: Programmer)
===
  1. Format Card
  2. Setup Master Key `KDF(UID)`
  3. Run Anti-spoof Deploy

Controller Deploy (actor: Programmer)
===
  1. Run Anti-spoof test
  2. Generate a Deploy Certificate `CONTROLLER_ID|UID|USERNAME|nonce|expiration_date`
  3. Deliver the Deploy Certificate to the Controller via Secure Channel


Card Deploy (actor: Controller)
===
  1. Run Anti-spoof test
  2. Perform Simple authentication to ensure the session is encrypted.
  3. Retrieve a Deploy Certificate for this UID: `CONTROLLER_ID|UID|USERNAME|nonce|expiration_date`
  4. Verify `nonce` and `expiration_date`
  5. Create CONTROLLER_APP for CONTROLLER_ID and inside CONTROLLER_ENC_FILE.
  6. Derive `K:=KDF(UID|K_CONTROLLER)`, and encrypt USERNAME in CONTROLLER_ENC_FILE using K.
  7. Set CONTROLLER_ENC_FILE to be accessible only with K

Attempted access (actor: Controller):
===
  1. Run Anti-spoof test
  2. Perform Simple authentication to ensure the session is encrypted.
  3. If CONTROLLER_APP does not exist: if a Deploy Certificate for UID exists, run Card Deploy
  4. If CONTROLLER_APP exists, derive `K:=KDF(UID|K_CONTROLLER)`
  5. Read USERNAME from CONTROLLER_ENC_FILE.
  6. Verify if the triple (USERNAME, UID, CONTROLLER_ID) is allowed

Enrollment (actor: Programmer)
===
  1. Retrieve the public key of the Controller
  2. Send the public key of the Programmer together with a unique CONTROLLER_ID
  3. Run Anti-spoof Enrollment.

Enrollment (actor: Controller)
===
  1. Send the public key to the Programmer
  2. Retrieve the public key of the Programmer and the CONTROLLER_ID
  3. Receive `UID|K_UID` pairs from the Programmer

Anti-spoof
===

The anti-spoof process checks that the Card provided is the same as the one offered at deploy time.
To do so, accesses an encrypted file on the Card using a key which is derived from the following parts:
  1. the Card UID
  2. a pre-shared secret K_UID associated to the Card UID, which is known by the Programmer and the Controller
  3. a public salt SALT_UID, written to the Card by the Programmer and readable with Simple Authentication
The file ANTISPOOF_ENC_FILE contains UID and is accessible only via `KDF(UID|K_UID|SALT_UID)`.

Card layout:
  - App ANTISPOOF_APP: readonly
    - ANTISPOOF_SALT_FILE: contains SALT_UID, readonly, publicly readable
    - ANTISPOOF_ENC_FILE: contains UID, readonly, encrypted with K

Stored data:
  - K_UID; generated by Programmer during Deploy, shared to Controllers via Secure Channel

The rationale is that even if a Controller compromised, and thus K_UID is known, each Card's SALT_UID has to be
retrieved in order to bypass the test. Even if that is the case, it is not possible to deploy new cards or enable new
cards unless a Deploy Certificate is forged.

Deploy (actor: Programmer)
---
  1. Perform Simple Authentication to ensure the session is encrypted.
  2. Read UID, and randomly select K_UID, SALT_UID
  3. Create ANTISPOOF_APP and inside it ANTISPOOF_ENC_FILE.
  4. Derive `K:=KDF(UID|K_UID|SALT_UID)`, and encrypt UID in ANTISPOOF_ENC_FILE.
  5. Set ANTISPOOF_ENC_FILE to be only readable with K, and not writeable by anyone.
  6. Create ANTISPOOF_SALT_FILE inside ANTISPOOF_APP.
  7. Write SALT_UID in ANTISPOOF_SALT_FILE. Make it readable with Simple Authentication and not writeable.
  8. Send `UID|K_UID` to each Controller via Secure Channel.

Enrollment (actor: Programmer)
---
  1. Send each Card's `UID|K_UID` to the new Controller.

Anti-spoof test (actor: Programmer, Controller)
---
  1. Perform Simple Authentication to ensure the session is encrypted.
  2. Read UID, retrieve K_UID
  3. Open ANTISPOOF_APP and read SALT_UID
  4. Derive `K:=KDF(UID|K_UID|SALT_UID)`
  5. Open ANTISPOOF_ENC_FILE with K.
  6. Verify that K opens ANTISPOOF_ENC_FILE and that the content is indeed UID.


"Threat analysis"
===
We assume that encrypted files in the card cannot be copied unless the key is known.
We assume that a Secure Channel exists so that the Deploy Certificate and the `UID|K_UID` pairs can be trasmitted
securily.

If we compromise a Controller, we cannot authorize cards for other Controllers, because K_CONTROLLER is not known.
We can bypass the Anti-spoof test, however, and thus induce deployment of cloned cards from other controllers.