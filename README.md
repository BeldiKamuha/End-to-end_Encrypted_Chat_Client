Short-answer Questions

	1.	Could the protocol be modified to increment the DH ratchets once every ten messages without compromising confidentiality?
	•	Modifying the protocol to update the Diffie-Hellman (DH) ratchet every ten messages instead of every message would reduce the frequency of key updates. While this may still provide some confidentiality, it reduces the protection level against future compromise since the encryption keys would remain static longer, making it easier for an attacker to compromise multiple messages if they ever obtain a DH key.
	2.	What if Alice and Bob never update their DH keys at all? Explain the security consequences.
	•	If Alice and Bob never update their DH keys, they lose the benefits of Forward Secrecy and Break-in Recovery. Forward secrecy ensures that past messages remain secure even if future keys are compromised. Without DH updates, all messages would be vulnerable if one key were compromised. Additionally, break-in recovery allows participants to regain security after a compromise, but without DH updates, there would be no way to refresh security.
	3.	In the given conversation, what is the length of the longest sending chain used by Alice? By Bob? Explain.
	•	The longest sending chain length for Alice is 3 (since she sends three consecutive messages without receiving a message from Bob). For Bob, the longest sending chain length is 1, as he only sends a single message between receiving messages from Alice. The sending chain increments with each consecutive message sent by the same participant.
	4.	If Mallory compromises Alice’s phone just before her third message, why can’t she determine the locker combination?
	•	Forward Secrecy is the relevant security property here. Double Ratchet ensures that previous keys are discarded after each message, preventing Mallory from decrypting earlier messages, such as the one containing the locker combination, even though she compromised Alice’s device and obtained current keys. This property protects past communications despite future compromises.
	5.	Why might the government surveillance method be flawed and less effective than intended?
	•	The government surveillance method is flawed because it requires access to private session keys for monitoring. This approach risks exposing sensitive information and violates user privacy. Additionally, it poses significant security risks, as a compromised government key would endanger the confidentiality of all monitored sessions.
	6.	Comparison of ECDSA and RSA for signature generation in SubtleCrypto:
	•	(a) Key Generation Time: RSA keys generally take longer to generate than ECDSA keys, as RSA involves generating large prime numbers.
	•	(b) Signature Generation Time: RSA signatures typically take longer to generate than ECDSA due to the complexity of the RSA signing algorithm.
	•	(c) Signature Length: RSA signatures are usually longer than ECDSA signatures for equivalent security levels, as RSA keys require a larger bit size.
	•	(d) Verification Time: RSA signatures generally take longer to verify than ECDSA, as ECDSA is optimized for faster verification.
