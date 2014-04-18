import OpenPGP
import OpenPGP.Crypto

key_and_sigs = OpenPGP.Message.parse(open('key').read())
key = key_and_sigs[0]

print "Verifying self-signatures on top-level key: " + key.fingerprint()
print "If no valid signatures are printed, the key's integrity is in question"

# Run verification in the presence of only the key itself,
# so all verified signatures will be self-sigs
verify = OpenPGP.Crypto.Wrapper(key)
verified_signatures = verify.verify(key_and_sigs)

for sig_chunk in verified_signatures:
    if sig_chunk[0] != key:
        continue # Not a signature bound to the key in question at all

    # Direct signature on the top-level key, pretty rare
    # If there is one of these, you can be sure of they key's integrity
    if len(sig_chunk) == 2:
        for sig in sig_chunk[1]:
          print "Valid self-sig on top-level key"

    # Signature to bind a UserID to the top-level key
    # This signature proves the top-level claims the UserID
    # If there is one of these, you can be sure of they key's integrity
    elif isinstance(sig_chunk[1], OpenPGP.UserIDPacket):
        for sig in sig_chunk[2]:
            print "Top level key claims UserID: " + str(sig_chunk[1])

    # Signature to bind a subkey to the top-level key
    # This signature proves the top-level claims the subkey
    # This is not usually interpreted to mean anything about key integrity
    elif isinstance(sig_chunk[1], OpenPGP.PublicSubkeyPacket):
        for sig in sig_chunk[2]:
            print "Top level key claims subkey: " + sig_chunk[1].fingerprint()
