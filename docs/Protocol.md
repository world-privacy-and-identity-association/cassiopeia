Record Format
=============

The signer and signer-client communicate through individual "records" (in a TLS-Session using a SLIP-like protocol, via Serial). All multi-byte integers are transfered in little-endian order. Each record has the following format:

1 byte ":" (fixed ascii ':')
Hex encoding of:
2 byte command
  see type of commands below
1 byte flags
  flags for this command (currently unused)
4 byte session identifier
  session identifier (must be equal for all commands in one TLS session)
2 byte command identifier (counter)
  identifier for invocation. A command may be split into multiple records. All such records must have the same command identifier.
4 byte total length
  total length of the payload
2 byte offset
  indicates which chunk of data is being sent (currently unused)
2 byte length
  length of payload in this record
<length> byte data
  the playload data of this record
1 byte checksum
  bitwise complement of the sum of all bytes until now.
End hex encoding.
1 byte "\n" (fixed ascii '\n')

Record Types/Commands
---------------------

's' indicates commands set by the signer while all other commands are sent by the signer client.

(0x01) setCSR
  Sets the target key of the certificate that is to be created to the one contained in the given CSR.
(0x02) setSPKAC
  Sets the target key of the certificate that is to be created to the one contained in the given SPKAC-Request.
(0x10) setSignatureType
  Sets the signing algorithms digest algorithm.
  (sha512|sha384|sha256)
(0x11) setProfile
  Sets the certificate profile to sign with.
(0x12) wishFrom
  Sets the desired starting date.
(0x13) wishTo
  Sets the desired ending date (or validity-period).
(0x14) ocspTargetCA
  Used instead of (0x11) when signing OCSP certs. The payload is an exact time-CA name (e.g. orga_2017_1).
(0x18) addSAN
  Adds a given SAN (Subject alternative name) to the certificate.
  (DNS,<dnsname> or email,<email address>)
(0x19) addAVA
  Adds an AVA (Attribute value association) to this certificates subject.

(0x40) addProofLine
<hex>timestamp,<hex>table,<hex>PK,<hex>column=value,<hex>column=value

(0x80) sign
  Issue signing request.
s(0x80) setLog
  Provide Log of certificate creation.
(0x81) logSaved (checksum of log)
  Confirm that the log has been saved.
s(0x81) respondCertificate
  Provide the newly created certificate.
s(0x82) signingCA
  Provide the name of the CA-certificate with which this certificate has been signed.

(0x102) addSerial
  Add a serial of a certificate that should be revoked.
(0x100) revoke
  Revoke the provided serials for the CA given in this command.
s(0x100) revoked
  Confirm revocation. Provide the "date" for all newly created CRL-entries and a new CRL-signature. The local CRL should be updated accordingly, the signature updated and then validated.

(0x101) getFullCRL
  Request a full version of the current CRL.
s(0x101) fullCRL
  Reply with the full CRL.

(0xC0) getTimestamp
s(0xC0) timestampResponse
