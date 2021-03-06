# Low level protocol

This document describes the low level protocol between the OnionPIR client and
the OnionPIR server.

Since the data is transmitted via a data stream in TCP, there are no such things
as packets with a given length. Therefore the length of the sent data will be
sent before the data itself:
> [length of the data (4 bytes)][data]

When inspecting the TCP stream, it will look like:
> [length of the data (4 bytes)][data][length of the data (4 bytes)][data]

# Registration
client>server
> [010][pk of the client][new random nonce][encrypted with the pk of the server,
> the sk of the client and the random nonce: [mail-address of the client]]

If the given mail address is not registered yet, the server will store the pk,
nonce and mail address of the client, send a confirmation mail containing a
24 byte random token, which is also stored, and will respond with

server>client
> [011][encrypted with the public key of the client, the secret key of the
> server and the (random nonce + 1): [byte(0)]]

In case an error occurs, the last byte represents the error code.

The client will then send the token received via mail to the server:

client>server
> [012][pk of the client][new random nonce][encrypted with the pk of the server,
> the sk of the client and the random nonce: [token][mail address of the
> client]]

The server will then check if the token matches the pk of the client. If the
token corresponds to the pk, the registration is considered successful and the
server will send a confirmation to the client:

server>client
> [013][encrypted with the public key of the client, the sk of the server and
> (the random nonce + 1): [byte(0)]]

In case any error occurs, the client has to restart the registration process
using a fresh base nonce.


## Updating the user's public key
If a client wants to update his public key, the following protocol is used. The
new temporary key pair provided by the server within this three-way handshake is
important to avoid replay attacks and provides perfect forward secrecy in
combination with the new key pair generated by the client.

client>server
> [020][pk of the client][new random nonce (from now on called temporary
> nonce)][encrypted with the public key of the server, the secret key of the
> client and the temporary nonce: [new temporary public key of the client]]

server>client
> [021][encrypted with the secret key of the server, the temporary public key of
> the client and the (temporary nonce + 1): [new temporary public key of the
> server]]

client>server
> [022][encrypted with the temporary public key of the server, the temporary
> secret key of the client and the (temporary nonce + 2): [new public key]]

server>client
> [023][encrypted with the temporary public key of the client, the temporary
> secret key of the server and (the temporary nonce + 3): [byte(0)]]
