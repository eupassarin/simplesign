# Security

## What the agent guarantees

- **The private key stays here.** The agent returns signatures, never keys. On a token or smartcard the key cannot leave the device at all.
- **Only this computer can reach it.** It listens on `127.0.0.1`, which other machines on the network cannot call.
- **Sites must be authorized.** The first call from a site asks you. The site is recognized by its exact origin: `https://bank.example` and `https://bank.example:8443` are different sites.
- **Every signature is confirmed.** The confirmation shows the site, the document name and the certificate. Being authorized lets a site list certificates, not sign by itself.
- **The PIN never goes through the page.** You type it in the agent's window, or on the reader's PIN pad. It is kept in memory only, and by default not kept at all.
- **Limits.** Requests up to 1 MB, 100 items per signature request, 20 calls a minute per site.
- **Only signature data is signed.** Each item must be CMS signed attributes or an XML-DSig `SignedInfo`. A raw hash, a document or anything else is refused before you are asked.
- **A token warns you before it locks.** When the token says a wrong PIN was typed, the PIN prompt says so, and on the last attempt it says that one more wrong PIN locks the card.

## For a managed installation

Two options exist for a deployment where a server drives the agent. Both are off unless someone turns them on.

- **Server-signed sign requests.** With `signedRequestsRequired`, a signature is made only when the request carries a token signed by one of the configured public keys. The token names the site, the certificate and the exact bytes to sign, lasts at most five minutes and is accepted once, so a page cannot replay it or ask for anything the server did not prepare. What the confirmation shows then comes from the token, not from the page.
- **A fixed list of sites.** An administrator can ship a `policy.json` that fixes the authorized sites and the other settings. **Sites** then shows the list read-only, an unknown site is refused without asking you, and the window says which settings your administrator fixed.

## What you should do

- Confirm only the signatures you started. An unexpected confirmation is a reason to refuse.
- Read the site's address in the confirmation, not only its name.
- Use **Always allow** only for sites you use regularly. Remove the ones you no longer use in **Sites**.
- Keep **Remember the token PIN** on *Never* on a shared computer.

## What the agent does not do

- It does not open, read or upload your files. The site sends the bytes to sign; the document itself stays with the site.
- It does not validate the document's content. What the confirmation shows is what the site says it is signing.
- It does not send anything to the internet. It only answers calls made on this computer.

## Where data is kept

The settings file holds the port, the authorized and blocked sites, the trust frameworks you enabled and your choices of language and theme. The activity list is kept in memory and disappears when the agent closes. No certificate, key, PIN or document is stored.
