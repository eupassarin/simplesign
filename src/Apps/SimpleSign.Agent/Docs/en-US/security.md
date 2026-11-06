# Security

## What the agent guarantees

- **The private key stays here.** The agent returns signatures, never keys. On a token or smartcard the key cannot leave the device at all.
- **Only this computer can reach it.** It listens on `127.0.0.1`, which other machines on the network cannot call.
- **Sites must be authorized.** The first call from a site asks you. The site is recognized by its exact origin: `https://bank.example` and `https://bank.example:8443` are different sites.
- **Every signature is confirmed.** The confirmation shows the site, the document name and the certificate. Being authorized lets a site list certificates, not sign by itself.
- **The PIN never goes through the page.** You type it in the agent's window, or on the reader's PIN pad. It is kept in memory only, and by default not kept at all.
- **Limits.** Requests up to 1 MB, 100 items per signature request, 20 calls a minute per site.

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

The settings file holds the port, the authorized and blocked sites and your choices of language and theme. The activity list is kept in memory and disappears when the agent closes. No certificate, key, PIN or document is stored.
