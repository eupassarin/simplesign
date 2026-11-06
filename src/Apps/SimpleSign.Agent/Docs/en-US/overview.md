# How it works

SimpleSign Agent is a small program that stays in the tray (the menu bar on macOS). It lets a web page sign with a certificate that lives on **this computer**: the system certificate store, an A3 token or a smartcard.

The page never sees the private key. It sends the bytes to sign and gets the signature back.

## The flow

1. The site's server prepares the document and computes what has to be signed.
2. The page calls the agent at `http://127.0.0.1:{port}`, on this computer.
3. The agent asks **you** to confirm, showing the site, the document and the certificate. For a token, it asks for the PIN in its own window.
4. The key signs. On a token, the signature is made inside the token.
5. The page sends the signature to the server, which finishes the signed document.

> A browser cannot reach a token or the certificate store by itself. The agent is the bridge, and it only works for the sites you authorize.

## What is in this window

| Section | What it is for |
| --- | --- |
| **Overview** | Whether the agent is running, and the certificates it found. |
| **Sites** | The sites you authorized or blocked. |
| **Activity** | What the agent did since it started. |
| **Test** | An end-to-end test with your real certificate. |
| **Documentation** | These pages. |

Settings and About open from the icons at the top right. Closing the window does not stop the agent: it keeps running in the tray until you choose **Quit** there.

## Next

- New here? Read [Getting started](#start).
- Building a site that signs? Read [Integration](#integration).
- Something is not working? Read [Troubleshooting](#troubleshooting).
