# Troubleshooting

Start with **Test**: it shows which step fails. **About** has *Copy diagnostics* to send with a support request.

## The site says the agent is not installed

- Check the **Overview**: the agent must be running.
- Check the port. The site must call the same port the agent listens on (`{port}` here, in Settings).
- Some browser extensions and corporate security tools block calls to `127.0.0.1`. Try another browser or a private window.

## The agent could not start: the port is in use

Another program, or another copy of the agent, is using port `{port}`. Close it and press **Try again**, or choose another port in Settings. If you change the port, the site has to call the new one.

## My token or smartcard does not show up

1. Plug it in and press **Refresh** on the **Overview**.
2. Install the token's driver from the manufacturer or from the certificate authority that issued it. Without the driver the computer cannot talk to the token.
3. **About** lists the *PKCS#11 drivers* that were found. If yours is not there, the agent does not know where it is.
4. For a driver in an unusual place, set the environment variable `SIMPLESIGN_PKCS11_LIBRARY` to the full path of the driver's library and start the agent again.

## My certificate from the system store does not show up

- It must have its private key on this computer. A certificate copied without the key cannot sign.
- It must allow signing (key usage *digital signature* or *non-repudiation*).
- On macOS the first use may ask for permission to use the key in the Keychain. Allow it.

## The site refuses my certificate

The site's server checks the certificate before signing. The **Overview** marks the certificates it will refuse:

- **Not for signing**: its key usage allows neither *digital signature* nor *non-repudiation*.
- **Weak key**: an RSA key under 2048 bits.

Use another certificate, or ask the certificate authority for a new one. A certificate whose chain has expired is
refused too.

## The PIN is refused

The PIN belongs to the token, not to the agent. After a few wrong attempts the token locks itself, and only the certificate authority or the token's own tool can unlock it. Stop trying and check the PIN.

## The site was not asked for, or keeps asking

- A site allowed with **Allow** is asked again after the agent restarts. Use **Always allow** for sites you use regularly.
- A site in the **Blocked** list is refused without asking. Unblock it in **Sites**.

## The confirmation window does not appear

It opens on top of the other windows, but it can be on another screen or desktop. Look for the agent's windows, or answer the pending request before starting another.

## macOS or Windows refuses to open the app

The downloads are not code-signed yet. On macOS, right-click the app and choose **Open** the first time. On Windows, choose **More info** and **Run anyway**.
