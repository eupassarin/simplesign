# Getting started

## 1. Check that the agent is running

The **Overview** shows *The agent is running* and the address it listens on. The tray icon shows the same: solid when running, an outline when paused.

## 2. Check your certificate

Your certificate should be in the list on the **Overview**:

- **System store**: certificates installed on the computer (the Keychain on macOS, the personal store on Windows).
- **Token or smartcard**: plug it in and press **Refresh**. The token's driver must be installed.

Certificates without a private key, or that cannot be used to sign, are not listed.

## 3. Enable your trust framework

In Settings, **Trust frameworks** lists the ones the agent ships with: ICP-Brasil, Gov.br, IOFE (Peru) and eIDAS (European Union). Enable the ones you care about: only those answer the `country` and `trust` filters of the API, and only those put a badge on a certificate in the **Overview**. IOFE and eIDAS read a trusted list, which is downloaded in the background.

## 4. Run the test

Open **Test** and run it. It makes the same calls a site makes and ends by checking the signature. If the test passes, the agent, the certificate and the key work.

## 5. Sign on a site

The first time a site calls the agent, you are asked whether it may use your certificates:

- **Allow**: for now, until the agent closes.
- **Always allow**: the site goes to the **Sites** list and is not asked again.
- **Refuse**: the site gets nothing.

After that, **every signature** asks for your confirmation, and a token asks for its PIN.

> Only confirm a signature you started yourself on the site. If a confirmation shows up out of nowhere, refuse it.

## Good to know

- **Start at login** (Settings) opens the agent in the tray when you sign in.
- **Remember the token PIN** (Settings) keeps the token unlocked for a few minutes, so a batch of documents does not ask for the PIN each time. The default is to ask every time.
- You can remove or block a site at any time in **Sites**.
