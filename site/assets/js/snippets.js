// Code builder model: turns a set of choices into a C# program and the equivalent CLI command.
// Pure module (no DOM) so site/tools/render-snippets.mjs can render every combination and the
// .NET project tests/site/SimpleSign.Site.SnippetTests can compile them against the real API.

export const CHOICES = {
  format: ['pades', 'cades', 'xades'],
  key: ['pfx', 'store', 'pkcs11', 'psc', 'csc', 'deferred'],
  level: ['bb', 'bt', 'blt', 'blta'],
  stamp: [false, true],
  validate: ['none', 'generic', 'icpbrasil'],
};

export const DEFAULTS = { format: 'pades', key: 'pfx', level: 'bt', stamp: false, validate: 'icpbrasil' };

/** Whether a choice combination makes sense (the UI disables the others). */
export function isValid(o) {
  if (o.key === 'deferred' && o.format !== 'pades') return false;
  if (o.stamp && (o.format !== 'pades' || o.key === 'deferred')) return false;
  return true;
}

/** Fixes an invalid combination by turning off what does not apply. */
export function normalize(o) {
  const given = Object.fromEntries(Object.entries(o ?? {}).filter(([, v]) => v !== undefined && v !== null));
  const n = { ...DEFAULTS, ...given };
  for (const [name, values] of Object.entries(CHOICES)) {
    if (!values.includes(n[name])) n[name] = DEFAULTS[name];
  }
  if (n.key === 'deferred' && n.format !== 'pades') n.key = 'pfx';
  if (n.format !== 'pades' || n.key === 'deferred') n.stamp = false;
  return n;
}

const INPUT = {
  pades: { read: 'var pdf = await File.ReadAllBytesAsync("contract.pdf");', name: 'pdf', file: 'contract.pdf', out: 'contract-signed.pdf' },
  cades: { read: 'var data = await File.ReadAllBytesAsync("contract.pdf");', name: 'data', file: 'contract.pdf', out: 'contract.pdf.p7s' },
  xades: { read: 'var xml = await File.ReadAllBytesAsync("invoice.xml");', name: 'xml', file: 'invoice.xml', out: 'invoice-signed.xml' },
};

const SIGNER = { pades: 'PadesSigner', cades: 'CadesSigner', xades: 'XadesSigner' };

const LEVEL = {
  bb: null,
  bt: 'AdesBaselineProfile.Timestamped(TimestampOptions.DigiCert)',
  blt: 'AdesBaselineProfile.LongTerm(TimestampOptions.DigiCert, new LongTermValidationOptions())',
  blta: 'AdesBaselineProfile.Archive(TimestampOptions.DigiCert, new LongTermValidationOptions())',
};

/** Builds the C# program for the choices. Returns { usings, setup, body, helpers } joined by render(). */
export function buildCSharp(choices) {
  const o = normalize(choices);
  const usings = new Set(['SimpleSign.Core.Signing']);
  const setup = [];
  const chain = [];
  let credential;
  const input = INPUT[o.format];
  usings.add({ pades: 'SimpleSign.PAdES', cades: 'SimpleSign.CAdES', xades: 'SimpleSign.XAdES' }[o.format]);

  switch (o.key) {
    case 'pfx':
      setup.push('var password = Environment.GetEnvironmentVariable("CERT_PASSWORD");');
      if (o.format === 'pades') {
        credential = '.WithCertificateFile("me.pfx", password)';
      } else {
        usings.add('System.Security.Cryptography.X509Certificates');
        setup.push('using var certificate = X509CertificateLoader.LoadPkcs12FromFile("me.pfx", password);');
        credential = '.WithCertificate(certificate)';
      }
      break;
    case 'store':
      usings.add('SimpleSign.Core.Crypto');
      setup.push('using var store = new SystemCertificateStore();   // Windows: Personal (My) store of the current user');
      setup.push('using var certificate = store.FindByThumbprint("YOUR_CERTIFICATE_THUMBPRINT")');
      setup.push('    ?? throw new InvalidOperationException("Certificate not found.");');
      credential = '.WithCertificate(certificate)';
      break;
    case 'pkcs11':
      usings.add('SimpleSign.Signers.Pkcs11');
      setup.push('using var token = Pkcs11Signer.Open(new Pkcs11SignerOptions');
      setup.push('{');
      setup.push('    LibraryPath = "/usr/lib/libeToken.so",   // your token\'s PKCS#11 driver');
      setup.push('    Pin = Environment.GetEnvironmentVariable("TOKEN_PIN"),');
      setup.push('});');
      credential = '.WithExternalSigner(token.Certificate, token, token.Chain)';
      break;
    case 'psc':
      usings.add('SimpleSign.Signers.Cloud');
      usings.add('SimpleSign.Signers.Cloud.Psc');
      setup.push('var psc = new PscClient(new PscClientOptions');
      setup.push('{');
      setup.push('    BaseUri = new Uri("https://your-provider.example/v0/"),   // from BirdID, VIDaaS, NeoID...');
      setup.push('    ClientId = "your-client-id",');
      setup.push('    ClientSecret = Environment.GetEnvironmentVariable("PSC_CLIENT_SECRET"),');
      setup.push('});');
      setup.push('// The holder approves in the browser (or use psc.PasswordAuthorizeAsync(cpf, otp)).');
      setup.push('var session = await psc.AuthorizeAsync(new LoopbackAuthorizationHandler(),');
      setup.push('    PscScope.SignatureSession, TimeSpan.FromMinutes(10), loginHint: "12345678909");');
      setup.push('using var signer = await PscSigner.CreateAsync(psc, session);');
      credential = '.WithExternalSigner(signer.Certificate, signer, signer.Chain)';
      break;
    case 'csc':
      usings.add('SimpleSign.Signers.Cloud.Csc');
      setup.push('var csc = new CscClient(new CscClientOptions');
      setup.push('{');
      setup.push('    BaseUri = new Uri("https://your-qtsp.example/csc/v2/"),');
      setup.push('    AccessToken = Environment.GetEnvironmentVariable("CSC_TOKEN"),');
      setup.push('});');
      setup.push('using var signer = await CscSigner.CreateAsync(csc, "your-credential-id",');
      setup.push('    new ExplicitCscAuthorizer(pin: Environment.GetEnvironmentVariable("CSC_PIN")));');
      credential = '.WithExternalSigner(signer.Certificate, signer, signer.Chain)';
      break;
    case 'deferred':
      usings.add('System.Security.Cryptography');
      usings.add('System.Security.Cryptography.X509Certificates');
      setup.push('// The server only needs the signer\'s public certificate.');
      setup.push('using var certificate = X509CertificateLoader.LoadCertificateFromFile("signer.cer");');
      setup.push('var sessionKey = RandomNumberGenerator.GetBytes(32);   // keep it on the server');
      break;
    default:
      throw new Error(`Unknown key source ${o.key}`);
  }

  const level = LEVEL[o.level];
  const body = [];
  body.push(input.read);
  if (o.key === 'deferred') {
    body.push('');
    body.push('// 1. Server: prepare the PDF and get the bytes the device must sign.');
    body.push('var prepared = await DeferredSigner.Document(pdf)');
    body.push('    .WithCertificate(certificate)');
    body.push('    .WithSessionIntegrityKey(sessionKey)');
    if (level) body.push(`    .WithLevel(${level})`);
    body.push('    .PrepareAsync();');
    body.push('');
    body.push('// 2. Browser, smartcard or HSM: sign prepared.HashToSign and return the raw signature.');
    body.push('byte[] rawSignature = await SignOnDeviceAsync(prepared.HashToSign);');
    body.push('');
    body.push('// 3. Server: resume the session and embed the signature.');
    body.push('byte[] signed = await DeferredSigner.Resume(prepared.SessionData, sessionKey)');
    body.push('    .CompleteAsync(rawSignature);');
  } else {
    chain.push(credential);
    if (level) chain.push(`.WithLevel(${level})`);
    if (o.stamp) {
      usings.add('SimpleSign.PAdES.Signing');
      chain.push('.WithFieldOptions(new SignatureFieldOptions');
      chain.push('{');
      chain.push('    Reason = "Contract approval",');
      chain.push('    Location = "São Paulo, BR",');
      chain.push('    Appearance = new SignatureAppearance { Page = 1, X = 40, Y = 40, ShowReason = true, ShowLocation = true },');
      chain.push('})');
    }
    body.push('');
    body.push(`byte[] signed = await ${SIGNER[o.format]}.Document(${input.name})`);
    for (const line of chain) body.push(line.startsWith('.') ? `    ${line}` : `    ${line}`);
    body.push('    .SignAsync();');
  }
  body.push(`await File.WriteAllBytesAsync("${input.out}", signed);`);

  if (o.validate !== 'none') {
    usings.add('SimpleSign.Core.Validation');
    body.push('');
    body.push('// Validate: integrity, signature, chain, revocation and timestamps.');
    if (o.format === 'pades') {
      if (o.validate === 'icpbrasil') {
        usings.add('SimpleSign.Brasil');
        body.push('var validator = BrasilExtension.CreateValidator();   // ICP-Brasil and Gov.br roots');
      } else {
        usings.add('SimpleSign.PAdES.Validation');
        body.push('var validator = new PdfSignatureValidator(new ValidationOptions { CheckRevocation = true, TrustSystemRoots = true });');
      }
      body.push('foreach (var result in await validator.ValidateAsync(new MemoryStream(signed)))');
      body.push('{');
      body.push('    Console.WriteLine($"{result.FieldName}: {result.Indication}");   // Valid, Invalid or Indeterminate');
      body.push('}');
    } else {
      const anchors = o.validate === 'icpbrasil' ? 'trustAnchors' : 'null';
      if (o.validate === 'icpbrasil') {
        usings.add('SimpleSign.Brasil');
        body.push('var trustAnchors = new BrasilExtension().TrustAnchorProviders.SelectMany(p => p.GetTrustAnchors()).ToList();');
      }
      body.push(o.format === 'cades'
        ? `var validation = new CadesSignatureValidator(new ValidationOptions { CheckRevocation = true }).Validate(signed, data, ${anchors});`
        : `var validation = new XadesSignatureValidator(new ValidationOptions { CheckRevocation = true }).Validate(signed, ${anchors});`);
      body.push('Console.WriteLine(validation.IsValid ? "Valid" : string.Join("; ", validation.Errors));');
    }
  }

  const helpers = o.key === 'deferred'
    ? ['', 'static Task<byte[]> SignOnDeviceAsync(byte[] dataToSign) =>',
      '    throw new NotImplementedException("Send dataToSign to the signing device and return its raw signature.");']
    : [];

  return { usings: [...usings].sort(), setup, body, helpers };
}

/** The C# program as shown to the user (top-level statements). */
export function renderCSharp(choices) {
  const { usings, setup, body, helpers } = buildCSharp(choices);
  return [...usings.map((u) => `using ${u};`), '', ...setup, ...(setup.length ? [''] : []), ...body, ...helpers].join('\n');
}

/** The NuGet packages the program needs. */
export function packages(choices) {
  const o = normalize(choices);
  const list = ['SimpleSign'];
  if (o.validate === 'icpbrasil') list.push('SimpleSign.Brasil');
  if (o.key === 'pkcs11') list.push('SimpleSign.Signers.Pkcs11');
  if (o.key === 'psc' || o.key === 'csc') list.push('SimpleSign.Signers.Cloud');
  return list;
}

/** The equivalent CLI command, or { note } when the CLI does not cover the combination. */
export function renderCli(choices) {
  const o = normalize(choices);
  if (o.key === 'deferred') return { note: 'build.cli.deferred' };
  if (o.format === 'xades' && !['pfx'].includes(o.key)) return { note: 'build.cli.xadesKey' };
  if (o.format === 'cades' && o.key === 'store') return { note: 'build.cli.cadesStore' };

  const input = INPUT[o.format];
  const lines = [];
  const command = { pades: 'simplesign sign', cades: 'simplesign cades sign', xades: 'simplesign xades sign' }[o.format];
  lines.push(`${command} ${input.file} -o ${input.out}`);
  const notes = {
    pfx: ['# Asks for the certificate password.'],
    store: [],
    pkcs11: ['# Asks for the token PIN; "simplesign pkcs11 list --lib <driver>" shows the keys.'],
    psc: ['# Opens the browser to approve; add --psc-otp <code> to use the app\'s one-time password instead.'],
    csc: ['# "simplesign csc list" shows the credential IDs.'],
  }[o.key];
  const credential = {
    pfx: ['--cert me.pfx'],
    store: ['--thumbprint YOUR_CERTIFICATE_THUMBPRINT'],
    pkcs11: ['--pkcs11-lib /usr/lib/libeToken.so'],
    psc: ['--psc-url https://your-provider.example/v0/ --psc-client-id your-client-id', '--psc-client-secret env:PSC_CLIENT_SECRET --psc-cpf 12345678909'],
    csc: ['--csc-url https://your-qtsp.example/csc/v2/ --csc-token env:CSC_TOKEN', '--csc-credential your-credential-id --pin env:CSC_PIN'],
  }[o.key];
  lines.push(...credential);
  if (o.level !== 'bb') {
    const tsa = '--tsa http://timestamp.digicert.com';
    if (o.format === 'pades') {
      lines.push({ bt: tsa, blt: `${tsa} --ltv`, blta: `${tsa} --archival` }[o.level]);
    } else {
      lines.push(`${tsa} --level ${{ bt: 'timestamped', blt: 'longterm', blta: 'archive' }[o.level]}`);
    }
  }
  if (o.stamp) lines.push('--visible --reason "Contract approval" --location "São Paulo, BR"');

  const out = [...notes, lines.map((l, i) => `${i === 0 ? '' : '  '}${l}${i === lines.length - 1 ? '' : ' \\'}`).join('\n')];

  if (o.validate !== 'none') {
    out.push('');
    out.push({
      pades: `simplesign validate ${input.out}`,
      cades: `simplesign cades validate ${input.out} --data ${input.file}`,
      xades: `simplesign xades validate ${input.out}`,
    }[o.format]);
  }
  return { command: out.join('\n') };
}

/** Every valid combination, for the compile test. */
export function allCombinations() {
  const result = [];
  for (const format of CHOICES.format) for (const key of CHOICES.key) for (const level of CHOICES.level)
    for (const stamp of CHOICES.stamp) for (const validate of CHOICES.validate) {
      const o = { format, key, level, stamp, validate };
      if (isValid(o)) result.push(o);
    }
  return result;
}
