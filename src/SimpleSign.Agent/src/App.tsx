import { useState, useEffect, useRef, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { t, setLocale, getLocale, supportedLocales, onLocaleChange } from "./i18n";

interface AgentSessionRequest {
  FileName: string;
  HashAlgorithm: string;
}

interface HttpSession {
  id: string;
  status: string;
  request: {
    fileName: string;
    hashAlgorithm: string;
    dataBase64: string;
  };
  thumbprint?: string;
  signatureBase64?: string;
  certificateBase64?: string;
  error?: string;
}

interface Certificate {
  thumbprint: string;
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
}

type Theme = "light" | "dark" | "system";

function useForceUpdate() {
  const [, setTick] = useState(0);
  return useCallback(() => setTick((t) => t + 1), []);
}

function getSystemTheme(): "light" | "dark" {
  return window.matchMedia("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light";
}

function resolveTheme(theme: Theme): "light" | "dark" {
  return theme === "system" ? getSystemTheme() : theme;
}

function App() {
  const forceUpdate = useForceUpdate();

  const [sessionRequest, setSessionRequest] = useState<AgentSessionRequest | null>(null);
  const [httpSession, setHttpSession] = useState<HttpSession | null>(null);
  const [signedCount, setSignedCount] = useState(0);

  const [certificates, setCertificates] = useState<Certificate[]>([]);
  const [selectedCert, setSelectedCert] = useState("");
  const [signing, setSigning] = useState(false);
  const [signStatus, setSignStatus] = useState<string>("");
  const [errorMessage, setErrorMessage] = useState("");
  const closeTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [theme, setTheme] = useState<Theme>(() => {
    return (localStorage.getItem("simplesign-theme") as Theme) || "system";
  });

  const resolved = resolveTheme(theme);

  // Listen for locale changes to re-render
  useEffect(() => onLocaleChange(forceUpdate), [forceUpdate]);

  // Listen for OS theme changes
  useEffect(() => {
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const handler = () => {
      if (theme === "system") forceUpdate();
    };
    mq.addEventListener("change", handler);
    return () => mq.removeEventListener("change", handler);
  }, [theme, forceUpdate]);

  // Apply theme to document
  useEffect(() => {
    document.documentElement.setAttribute("data-theme", resolved);
  }, [resolved]);

  // Load certificates on startup
  useEffect(() => {
    (async () => {
      try {
        const certs = (await invoke("get_certificates")) as Certificate[];
        setCertificates(certs);
      } catch (err) {
        console.error("Init error:", err);
        setCertificates([]);
      }
    })();
  }, []);

  // Poll for HTTP sessions (from CLI or web apps)
  useEffect(() => {
    const interval = setInterval(async () => {
      try {
        const session = (await invoke("get_pending_session")) as HttpSession | null;
        if (session && !httpSession) {
          if (session.status === "data_ready") {
            // Multi-doc auto-sign: sign immediately without user interaction
            setHttpSession(session);
            setSessionRequest({
              FileName: session.request.fileName,
              HashAlgorithm: session.request.hashAlgorithm,
            });
            setSigning(true);
            setSignStatus("signing");
            try {
              await invoke("sign_session", { sessionId: session.id });
              setSignedCount((c) => c + 1);
              setSignStatus("done");
              setTimeout(() => {
                setHttpSession(null);
                setSessionRequest(null);
                setSignStatus("");
                setSigning(false);
              }, 500);
            } catch (err) {
              setSignStatus("error");
              setErrorMessage(String(err));
              setTimeout(() => {
                setHttpSession(null);
                setSessionRequest(null);
                setSignStatus("");
                setErrorMessage("");
                setSigning(false);
              }, 2000);
            }
          } else {
            // Normal pending session: show cert selection UI
            setHttpSession(session);
            setSessionRequest({
              FileName: session.request.fileName,
              HashAlgorithm: session.request.hashAlgorithm,
            });
          }
        }
      } catch (err) {
        // Ignore polling errors
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [httpSession]);

  // Auto-close after 3s of inactivity — silent timer, no countdown shown.
  // Between docs the CLI waits 1.8s, so the next session arrives before 3s and cancels the timer.
  // Only after the last document does the full 3s elapse and the app closes.
  useEffect(() => {
    const idle = signedCount > 0 && !signing && !httpSession && signStatus === "";
    if (idle) {
      const timer = setTimeout(() => {
        invoke("cancel_sign"); // app.exit(0) in Rust
      }, 3000);
      closeTimerRef.current = timer as unknown as ReturnType<typeof setInterval>;
      return () => clearTimeout(timer);
    } else {
      if (closeTimerRef.current !== null) {
        clearTimeout(closeTimerRef.current as unknown as ReturnType<typeof setTimeout>);
        closeTimerRef.current = null;
      }
    }
  }, [signedCount, signing, httpSession, signStatus]);

  function handleTheme(newTheme: Theme) {
    setTheme(newTheme);
    localStorage.setItem("simplesign-theme", newTheme);
  }

  async function handleSign() {
    if (!selectedCert || signing) return;
    setSigning(true);
    setSignStatus("preparing");
    setErrorMessage("");
    try {
      if (httpSession) {
        // HTTP session mode: select cert and wait for client to send data
        await invoke("select_cert_for_session", {
          sessionId: httpSession.id,
          thumbprint: selectedCert,
        });

        // Poll for "data_ready" state (client will PUT data after receiving cert)
        setSignStatus("waiting_data");
        let ready = false;
        const startTime = Date.now();
        while (Date.now() - startTime < 5 * 60 * 1000) {
          try {
            const resp = await fetch(
              `http://127.0.0.1:21599/api/sign/${httpSession.id}`
            );
            if (resp.ok) {
              const data = await resp.json();
              if (data.status === "data_ready") {
                ready = true;
                break;
              }
              if (data.status === "cancelled" || data.status === "error") {
                throw new Error(data.error || "Session cancelled");
              }
            }
          } catch (fetchErr) {
            if (fetchErr instanceof Error && fetchErr.message !== "Session cancelled") {
              // Ignore transient fetch errors
            } else {
              throw fetchErr;
            }
          }
          await new Promise((r) => setTimeout(r, 500));
        }

        if (!ready) {
          throw new Error("Timeout waiting for signing data");
        }

        // Data is ready, sign it
        setSignStatus("signing");
        await invoke("sign_session", {
          sessionId: httpSession.id,
        });

        setSignedCount((c) => c + 1);
        setSignStatus("done");

        // Reset quickly so Agent can accept the next document
        setTimeout(() => {
          setHttpSession(null);
          setSessionRequest(null);
          setSignStatus("");
        }, 1500);
      } else {
        // Standalone mode
        await invoke("sign_document", {
          thumbprint: selectedCert,
        });
        setSignedCount((c) => c + 1);
        setSignStatus("done");
        setTimeout(() => setSignStatus(""), 2000);
      }
    } catch (err) {
      console.error("Sign failed:", err);
      setSignStatus("error");
      setErrorMessage(String(err));
      // Reset error after a few seconds so user can retry
      setTimeout(() => {
        setHttpSession(null);
        setSessionRequest(null);
        setSignStatus("");
        setErrorMessage("");
      }, 4000);
    } finally {
      setSigning(false);
    }
  }

  async function handleCancel() {
    await invoke("cancel_sign");
  }

  const selectedCertInfo = certificates.find(
    (c) => c.thumbprint === selectedCert
  );

  return (
    <div className={`app ${resolved}`}>
      {/* Header */}
      <header className="header">
        <div className="header-left">
          <svg className="logo" viewBox="0 0 24 24" width="28" height="28">
            <rect rx="5" width="24" height="24" fill="var(--accent)" />
            <text
              x="12"
              y="17"
              textAnchor="middle"
              fill="white"
              fontSize="14"
              fontWeight="700"
              fontFamily="system-ui"
            >
              S
            </text>
          </svg>
          <span className="header-title">SimpleSign</span>
        </div>
        <div className="header-right">
          {/* Language picker */}
          <div className="picker">
            <select
              value={getLocale()}
              onChange={(e) => setLocale(e.target.value)}
              className="picker-select"
              aria-label={t("language")}
            >
              {supportedLocales.map((l) => (
                <option key={l.code} value={l.code}>
                  {l.label}
                </option>
              ))}
            </select>
          </div>
          {/* Theme toggle */}
          <div className="theme-toggle">
            <button
              className={`theme-btn ${theme === "light" ? "active" : ""}`}
              onClick={() => handleTheme("light")}
              title={t("light")}
              aria-label={t("light")}
            >
              <svg viewBox="0 0 20 20" width="14" height="14" fill="currentColor">
                <path d="M10 2a1 1 0 011 1v1a1 1 0 11-2 0V3a1 1 0 011-1zm4 8a4 4 0 11-8 0 4 4 0 018 0zm-.464 4.95l.707.707a1 1 0 001.414-1.414l-.707-.707a1 1 0 00-1.414 1.414zm2.12-10.607a1 1 0 010 1.414l-.706.707a1 1 0 11-1.414-1.414l.707-.707a1 1 0 011.414 0zM17 11a1 1 0 100-2h-1a1 1 0 100 2h1zm-7 4a1 1 0 011 1v1a1 1 0 11-2 0v-1a1 1 0 011-1zM5.05 6.464A1 1 0 106.465 5.05l-.708-.707a1 1 0 00-1.414 1.414l.707.707zm1.414 8.486l-.707.707a1 1 0 01-1.414-1.414l.707-.707a1 1 0 011.414 1.414zM4 11a1 1 0 100-2H3a1 1 0 000 2h1z" />
              </svg>
            </button>
            <button
              className={`theme-btn ${theme === "system" ? "active" : ""}`}
              onClick={() => handleTheme("system")}
              title={t("system")}
              aria-label={t("system")}
            >
              <svg viewBox="0 0 20 20" width="14" height="14" fill="currentColor">
                <path fillRule="evenodd" d="M3 5a2 2 0 012-2h10a2 2 0 012 2v8a2 2 0 01-2 2h-2.22l.123.489.804.804A1 1 0 0113 18H7a1 1 0 01-.707-1.707l.804-.804L7.22 15H5a2 2 0 01-2-2V5zm5.771 7H5V5h10v7H8.771z" clipRule="evenodd" />
              </svg>
            </button>
            <button
              className={`theme-btn ${theme === "dark" ? "active" : ""}`}
              onClick={() => handleTheme("dark")}
              title={t("dark")}
              aria-label={t("dark")}
            >
              <svg viewBox="0 0 20 20" width="14" height="14" fill="currentColor">
                <path d="M17.293 13.293A8 8 0 016.707 2.707a8.001 8.001 0 1010.586 10.586z" />
              </svg>
            </button>
          </div>
        </div>
      </header>

      {/* Document info card — only shown when a document is pending */}
      {sessionRequest && (
      <div className="card card-info">
        <div className="card-label">{t("documentInfo")}</div>
        <div className="card-row">
          <span className="card-row-label">{t("fileToSign")}</span>
          <span className="card-row-value file-name">
            <svg viewBox="0 0 20 20" width="16" height="16" fill="var(--accent)" className="icon-inline">
              <path fillRule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4z" clipRule="evenodd" />
            </svg>
            {sessionRequest.FileName}
          </span>
        </div>
        <div className="card-row">
          <span className="card-row-label">{t("requestedBy")}</span>
          <span className="card-row-value">
            <svg viewBox="0 0 20 20" width="16" height="16" fill="var(--text-muted)" className="icon-inline">
              <path fillRule="evenodd" d="M10 9a3 3 0 100-6 3 3 0 000 6zm-7 9a7 7 0 1114 0H3z" clipRule="evenodd" />
            </svg>
            SimpleSign CLI
          </span>
        </div>
        <div className="card-row">
          <span className="card-row-label">Algorithm</span>
          <span className="card-row-value">{sessionRequest.HashAlgorithm}</span>
        </div>
      </div>
      )}

      {/* Certificate selector */}
      <div className="card card-cert">
        <div className="card-label">{t("certificate")}</div>
        <div className="select-wrapper">
          <select
            value={selectedCert}
            onChange={(e) => setSelectedCert(e.target.value)}
            disabled={signing || certificates.length === 0}
            className="cert-select"
          >
            <option value="">
              {certificates.length === 0
                ? t("noCertificates")
                : t("selectCertificate")}
            </option>
            {certificates.map((cert) => (
              <option key={cert.thumbprint} value={cert.thumbprint}>
                {cert.subject}
              </option>
            ))}
          </select>
          <svg className="select-chevron" viewBox="0 0 20 20" width="16" height="16" fill="var(--text-muted)">
            <path fillRule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clipRule="evenodd" />
          </svg>
        </div>

        {/* Certificate details (when selected) */}
        {selectedCertInfo && (
          <div className="cert-details">
            <div className="cert-detail-row">
              <span className="cert-detail-label">{t("issuer")}</span>
              <span className="cert-detail-value">{selectedCertInfo.issuer}</span>
            </div>
            <div className="cert-detail-row">
              <span className="cert-detail-label">{t("validFrom")}</span>
              <span className="cert-detail-value">
                {selectedCertInfo.validFrom} → {selectedCertInfo.validTo}
              </span>
            </div>
          </div>
        )}
      </div>

      {/* Action buttons */}
      <div className="actions">
        <button
          className="btn btn-primary"
          onClick={handleSign}
          disabled={!selectedCert || signing || signStatus === "done"}
        >
          {signing ? (
            <>
              <svg className="spinner" viewBox="0 0 24 24" width="18" height="18">
                <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" fill="none" strokeDasharray="31.4" strokeLinecap="round" />
              </svg>
              {signStatus === "signing" ? t("signing") + "…" : t("signing")}
            </>
          ) : signStatus === "done" ? (
            <>
              <svg viewBox="0 0 20 20" width="18" height="18" fill="currentColor">
                <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
              </svg>
              ✓ {t("signed")}
            </>
          ) : (
            <>
              <svg viewBox="0 0 20 20" width="18" height="18" fill="currentColor">
                <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
              </svg>
              {t("sign")}
            </>
          )}
        </button>
        <button
          className="btn btn-secondary"
          onClick={handleCancel}
          disabled={signing}
        >
          <svg viewBox="0 0 20 20" width="18" height="18" fill="currentColor">
            <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
          </svg>
          {t("cancel")}
        </button>
      </div>

      {/* Status messages */}
      {signStatus === "done" && (
        <div className="status-banner success">
          ✓ {t("signedSuccess")}
        </div>
      )}
      {signStatus === "error" && (
        <div className="status-banner error">
          ✗ {errorMessage || "Signing failed."}
        </div>
      )}
      {signedCount > 0 && !signing && signStatus === "" && (
        <div className="status-banner success">
          ✓ {signedCount} {signedCount === 1 ? t("documentSigned") : t("documentsSigned")}
        </div>
      )}
    </div>
  );
}

export default App;
