import { useEffect, useRef } from 'react'

type MessageHandler = (data: any) => void

export function useWebViewMessage(handler: MessageHandler) {
  const handlerRef = useRef(handler)
  handlerRef.current = handler

  useEffect(() => {
    // WebView2 sends messages via window.chrome.webview
    const webview = (window as any).chrome?.webview
    if (webview) {
      const listener = (event: any) => {
        const data = typeof event.data === 'string' ? JSON.parse(event.data) : event.data
        handlerRef.current(data)
      }
      webview.addEventListener('message', listener)
      return () => webview.removeEventListener('message', listener)
    }

    // Fallback: standard postMessage (for dev/testing)
    const listener = (event: MessageEvent) => {
      handlerRef.current(event.data)
    }
    window.addEventListener('message', listener)
    return () => window.removeEventListener('message', listener)
  }, [])
}
