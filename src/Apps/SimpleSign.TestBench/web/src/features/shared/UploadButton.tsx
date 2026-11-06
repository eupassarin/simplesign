import { useRef } from "react"
import { FileUp } from "lucide-react"
import { Button } from "@/components/ui/button"
import { api } from "@/lib/api"

/** A button that uploads one file and reports its id. */
export function UploadButton({ label, accept, onUploaded }: { label: string; accept: string; onUploaded: (file: { id: string; fileName: string }) => void }) {
  const input = useRef<HTMLInputElement>(null)
  return (
    <>
      <Button variant="outline" size="sm" onClick={() => input.current?.click()}><FileUp /> {label}</Button>
      <input ref={input} type="file" accept={accept} hidden onChange={async (e) => {
        const file = e.target.files?.[0]
        if (!file) return
        const uploaded = await api.uploadFile(file)
        onUploaded({ id: uploaded.id, fileName: uploaded.fileName })
        e.target.value = ""
      }} />
    </>
  )
}
