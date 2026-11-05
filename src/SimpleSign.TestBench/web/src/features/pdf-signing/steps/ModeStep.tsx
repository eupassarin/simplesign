import { Layers3, Split, Zap } from "lucide-react"
import { Input } from "@/components/ui/input"
import { ChoiceCard, Field, Section, ToggleRow } from "../ui"
import { useSigning } from "../state"

export function ModeStep() {
  const { options, update, state } = useSigning()
  return (
    <div className="space-y-8">
      <Section title="How to sign" description="The same signature, three ways to produce it. Options a mode does not support were already hidden or disabled in the earlier steps.">
        <div className="grid gap-3 md:grid-cols-3">
          <ChoiceCard selected={options.mode === "Sign"} onSelect={() => update({ mode: "Sign" })} title="Sign now" infoId="mode.Sign" icon={<Zap className="size-4" />}
            description="PadesSigner.Document(pdf)…SignWithDetailsAsync(): one call, reports the achieved level." state={state("mode.Sign")} />
          <ChoiceCard selected={options.mode === "Deferred"} onSelect={() => update({ mode: "Deferred" })} title="Deferred (two phases)" infoId="mode.Deferred" icon={<Split className="size-4" />}
            description="Prepare → sign the signed attributes elsewhere → complete. The TestBench plays both sides and shows the intermediate data." state={state("mode.Deferred")} />
          <ChoiceCard selected={options.mode === "Batch"} onSelect={() => update({ mode: "Batch" })} title="Batch" infoId="mode.Batch" icon={<Layers3 className="size-4" />}
            description="BatchSigner: copies of this document with one configuration and bounded concurrency." state={state("mode.Batch")} />
        </div>
      </Section>

      {options.mode === "Deferred" && (
        <ol className="text-muted-foreground list-decimal space-y-1 rounded-lg border p-4 pl-8 text-sm">
          <li><b className="text-foreground">Prepare</b> (server): the PDF gets the signature field and a placeholder; <code className="font-mono text-xs">HashToSign</code> holds the DER signed attributes and the session is sealed with an integrity key.</li>
          <li><b className="text-foreground">Sign</b> (signer): a browser + local agent, a token or a cloud service signs those bytes and returns the raw signature.</li>
          <li><b className="text-foreground">Complete</b> (server): <code className="font-mono text-xs">DeferredSigner.Resume(session, key).CompleteAsync(signature)</code> embeds it and adds timestamps / LTV.</li>
        </ol>
      )}

      {state("batch").visible && (
        <div className="grid max-w-md grid-cols-2 gap-4">
          <Field label="Copies" description="1–50 documents."><Input type="number" min={1} max={50} value={options.batchCopies} onChange={(e) => update({ batchCopies: Number(e.target.value) })} /></Field>
          <Field label="Max concurrency" description="WithMaxConcurrency (1–16)."><Input type="number" min={1} max={16} value={options.maxConcurrency} onChange={(e) => update({ maxConcurrency: Number(e.target.value) })} /></Field>
        </div>
      )}

      <ToggleRow checked={options.validate} onChange={(validate) => update({ validate })} label="Validate the result"
        description={options.environment === "Sandbox" ? "PdfSignatureValidator + BrasilExtension, trusting the sandbox root." : "PdfSignatureValidator + BrasilExtension, trusting the OS and ICP-Brasil roots (needs the network)."} />
    </div>
  )
}
