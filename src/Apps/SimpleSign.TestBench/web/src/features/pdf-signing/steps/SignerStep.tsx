import { CredentialPicker } from "@/features/credentials/CredentialPicker"
import { useSigning } from "../state"

export function SignerStep() {
  const { environment, env, credential, update } = useSigning()
  return <CredentialPicker environment={environment} env={env} credential={credential} onCredential={(facts) => update({ credentialId: facts.id })} />
}
