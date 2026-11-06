# Solução de problemas

Comece por **Testar**: ele mostra em que passo falha. O **Sobre** tem *Copiar diagnóstico* para enviar junto com um pedido de suporte.

## O site diz que o agente não está instalado

- Confira a **Visão geral**: o agente precisa estar ativo.
- Confira a porta. O site precisa chamar a mesma porta em que o agente ouve (`{port}` aqui, em Configurações).
- Algumas extensões de navegador e ferramentas de segurança corporativas bloqueiam chamadas a `127.0.0.1`. Tente outro navegador ou uma janela anônima.

## O agente não conseguiu iniciar: a porta está em uso

Outro programa, ou outra cópia do agente, está usando a porta `{port}`. Feche-o e clique em **Tentar de novo**, ou escolha outra porta em Configurações. Se mudar a porta, o site precisa chamar a nova.

## Meu token ou smartcard não aparece

1. Conecte e clique em **Atualizar** na **Visão geral**.
2. Instale o driver do token, do fabricante ou da autoridade certificadora que o emitiu. Sem o driver o computador não conversa com o token.
3. O **Sobre** lista os *Drivers PKCS#11* encontrados. Se o seu não está lá, o agente não sabe onde ele fica.
4. Para um driver em lugar incomum, defina a variável de ambiente `SIMPLESIGN_PKCS11_LIBRARY` com o caminho completo da biblioteca do driver e abra o agente de novo.

## Meu certificado do repositório do sistema não aparece

- Ele precisa ter a chave privada neste computador. Um certificado copiado sem a chave não assina.
- Ele precisa permitir assinatura (uso da chave *assinatura digital* ou *não repúdio*).
- No macOS, o primeiro uso pode pedir permissão para usar a chave nas Chaves. Permita.

## O PIN é recusado

O PIN é do token, não do agente. Depois de algumas tentativas erradas o token se bloqueia, e só a autoridade certificadora ou a ferramenta do próprio token desbloqueia. Pare de tentar e confira o PIN.

## O site não perguntou, ou pergunta sempre

- Um site liberado com **Permitir** pergunta de novo depois que o agente reinicia. Use **Permitir sempre** nos sites que você usa com frequência.
- Um site na lista de **Bloqueados** é recusado sem perguntar. Desbloqueie em **Sites**.

## A janela de confirmação não aparece

Ela abre por cima das outras janelas, mas pode estar em outra tela ou área de trabalho. Procure as janelas do agente, ou responda ao pedido pendente antes de iniciar outro.

## O macOS ou o Windows se recusa a abrir o app

Os downloads ainda não têm assinatura de código. No macOS, clique com o botão direito no app e escolha **Abrir** na primeira vez. No Windows, escolha **Mais informações** e **Executar assim mesmo**.
