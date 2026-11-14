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

## O site recebe "a estrutura de confiança não está habilitada"

Os filtros `country` e `trust`, e o antigo `filterIcpBrasil`, só respondem pelas estruturas habilitadas nas Configurações, em **Estruturas de confiança**. O erro lista quais estão habilitadas. Uma listagem sem filtro não é afetada.

Em um DNIe peruano, o middleware que a RENIEC publica (AuthentIC WebPack) é o que o agente procura; para outro token peruano cujo módulo o agente não conhece, aponte `SIMPLESIGN_PKCS11_LIBRARY` para a biblioteca dele.

## O site recebe "indisponível offline"

IOFE e eIDAS leem uma lista de confiança pela internet, guardam em cache e atualizam a cada seis horas. Enquanto ela não pode ser lida, esses filtros respondem 503 em vez de devolver uma lista menor, e as Configurações mostram *indisponível offline*. Uma nova tentativa acontece um minuto depois. As estruturas do Brasil trazem as raízes dentro do agente e nunca precisam da rede para isso.

## Meu certificado do repositório do sistema não aparece

- Ele precisa ter a chave privada neste computador. Um certificado copiado sem a chave não assina.
- Ele precisa permitir assinatura (uso da chave *assinatura digital* ou *não repúdio*).
- No macOS, o primeiro uso pode pedir permissão para usar a chave nas Chaves. Permita.

## O site recusa meu certificado

O servidor do site confere o certificado antes de assinar. A **Visão geral** marca os certificados que ele vai recusar:

- **Não serve para assinar**: o key usage não permite *assinatura digital* nem *não repúdio*.
- **Chave fraca**: uma chave RSA abaixo de 2048 bits.

Use outro certificado, ou peça um novo à autoridade certificadora. Um certificado com a cadeia expirada também é
recusado.

## O PIN é recusado

O PIN é do token, não do agente. Depois de algumas tentativas erradas o token se bloqueia, e só a autoridade certificadora ou a ferramenta do próprio token desbloqueia. Pare de tentar e confira o PIN.

## O site não perguntou, ou pergunta sempre

- Um site liberado com **Permitir** pergunta de novo depois que o agente reinicia. Use **Permitir sempre** nos sites que você usa com frequência.
- Um site na lista de **Bloqueados** é recusado sem perguntar. Desbloqueie em **Sites**.

## A janela de confirmação não aparece

Ela abre por cima das outras janelas, mas pode estar em outra tela ou área de trabalho. Procure as janelas do agente, ou responda ao pedido pendente antes de iniciar outro.

## O macOS ou o Windows se recusa a abrir o app

Os downloads ainda não têm assinatura de código. No macOS, clique com o botão direito no app e escolha **Abrir** na primeira vez. No Windows, escolha **Mais informações** e **Executar assim mesmo**.
