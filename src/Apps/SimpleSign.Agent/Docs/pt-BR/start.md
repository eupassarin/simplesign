# Primeiros passos

## 1. Confira se o agente está ativo

A **Visão geral** mostra *O agente está ativo* e o endereço em que ele ouve. O ícone da bandeja diz o mesmo: cheio quando ativo, só o contorno quando pausado.

## 2. Confira o seu certificado

O seu certificado deve estar na lista da **Visão geral**:

- **Repositório do sistema**: certificados instalados no computador (as Chaves no macOS, o repositório pessoal no Windows).
- **Token ou smartcard**: conecte e clique em **Atualizar**. O driver do token precisa estar instalado.

Certificados sem chave privada, ou que não servem para assinar, não aparecem.

## 3. Faça o teste

Abra **Testar** e inicie. Ele faz as mesmas chamadas que um site faz e termina conferindo a assinatura. Se o teste passa, o agente, o certificado e a chave funcionam.

## 4. Assine em um site

Na primeira vez que um site chama o agente, você responde se ele pode usar os seus certificados:

- **Permitir**: por agora, até o agente fechar.
- **Permitir sempre**: o site vai para a lista de **Sites** e não pergunta de novo.
- **Recusar**: o site não recebe nada.

Depois disso, **cada assinatura** pede a sua confirmação, e o token pede o PIN.

> Só confirme uma assinatura que você mesmo iniciou no site. Se uma confirmação aparecer do nada, recuse.

## Bom saber

- **Iniciar com o sistema** (Configurações) abre o agente na bandeja quando você entra no computador.
- **Lembrar o PIN do token** (Configurações) mantém o token destravado por alguns minutos, para um lote de documentos não pedir o PIN a cada um. O padrão é perguntar sempre.
- Você pode remover ou bloquear um site a qualquer momento em **Sites**.
