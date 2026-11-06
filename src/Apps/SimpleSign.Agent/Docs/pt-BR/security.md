# Segurança

## O que o agente garante

- **A chave privada fica aqui.** O agente devolve assinaturas, nunca chaves. Em um token ou smartcard a chave nem tem como sair do dispositivo.
- **Só este computador fala com ele.** Ele ouve em `127.0.0.1`, que outras máquinas da rede não conseguem chamar.
- **Os sites precisam ser autorizados.** A primeira chamada de um site pergunta a você. O site é reconhecido pela origem exata: `https://banco.example` e `https://banco.example:8443` são sites diferentes.
- **Cada assinatura é confirmada.** A confirmação mostra o site, o nome do documento e o certificado. Estar autorizado deixa o site listar certificados, não assinar sozinho.
- **O PIN nunca passa pela página.** Você digita na janela do agente, ou no teclado da leitora. Ele fica só na memória e, por padrão, nem fica.
- **Limites.** Pedidos de até 1 MB, 100 itens por pedido de assinatura, 20 chamadas por minuto por site.

## O que você deve fazer

- Confirme só as assinaturas que você iniciou. Uma confirmação inesperada é motivo para recusar.
- Leia o endereço do site na confirmação, não só o nome.
- Use **Permitir sempre** só nos sites que você usa com frequência. Remova em **Sites** os que não usa mais.
- Deixe **Lembrar o PIN do token** em *Nunca* em um computador compartilhado.

## O que o agente não faz

- Não abre, não lê e não envia os seus arquivos. O site manda os bytes a assinar; o documento fica com o site.
- Não valida o conteúdo do documento. O que a confirmação mostra é o que o site diz que está assinando.
- Não envia nada para a internet. Ele só responde a chamadas feitas neste computador.

## Onde ficam os dados

O arquivo de configurações guarda a porta, os sites autorizados e bloqueados e as suas escolhas de idioma e tema. A lista de atividade fica na memória e some quando o agente fecha. Nenhum certificado, chave, PIN ou documento é guardado.
