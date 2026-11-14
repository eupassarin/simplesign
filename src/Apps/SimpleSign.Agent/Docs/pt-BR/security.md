# Segurança

## O que o agente garante

- **A chave privada fica aqui.** O agente devolve assinaturas, nunca chaves. Em um token ou smartcard a chave nem tem como sair do dispositivo.
- **Só este computador fala com ele.** Ele ouve em `127.0.0.1`, que outras máquinas da rede não conseguem chamar.
- **Os sites precisam ser autorizados.** A primeira chamada de um site pergunta a você. O site é reconhecido pela origem exata: `https://banco.example` e `https://banco.example:8443` são sites diferentes.
- **Cada assinatura é confirmada.** A confirmação mostra o site, o nome do documento e o certificado. Estar autorizado deixa o site listar certificados, não assinar sozinho.
- **O PIN nunca passa pela página.** Você digita na janela do agente, ou no teclado da leitora. Ele fica só na memória e, por padrão, nem fica.
- **Limites.** Pedidos de até 1 MB, 100 itens por pedido de assinatura, 20 chamadas por minuto por site.
- **Só dados de assinatura são assinados.** Cada item precisa ser atributos assinados CMS ou um `SignedInfo` XML-DSig. Um hash solto, um documento ou qualquer outra coisa é recusado antes de perguntar a você.
- **O token avisa antes de bloquear.** Quando o token diz que um PIN errado foi digitado, o pedido de PIN avisa, e na última tentativa avisa que mais um PIN errado bloqueia o cartão.

## Em uma instalação gerenciada

Existem duas opções para um cenário em que um servidor comanda o agente. As duas ficam desligadas até alguém ligar.

- **Pedidos de assinatura assinados pelo servidor.** Com `signedRequestsRequired`, uma assinatura só é feita quando o pedido traz um token assinado por uma das chaves públicas configuradas. O token indica o site, o certificado e os bytes exatos a assinar, dura no máximo cinco minutos e é aceito uma vez, então a página não consegue repeti-lo nem pedir algo que o servidor não preparou. O que a confirmação mostra passa a vir do token, não da página.
- **Uma lista fixa de sites.** Um administrador pode distribuir um `policy.json` que fixa os sites autorizados e as outras configurações. A seção **Sites** passa a mostrar a lista só para leitura, um site desconhecido é recusado sem perguntar a você, e a janela diz quais configurações o seu administrador fixou.

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

O arquivo de configurações guarda a porta, os sites autorizados e bloqueados, as estruturas de confiança que você habilitou e as suas escolhas de idioma e tema. A lista de atividade fica na memória e some quando o agente fecha. Nenhum certificado, chave, PIN ou documento é guardado.
