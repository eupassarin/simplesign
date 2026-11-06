# Como funciona

O SimpleSign Agent é um programa pequeno que fica na bandeja (a barra de menus, no macOS). Ele deixa uma página web assinar com um certificado que está **neste computador**: o repositório de certificados do sistema, um token A3 ou um smartcard.

A página nunca vê a chave privada. Ela manda os bytes a assinar e recebe a assinatura.

## O fluxo

1. O servidor do site prepara o documento e calcula o que precisa ser assinado.
2. A página chama o agente em `http://127.0.0.1:{port}`, neste computador.
3. O agente pede a **sua** confirmação, mostrando o site, o documento e o certificado. Com token, ele pede o PIN na própria janela.
4. A chave assina. Com token, a assinatura é feita dentro do token.
5. A página manda a assinatura para o servidor, que conclui o documento assinado.

> Um navegador não consegue acessar um token nem o repositório de certificados sozinho. O agente é a ponte, e só funciona para os sites que você autorizar.

## O que há nesta janela

| Seção | Para que serve |
| --- | --- |
| **Visão geral** | Se o agente está ativo e os certificados que ele encontrou. |
| **Sites** | Os sites que você autorizou ou bloqueou. |
| **Atividade** | O que o agente fez desde que iniciou. |
| **Testar** | Um teste de ponta a ponta com o seu certificado real. |
| **Documentação** | Estas páginas. |

Configurações e Sobre abrem pelos ícones no canto superior direito. Fechar a janela não para o agente: ele continua na bandeja até você escolher **Sair** ali.

## A seguir

- Chegou agora? Leia [Primeiros passos](#start).
- Está construindo um site que assina? Leia [Integração](#integration).
- Algo não funciona? Leia [Solução de problemas](#troubleshooting).
