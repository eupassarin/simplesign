# Roteiro da auditoria de acreditação (INDECOPI)

Passo a passo do que preparar, executar e mostrar ao auditor para acreditar o `SimpleSign.Peru.Iofe.Accredited` e os
comandos `simplesign iofe` pela *Guía de Acreditación de Aplicaciones de Software* v4.0, seções 4.2, 4.3 e 4.4.
Tudo aqui foi ensaiado numa máquina de desenvolvimento (macOS) contra o ambiente de teste; o que não foi ensaiado
está dito como tal.

Outras línguas: [English](audit-walkthrough.md) · [Español](guion-de-auditoria.md).

O que se entrega ao auditor são os manuais em espanhol ([`acreditacion/`](acreditacion/README.md), também em
[inglês](acreditacion/en/README.md)) e as evidências que este roteiro produz. Este documento é para a sua equipe.

## 1. Como a acreditação funciona

Do capítulo 6 do guia ("Procedimientos de evaluación"):

1. Escolhido o auditor, ele entrega a lista de requisitos conforme o tipo de software.
2. O auditado **sustenta o alcance** da acreditação e **justifica a não aplicabilidade** do que não se aplica.
3. A sessão de auditoria é presencial: o auditado apresenta **todas as evidências de cada item**. O Anexo B pede uma
   **captura de tela por requisito** e, quando um certificado é usado num teste, a imagem do perfil desse certificado.
4. O auditor entrega um relatório ao auditado e à comissão, com observações e recomendações.
5. O auditor expõe as evidências à comissão.
6. Aprovada, o auditado **apresenta as funções da aplicação aos comissionados** antes da resolução.
7. A comissão emite a Resolução de Acreditação.

Depois: **avaliação de seguimento anual, em ambiente de produção real** (confiança, revogação e validade do
certificado antes de assinar), e avaliação de atualização quando o alcance muda. Taxas, prazos e formulários não estão
no guia: confirme com o INDECOPI.

O que é de cada um:

| Do software (este roteiro demonstra) | Do operador (procedimentos e documentos seus) |
|---|---|
| Verificações do certificado, lista de confiança, auditoria, transações, chave só em módulo ou serviço remoto, visor, carimbo de tempo, manuais | Certificação FIPS/Common Criteria do HSM ou acreditação do prestador remoto, custódia de chaves com dois responsáveis, controle de acesso ao sistema, assinatura de código do seu instalador |

## 2. O que demonstra que é a lib acreditada

| Ferramenta | Usa `IofeSigningAgent` / `IofeVerificationAgent`? |
|---|---|
| `simplesign iofe sign \| verify \| view` | **Sim** |
| `auditoria.py` (este roteiro) | **Sim**: só executa os comandos acima |
| `SimpleSign.Peru.Iofe.Accredited.Tests` | **Sim** |
| TestBench (playbooks) e `simplesign sign --profile iofe` | Não: assinadores gerais. Servem de material complementar, nunca de evidência do pacote |

## 3. Pré-requisitos

- .NET SDK 8 ou 10, Python 3.9+, `curl`.
- Para a trilha PKCS#11 do ensaio: SoftHSM2 e OpenSC (`brew install softhsm opensc openssl@3 jq`, ou
  `apt-get install softhsm2 opensc openssl curl jq`).
- No dia, no lugar do ensaio: o HSM real (ou o serviço de assinatura remota real), o certificado real, a TSA real.

## 4. Subir o ambiente de ensaio

Na raiz do repositório, em dois terminais:

```bash
dotnet run --project src/Apps/Development/SimpleSign.Sandbox -- --ephemeral
```

```bash
tools/stack/softhsm-provision.sh
```

```bash
export SOFTHSM2_CONF="$PWD/.softhsm/softhsm2.conf"
```

O primeiro é a PKI de teste (http://localhost:5300): certificados bons e ruins, CRL por HTTP/HTTPS/LDAP, OCSP, TSA,
lista de confiança no formato do INDECOPI e um serviço de assinatura remota. O segundo carrega num token SoftHSM as
chaves de teste, os certificados das ACs emissoras e uma chave marcada como extraível (a que o agente deve recusar).

Alternativa com Docker, não ensaiada nesta rodada: `tools/stack/up.sh --no-dss`. No Windows há os equivalentes
`tools/stack/*.ps1`, também não ensaiados.

## 5. Instalar a CLI e a extensão IOFE

No ensaio, a partir do código (as versões publicadas vêm do nuget.org no dia):

```bash
dotnet pack src/Apps/SimpleSign.Cli -c Release -o ./nupkgs
```

```bash
dotnet pack src/Extensions/Peru/Iofe/SimpleSign.Peru.Iofe.Cli -c Release -o ./nupkgs
```

```bash
dotnet tool install --global SimpleSign.Cli --add-source ./nupkgs --version 0.12.0
```

```bash
simplesign extension install SimpleSign.Peru.Iofe.Cli --source ./nupkgs
```

```bash
simplesign extension list
```

```bash
simplesign version
```

Mostre ao auditor: `simplesign version` (item "a" do alcance), `simplesign extension list` e
`simplesign iofe sign --help`, em que **não existe** opção de política, de pular verificação nem de arquivo PFX.

Autenticidade do software (Req. 17, 27): `dotnet nuget verify <pacote>.nupkg` mostra a assinatura de repositório do
nuget.org nos pacotes publicados. Um pacote gerado localmente responde "The package is not signed". **A assinatura de
código do autor está em aberto** (seção 11).

## 6. Rodar o roteiro inteiro

```bash
python3 src/Extensions/Peru/Iofe/tools/auditoria/auditoria.py --key both --lang pt --out evidencias
```

São 70 cenários; com as duas fontes de chave, 110 execuções (cerca de 5 minutos). Resultado do ensaio: **110
conformes, 0 não conformes, 0 omitidos**.

Para cada cenário o roteiro prepara o Sandbox (liga uma falha, revoga, cria credencial), roda `simplesign iofe …`,
confere a assinatura ou a recusa **e o motivo**, e desfaz a preparação. Em `evidencias/`:

| Arquivo | O que é |
|---|---|
| `informe.es.html`, `informe.en.html`, `informe.pt.html` (e `.md`) | O relatório por item do Anexo B: o que o guia pede, cenários, resultado, e cada comando com a saída |
| `NN-cenario-chave/comandos.txt` | Os comandos executados e a saída de cada um |
| `NN-…/auditoria.jsonl`, `verificacion.jsonl` | A trilha de auditoria do cenário |
| `NN-…/firmado-*.pdf`, `comunicado.txt`, `visor.html` | O documento assinado, o comunicado ao remetente, a página do visor |
| `NN-…/sandbox-log.json` | As requisições que o agente fez à CRL, ao OCSP, à TSA e ao serviço remoto |

Opções úteis: `--key remote` (padrão; não precisa de token), `--key pkcs11`, `--list`, `-v` (mostra tudo),
`--cli "caminho/simplesign"`, `--sandbox URL`.

## 7. Demonstração ao vivo, item a item

O auditor escolhe um item; rode-o e ele narra cada passo:

```bash
python3 src/Extensions/Peru/Iofe/tools/auditoria/auditoria.py --item F-8 --key both --lang pt
```

```bash
python3 src/Extensions/Peru/Iofe/tools/auditoria/auditoria.py --scenario contingencia --lang pt
```

Sequência sugerida (cada linha é um `--scenario`):

| O que mostrar | Cenários | Itens |
|---|---|---|
| Lista de confiança: vigente; de outro signatário; alterada; expirada; raiz não listada | `tsl-vigente`, `tsl-otro-firmante`, `tsl-alterada`, `tsl-expirada`, `raiz-no-listada` | F-1 a F-3 |
| CRL por HTTP, HTTPS e LDAP; de chave errada; vencida; sem próxima atualização | `crl-http`, `crl-https`, `crl-ldap`, `crl-clave-ajena`, `crl-expirada`, `crl-sin-proxima-actualizacion` | F-5 a F-7 |
| Revogado não assina; sem CRL nem OCSP não assina; AC emissora revogada | `revocado`, `revocacion-no-disponible`, `cadena-revocada` | F-8, F-9 |
| OCSP: bom, revogado, resposta não autorizada | `ocsp-vigente`, `ocsp-revocado`, `ocsp-no-autorizado` | F-10 |
| Expirado, ainda não válido, AC expirada | `expirado`, `aun-no-valido`, `ec-expirada` | F-11 |
| Sem nonRepudiation; sem uso de chave para assinar | `sin-no-repudio`, `sin-uso-de-firma` | F-12 |
| Nada se desliga; contingência declarada; revogado sob contingência; contingência vencida | `sin-opcion-de-politica`, `contingencia`, `contingencia-revocado`, `contingencia-vencida` | F-14 |
| Auditoria: registros, cadeia íntegra, cadeia adulterada; sem registro não assina | `auditoria`, `sin-registro-de-auditoria` | F-15 |
| Transação não definida | `transaccion-no-definida` | F-16 |
| **Trilha PKCS#11**: chave no módulo; chave extraível; módulo não declarado | `clave-en-el-modulo`, `clave-extraible`, `modulo-no-declarado` | F-17 a F-19 |
| **Trilha remota**: chave no serviço; serviço não declarado; credencial que exige pessoa | `clave-en-el-servicio-remoto`, `servicio-no-declarado`, `credencial-con-persona` | F-16 a F-19 |
| PFX não é aceito; PIN errado | `pfx-no-aceptado`, `pin-incorrecto` | F-17, F-18 |
| Algoritmos: chave fraca, SHA-1 na cadeia, algoritmos vigentes | `clave-debil`, `sha1-en-la-cadena`, `algoritmos-vigentes` | F-28 |
| Visor; dados de validação (B-LT); XML e CMS | `visor`, `datos-de-validacion`, `formatos` | F-30, F-31 |
| Carimbo de tempo: outra autoridade, carimbo alterado, TSA revogada, TSA expirada | `tsa-otra-autoridad`, `tsa-sello-alterado`, `tsa-revocada`, `tsa-expirada` | S-1 a S-4 |
| Verificação: válido; revogado com comunicado; alterado; sem assinaturas; contingência; auditoria | `v-valido`, `v-revocado`, `v-documento-alterado`, `v-sin-firmas`, `v-contingencia`, `v-auditoria` | V-1 a V-15, V-30 |

Para a captura de tela que o Anexo B pede, use o terminal com o cenário ao vivo ou a seção do cenário em
`informe.es.html`. O perfil do certificado usado sai de `simplesign pkcs11 list --lib <driver>` (trilha PKCS#11) ou
`simplesign csc list --csc-url … --csc-token …` (trilha remota), e de `simplesign iofe view`.

## 8. Relatório da suíte de testes por item

```bash
dotnet test tests/unit/Extensions/Peru/Iofe/SimpleSign.Peru.Iofe.Accredited.Tests --framework net10.0 --filter "AnnexB~-" --logger "html;LogFileName=anexo-b.html" --results-directory evidencias/pruebas
```

```bash
dotnet test tests/unit/Extensions/Peru/Iofe/SimpleSign.Peru.Iofe.Accredited.Tests --filter "AnnexB=F-8"
```

No ensaio: 33 passaram e 6 foram pulados, porque os testes de token precisam do SoftHSM; em Docker,
`scripts/tests/pkcs11.sh` roda todos sem pular. `AnnexBCoverageTests` falha se algum item demonstrável ficar sem
teste ou sem cenário.

## 9. No dia: o que troca

| No ensaio | No dia |
|---|---|
| Sandbox (PKI de teste) | A PKI real: certificado emitido por uma EC acreditada |
| `--tsl http://localhost:5300/tl/tl.xml --tsl-signer …` | Nada: por padrão o agente usa a TSL do INDECOPI |
| Token SoftHSM, `--module-… "SoftHSM…"` | O HSM real: `--pkcs11-lib` do fabricante e `--module-manufacturer/-model/-certification/-certificate` com os dados do certificado FIPS 140-2 ou Common Criteria |
| Serviço remoto do Sandbox | O serviço do prestador: `--csc-url`, credenciais de cliente e `--service-…` com a acreditação dele |
| TSA do Sandbox | A TSA contratada: `--tsa URL --tsa-cert arquivo` |
| Pacotes locais | `dotnet tool install --global SimpleSign.Cli` e `simplesign extension install SimpleSign.Peru.Iofe.Cli` do nuget.org |

No HSM real, **carregue no módulo os certificados das ECs emissoras** junto do certificado de assinatura: o agente
monta a cadeia com o que está no módulo e na lista de confiança. Sem eles a assinatura é recusada com
`UntrustedRoot` (foi o que o ensaio mostrou antes de o token de teste recebê-los).

Os cenários de falha (CRL adulterada, TSA revogada) dependem do Sandbox: com a PKI real mostra-se o caminho bom e as
recusas que não exigem falha de terceiros (transação, módulo não declarado, opção inexistente, PFX, contingência). O
restante vem do relatório do ensaio. **Não ensaiado**: HSM real, serviço remoto real e a TSL real do INDECOPI nesta
rodada.

## 10. Preencher o Anexo B

Use `evidencias/informe.es.html`: a tabela "Por ítem del Anexo B" dá, para cada item, os cenários e o resultado; cada
cenário tem o comando e a saída. A correspondência completa, com os testes, está em
[`playbooks/indecopi-checklist.md`](../playbooks/indecopi-checklist.md) (tabela "Shown by the accredited package
itself"). Os dados do alcance (itens a–k) estão em [`acreditacion/alcance.md`](acreditacion/alcance.md).

Itens a declarar como **não aplicáveis ou a cargo do operador**, com a justificativa:

| Itens | Justificativa |
|---|---|
| F-13, V-13 | Controle de acesso é do produto e do sistema que hospeda a biblioteca |
| F-20 a F-27, V-18 a V-27 | Custódia da chave: operação do HSM. Com chave em serviço remoto, o módulo é do prestador |
| V-16, V-17, V-31 | O agente de verificação não assina os documentos recebidos |
| F-4, V-4 | Recarga periódica da TSL: é da biblioteca (`IofeTrustedListSource`), comprovada por testes, não por comando |
| F-29, V-29 | **Em aberto** (seção 11) |
| Seção 4.1 | Fora do alcance deste pacote |

## 11. O que não está coberto, e o que o ensaio mostrou

- **Assinatura de código (F-29 / V-29): em aberto.** Os pacotes não têm assinatura de autor nem os assemblies
  Authenticode. Depende do certificado de assinatura de código.
- **PFX / PKCS#12 não é fonte de chave** do pacote acreditado, por contrariar o Req. 15. Não há opção que o habilite.
- **Seção 4.1** (software de usuário final) não é coberta.
- **Trilha remota**: a acreditação do prestador e a não extraibilidade da chave são declaração do operador; o
  protocolo não as informa.
- Recusas que ocorrem **antes de o agente abrir** — lista de confiança ilegível, PIN errado no módulo — saem no
  terminal com o motivo, mas **não geram registro na trilha de auditoria**.
- O **comunicado ao remetente** é em espanhol, mas alguns motivos saem em inglês (por exemplo "Certificate revocation
  check failed.").
- Um carimbo de tempo com a assinatura alterada é recusado, mas com o motivo classificado como `NetworkFailure`.
- O agente assina em B-B (sem TSA) ou B-LT (com TSA); não há B-LTA no pacote acreditado.

## 12. Problemas comuns

| Sintoma | Causa e solução |
|---|---|
| `Error (RevocationStatusUnknown)` contra o Sandbox | A CLI recusa endereços locais: acrescente `--allow-origin http://localhost:5300` (o roteiro já faz isso) |
| `Error (UntrustedRoot)` na trilha PKCS#11 | Faltam no token os certificados das ACs emissoras: `tools/stack/softhsm-provision.sh --force` |
| Cenários `(pkcs11)` omitidos | `SOFTHSM2_CONF` não está exportada ou o token não foi provisionado |
| `Unknown option --…` em `simplesign iofe` | A opção não existe nesse comando; opções desconhecidas são erro, de propósito |
| O Sandbox reiniciou e o token "não bate" | Cada Sandbox `--ephemeral` tem uma PKI nova: rode o provisionamento de novo |

## 13. Ordem sugerida da apresentação

1. Alcance e não aplicabilidade (`alcance.md`, seção 10) — 10 min.
2. Instalação e versão; `iofe sign --help` sem opções de contorno — 5 min.
3. Relatório do roteiro completo (`informe.es.html`) — 10 min.
4. Itens ao vivo, à escolha do auditor (seção 7) — 30 a 40 min.
5. Trilha de auditoria: `simplesign audit verify`, registro adulterado — 5 min.
6. Visor e comunicado ao remetente — 5 min.
7. Relatório de testes por item — 5 min.
8. Manuais e configuração de segurança; pendências (seção 11) — 10 min.
