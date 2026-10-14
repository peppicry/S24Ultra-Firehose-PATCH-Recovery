# Linha do tempo e tentativas

Os horários abaixo são os dos artefatos locais, em **Europe/Berlin, UTC+02**, em 13 e 14/10/2026. Quando não existe timestamp capturado para um acontecimento, ele é apresentado como relato/ordem relativa, sem inventar um horário.

## 13/10: alteração de init_boot e falhas de escrita

O proprietário relatou um clique equivocado no aplicativo. A tela do telefone dizia que software não autorizado tinha sido instalado e mostrava `SECURE CHECK FAIL: init_boot(3)`. A imagem foi fornecida na conversa; a foto original não foi publicada, para evitar metadados e detalhes pessoais.

A inspeção dos arquivos identificou KernelSU. A referência original tinha `init`; a imagem modificada tinha outro `init`, `init.real`, `kernelsu.ko`, `ksu_config` e `stock_image.sha1`. A comparação confirmou preservação do `init` original em `init.real` e correspondência do SHA-1 registrado com a referência.

Foi preparado um pacote com `init_boot.img` e um rawprogram de uma entrada, limitado a LUN0/188944/2048 setores de 4096 bytes. O [XML histórico](../historical/config/rawprogram_init_boot.xml.txt) foi preservado como texto. Houve tentativas tanto pelo XML/FLASH quanto pelo menu WRITE da partição no UnlockTool.

O log manual das [21:54:24](../evidence/unlocktool/2026-10-13_21-54-24_MANUAL_SAVE.txt) registra `Writing init_boot.img ... ->init_boot [188944]... FAIL 7,209s`. A barra de envio podia chegar a 100%; não havia prova de persistência.

Uma pasta denominada `init_boot_pos_falha.img` continha uma **cópia local do original**, não uma nova leitura. A inferência inicial de sucesso baseada nela foi retirada. A [leitura real das 22:03](../evidence/audit/comparacao_pos_write_22-03.json) permaneceu idêntica à imagem modificada, com zero setores diferentes do backup conhecido.

Também se preparou um TAR de uma única partição como alternativa de empacotamento Samsung. A importação/gravação desse TAR não foi demonstrada: o proprietário informou que Download não estava acessível. O código de empacotamento é histórico; a recuperação final não dependeu dele.

Depois da leitura das 22:03, o proprietário relatou **ERASE de gpt_main0 com OK**. Isso foi uma ação anterior à recuperação por PATCH, não um procedimento recomendado nem executado pelos nossos clientes de restauração. Leituras posteriores verificaram GPT principal válida e limites de init_boot conhecidos; a investigação não fez escrita de GPT para tentar contornar a recusa.

## 14/10: sessão direta e diagnóstico

| Horário | Operação e resultado | Fonte |
|---|---|---|
| 10:15:55 | BOOT DEVICE: autenticação, programmer, UFS, tabela e fechamento da conexão | [UnlockTool](../evidence/unlocktool/2026-10-14_10-15-55_BOOT%20DEVICE.txt) |
| 10:18:29 | Cliente COM próprio: NOP recebe ACK false, build e funções | [NOP](../evidence/results/firehose_nop_result.json) |
| 10:26:25–10:26:36 | PROGRAM de 8 MiB; contador 8.257.536 bytes e timeout, sem ACK final | [Tentativa 1](../evidence/results/direct_write_attempt_1.json) |
| Após reinício/reautenticação | READ confirmou a imagem ainda modificada | Resultado posterior e relato de sessão; nem todo snapshot intermediário foi mantido separadamente |
| 10:40:11–10:40:50 | Novo PROGRAM de 8 MiB, timeout de escrita 30 s; mesmo contador e sem confirmação | [Tentativa 2](../evidence/results/direct_write_attempt_2.json) |
| Antes de 11:20 | Investigação do transporte UsbDk/libusb, sem restauração; enumeração temporariamente falhou | [Log salvo](../evidence/transport/usb_debug_read.log) e relatório histórico |
| 11:20:30 | BOOT DEVICE conclui em COM1 após recuperação da enumeração | [UnlockTool](../evidence/unlocktool/2026-10-14_11-20-30_BOOT%20DEVICE.txt) |
| 11:29:00–11:29:02 | PROGRAM em blocos; primeiro MiB recebe recusa de endereço e NAK | [Teste em blocos](../evidence/results/fragmented_write_result.json) |
| 11:29:18 | READ completo: imagem ainda idêntica ao patch inicial; GPT com CRC válido | [Leitura posterior](../evidence/results/current_read_post_fragmented.json) |

O transporte nativo USB não foi a solução. O arquivo persistido registra uma tentativa interrompida na identificação de dispositivo; detalhes adicionais narrados na conversa, inclusive erros de abertura e Code 43, não têm aqui uma captura completa para estabelecer causalidade. Nenhuma escrita via esse transporte foi demonstrada.

Uma busca por loaders alternativos encontrou anúncios BIT-6 e um arquivo público com prefixo `.rtc`, sem cabeçalho ELF convencional. A revisão e permissão de escrita daquele arquivo não foram verificadas. Ele não foi carregado no telefone. Não houve compra de outro programmer.

## 14/10: prova de PATCH e restauração

| Horário | Passo | O que comprova |
|---|---|---|
| 11:47:09–11:47:10 | PATCH de `ANDROID!`, já igual nas duas imagens | [Comando aceito e imagem inalterada](../evidence/results/init_boot_patch_probe_result.json); não prova escrita de valores diferentes |
| 11:50:13–11:50:15 | Palavra original no offset 8 | [ACK e mudança exata da única palavra](../evidence/results/original_word_patch_result.json), confirmada pela leitura completa |
| 11:54:10–11:54:11 | 64 palavras originais adicionais | [Estado planejado idêntico à releitura](../evidence/results/patch_restore_20261014_115410.json) |
| 11:55:15–12:01:41 | 277.570 palavras restantes; setores e imagem completa relidos | [Original restaurado e leitura final verificada](../evidence/results/patch_restore_20261014_115515.json) |
| Após reinício | Proprietário confirma “Abriu o Android” | [Confirmação registrada](../evidence/results/restauracao_confirmada.json), relato do proprietário |

A última execução começou de uma imagem **já parcialmente corrigida** pelos dois testes anteriores. Por isso, seu `before_sha256` é `16012c...`, não o hash inicial `f50885...`. Seu campo `remaining_original_words=277570` representa a quantidade pendente **no início da execução**, não pendências depois da conclusão.

O retorno do Android completou a verificação funcional relatada. Posteriormente, foram feitas apenas organização documental e reverificações de arquivos locais, sem novas operações no aparelho.
