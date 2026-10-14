# Referências e proveniência

Os logs e binários preservados são a evidência do caso. As referências abaixo explicam contratos e formatos; não substituem prova do comportamento deste aparelho.

- [Microsoft: Communications Resource Handles](https://learn.microsoft.com/en-us/windows/win32/devio/communications-resource-handles) — abertura e exclusividade do recurso COM por `CreateFile`.
- [pySerial v3.5: serialwin32.py](https://github.com/pyserial/pyserial/blob/v3.5/serial/serialwin32.py) — backend correspondente à versão usada; a inspeção do módulo local confirma o caminho de `PurgeComm` na abertura. O hash do módulo local está documentado separadamente e não é apresentado como hash do upstream.
- [bkerler/edl: transporte serial](https://github.com/bkerler/edl/blob/master/edlclient/Library/Connection/seriallib.py) — referência consultada para parâmetros seriais, sem executar seu upload/detecção automática de loader nesta recuperação.
- [bkerler/edl: Firehose](https://github.com/bkerler/edl/blob/master/edlclient/Library/firehose.py) — referência da codificação XML de PATCH, incluindo valor little-endian e `filename="DISK"`.
- [bkerler/edl, issue 737](https://github.com/bkerler/edl/issues/737) — investigação primária de terceiros sobre mensagens após ACK e restrições de setores em alguns loaders Samsung. Não se demonstrou identidade do seu loader com o nosso.
- [Android: Verified Boot 2.0](https://android.googlesource.com/platform/external/avb/+/master/README.md) — contexto dos descritores, dados autenticados e confiança na chave.
- [Android: Boot image header](https://source.android.com/docs/core/architecture/bootloader/boot-image-header) — estrutura de headers de boot/init_boot.
- [UEFI: GPT format](https://uefi.org/specs/UEFI/2.10/05_GUID_Partition_Table_Format.html) — header, matriz de entradas e respectivos CRCs.
- [libusb: Windows](https://github.com/libusb/libusb/wiki/Windows) e [UsbDk](https://github.com/daynix/UsbDk) — contexto da alternativa USB investigada, que não concluiu a recuperação.

Os links `master` e wikis podem mudar. A evidência primária retida são os snapshots dos nossos clientes, seus hashes de origem/exportação e os resultados. O backend pySerial é referenciado por tag de versão. Não são distribuídas cópias de firmware/programmers ou bibliotecas de terceiros sob uma licença presumida.

## Evidências decisivas do próprio caso

| Conclusão | Artefato |
|---|---|
| App encerrou a conexão preparada | BOOT DEVICE de 10:15:55, em `evidence/unlocktool` |
| Outro cliente alcançou XML Firehose | `firehose_nop_result.json` |
| PROGRAM recusou o endereço | `fragmented_write_result.json` |
| PATCH mudou exatamente a primeira palavra | `original_word_patch_result.json` |
| Original completo foi relido | `patch_restore_20261014_115515.json` |
| Integridade repetida sem aparelho | `evidence/reproduction/offline_verification.json` |

Os sources e exports são listados em [source_manifest.json](../evidence/source_manifest.json); nenhum segredo de autenticação é uma dependência para ler este arquivo de investigação.
