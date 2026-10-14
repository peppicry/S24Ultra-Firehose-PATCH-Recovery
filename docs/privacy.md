# Preservação e sanitização

## Originais

Foram selecionados **58 arquivos originais locais**: 50 fontes textuais exportadas e oito binários representados apenas por hashes/tamanhos. O processo de documentação apenas os leu. Registrou seus SHA-256 e verificou novamente esses bytes ao concluir a exportação. Uma checagem posterior confirma a preservação antes da publicação.

Fotos anexadas, dumps de dados do usuário, EFS e outros arquivos não selecionados não foram copiados ou alterados. O repositório de documentação não inclui diretórios de outros projetos da máquina.

## Material mantido no Git

- Fontes dos clientes escritos na investigação, como texto `.py.txt`.
- JSONs de resultados e auditoria com caminhos pessoais substituídos.
- Logs do UnlockTool convertidos de HTML para texto, sem estilos.
- Números de setor, hashes de integridade, versão/build do programmer, versão do driver e rótulos COM efêmeros relevantes à análise.
- Declaração de boot como relato do proprietário, sem reproduzir fotos ou dados de conta.

## Material removido ou mantido somente localmente

- Caminhos absolutos do perfil/área de trabalho: substituídos por `<WORKSPACE>`, `<DOWNLOADS>` ou `<USER_HOME>`.
- Campos `received_hex`/`initial_received_hex`, que duplicavam a captura textual e eram menos auditáveis para dados ocultos.
- Campos de IDs de processo/thread, irrelevantes à conclusão.
- Handles, IDs de thread e endereços de contexto do host no log USB de debug.
- Fotos, imagens de partições, GPT binária, executáveis, loaders, DLLs e ramdisk extraído.
- Inventário com os caminhos reais dos originais; esse arquivo privado não foi incluído.

Nenhuma credencial de autenticação, licença do UnlockTool, IMEI ou serial real do aparelho foi necessária para a documentação. O diagnóstico Firehose salvo retornou serial/chip ID zero; isso não permite identificar esses valores reais. Não houve extração de dados de autenticação do processo ou do servidor.

Os placeholders documentam uma alteração editorial de privacidade. Os hashes de origem e de exportação são separados. Textos antigos com problemas de codificação podem conservar caracteres de substituição; a declaração de conclusão legível no README está baseada no resultado estruturado e no relato registrado, não em uma restauração inventada do texto bruto.

## Prevenção de inclusão acidental

`.gitignore` exclui imagens, loaders, arquivos compactados, chaves e diretórios privados. Os testes também examinam a árvore textual, verificam as extensões proibidas e recusam imports de COM, USB ou rede nos utilitários executáveis. O código histórico é analisado por AST apenas para sintaxe, sem execução/importação.

Esses testes validam o conjunto atual de arquivos; não prometem sanitizar automaticamente qualquer dump ou captura futura. Novas evidências precisam passar pela mesma revisão antes de serem adicionadas.
