# Fatos, hipóteses e limites

## Classificação das conclusões

| Afirmação | Categoria | Base / limite |
|---|---|---|
| A imagem inicial tinha alterações KernelSU | Comprovado por arquivos | Comparação CPIO, init.real, módulo e SHA-1 registrado |
| O original correspondia ao hash esperado pelo vbmeta raiz | Comprovado por arquivos | Descritor salgado, hash do bloco e assinatura interna; repetidos offline |
| BOOT DEVICE informou autenticação e upload do programmer | Comprovado como saída do aplicativo | Log histórico; não houve captura da conversa de autenticação com o servidor |
| O UnlockTool fechou sua conexão | Comprovado como saída do aplicativo e coerente com o acesso posterior | `Closing connection... OK`; depois CreateFile/NOP do cliente próprio funcionou |
| O estado Firehose foi reutilizado por outro cliente | Comprovado operacionalmente | Cliente sem upload/Sahara recebeu NOP/READ/PATCH na COM |
| O loader permanecia executando em RAM após fechar o handle | Explicação arquitetural consistente, sem inspeção da localização | Não houve dump de memória, PC/register trace ou hash do código carregado |
| PROGRAM recusou o setor 188944/LUN0 | Comprovado no teste em blocos | Mensagem explícita + NAK |
| Os timeouts anteriores tiveram exatamente a mesma causa | Hipótese | Não houve NAK capturado nas tentativas grandes |
| PATCH gravou valores diferentes no mesmo endereço de partição | Comprovado por leitura | Mudança exata da palavra e depois dos setores/imagem completa |
| A diferença entre handlers é um bug de autorização específico | Hipótese sobre implementação | Não se analisou o binário carregado nem suas regras internas |
| ZLP=0, controles seriais ou maior timeout foram a causa da recuperação | Não demonstrado | Parâmetros variaram; PROGRAM continuou recusado e PATCH foi a operação que persistiu dados |
| O Android abriu após reinício | Relato confirmado do proprietário | Registro da resposta; não houve observação independente pelo cliente Python |
| O aparelho inteiro ficou igual ao firmware oficial | Não demonstrado | A comparação completa foi de init_boot; não se auditou toda a memória |
| ERASE OK prova capacidade de PROGRAM em init_boot | Não demonstrado | Comandos diferentes e endereços diferentes |

## Limites técnicos da implementação histórica

1. **Detecção de dispositivo:** VID/PID e COM selecionada, somados aos hashes/GPT do caso, vincularam o alvo. VID/PID sozinhos não identificam de forma única um S24 Ultra.
2. **Programmer:** build anunciada por NOP, sem arquivo binário ou SHA do código carregado. Não se confirmou se um anúncio comercial de loader oferecia o mesmo código ou outro.
3. **Autenticação:** o UnlockTool realizou a etapa registrada. Nosso cliente não explica nem reproduz independentemente o mecanismo de autorização de servidor/Sahara.
4. **Buffer de abertura:** o comentário sobre `_reset_input_buffer` era incorreto para o backend Windows, que faz `PurgeComm` diretamente. Não foi necessário esse efeito suposto para o sucesso.
5. **Streaming PROGRAM:** o cliente antigo não tratava recusa recebida depois do ACK inicial enquanto transmitia o payload. Não é uma referência de implementação geral para PROGRAM.
6. **Parser XML:** o histórico busca `</data>` e assume os documentos observados; não é um parser genérico de streams arbitrários. O payload READ usa comprimento exato, para não interpretar firmware como XML.
7. **Timeout:** após resposta incompleta/estado raw incerto, a sessão era abandonada. Não existe protocolo de recuperação universal daquela situação demonstrado aqui.
8. **Retomada:** valida palavras originais ou do backup conhecido. Isso não garante atomicidade de oito bytes se ocorrer queda de energia no meio de uma operação. Uma palavra desconhecida precisa ser investigada; o código recusa continuar silenciosamente.
9. **Registros:** eventos finais limitados a 80 e contadores agregados. A persistência de cada palavra não está acompanhada de um log individual completo, embora os setores e a imagem final tenham sido relidos.
10. **Estado funcional:** a confirmação de boot não constitui teste de todos os sensores, rádio, dados do usuário, eFuses ou garantias de segurança.

## Preservação de GPT e outros dados

O proprietário relatou ERASE anterior de gpt_main0. Os clientes de recuperação não utilizaram esse caminho para obter permissão e não restauraram GPT. Os CRCs e limites atuais verificados foram suficientes para restringir init_boot; não se confundiu validade do header/entradas com igualdade de todos os bytes do dump ou integridade da GPT reserva.

Boot, recovery e vendor_boot de leituras anteriores corresponderam aos descritores esperados. Isso não foi estendido a todas as partições/hashtrees. A confirmação de integridade do original contra a chave embutida também não foi transformada em autenticação independente de fabricante.

## Alcance da descoberta

O resultado é um caso de **restauração de bytes originais** usando uma sessão preparada por ferramenta autorizada no ambiente observado. Não foi feito patch do Firehose, extração de credenciais, alteração de vbmeta para aceitar software modificado ou upload de um loader alternativo.

Não há base neste material para declarar vulnerabilidade universal, atribuir um CVE, prometer suporte a outro BIT/modelo ou garantir a mesma permissão em outra versão do programmer. A descrição do procedimento histórico e a reprodução offline são mais estreitas que uma reprodução de hardware.
