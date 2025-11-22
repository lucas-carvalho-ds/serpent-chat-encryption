# Manual do Usuário - Serpent Chat

Este manual descreve como utilizar o sistema de chat seguro Serpent Chat.

## 1. Visão Geral

O Serpent Chat é uma ferramenta de comunicação que prioriza a segurança. Ele garante que suas mensagens sejam lidas apenas pelos destinatários autorizados na sala de chat.

## 2. Primeiros Passos

### Iniciando o Servidor

O servidor deve estar rodando para que os clientes possam se conectar.

```bash
python server.py
```

_O servidor escuta na porta 8888 por padrão._

### Iniciando o Cliente

Para entrar no chat, execute o cliente em um novo terminal:

```bash
python client.py
```

## 3. Comandos do Chat

Ao iniciar o cliente, você verá uma interface de terminal. Você deve se autenticar para enviar ou receber mensagens.

### Registrar um Novo Usuário

Se você é um novo usuário, precisa criar uma conta.
**Comando:** `/register <usuario> <senha>`
**Exemplo:** `/register alice minhasenha123`

> **⚠️ IMPORTANTE:** Após o registro, o sistema exibirá um **Segredo TOTP** (ex: `JBSWY3DPEHPK...`).
> **Salve este código!** Você precisará dele para configurar seu aplicativo autenticador (Google Authenticator, Authy, ou script Python) para gerar os códigos de login.

### Fazer Login

Para entrar no chat, você precisa do seu usuário, senha e o código 2FA atual.
**Comando:** `/login <usuario> <senha> <codigo_2fa>`
**Exemplo:** `/login alice minhasenha123 123456`

_Se o login for bem-sucedido, você verá a lista de usuários online e poderá enviar mensagens._

### Enviar Mensagens

Basta digitar sua mensagem e pressionar `Enter`.
**Exemplo:** `Olá a todos, esta é uma mensagem segura!`

### Sair

Pressione `Ctrl+C` para fechar o cliente.

## 4. Funcionalidades de Segurança Explicadas

### Criptografia Serpent

Diferente do AES padrão, utilizamos o **Serpent**, um algoritmo conhecido por sua altíssima margem de segurança. Seus dados são transformados em código ilegível antes mesmo de saírem do seu computador.

### Troca de Chaves (Key Exchange)

Quando você entra no chat, o servidor envia uma "Chave de Sala" exclusiva para você. Esta chave é enviada criptografada com sua Chave Pública RSA (gerada localmente no seu cliente). Isso garante que apenas você (com sua Chave Privada) possa desbloquear a chave da sala.

- **Rotação de Chaves**: Se alguém sair da sala, uma nova chave é gerada e distribuída para quem ficou. Isso impede que o usuário que saiu continue lendo novas mensagens (Forward Secrecy).

### Autenticação de Dois Fatores (2FA)

Mesmo que alguém descubra sua senha, não conseguirá entrar na sua conta sem o código temporário gerado pelo seu segredo TOTP. Isso adiciona uma camada crítica de proteção contra roubo de credenciais.

## 5. Solução de Problemas

- **Erro "Não autenticado"**: Certifique-se de ter feito login com sucesso.
- **Erro "Código 2FA inválido"**: O código muda a cada 30 segundos. Verifique se o relógio do seu computador está sincronizado.
- **Mensagens não aparecem**: Verifique se você está conectado ao servidor (status no topo da tela).
