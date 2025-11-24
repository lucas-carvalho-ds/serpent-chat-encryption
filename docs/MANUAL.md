# Manual do Usuário - SerpTalk

Este manual descreve como utilizar o sistema de chat seguro SerpTalk.

## 1. Visão Geral

O SerpTalk é uma ferramenta de comunicação que prioriza a segurança. Ele garante que suas mensagens sejam lidas apenas pelos destinatários autorizados, utilizando criptografia ponta-a-ponta com o algoritmo Serpent e autenticação de dois fatores (2FA).

**Interface Disponível:**

- **GUI (Interface Gráfica)**: Interface moderna e intuitiva com Tkinter.

## 2. Primeiros Passos

### Iniciando o Servidor

O servidor deve estar rodando para que os clientes possam se conectar.

```bash
python -m src.server.server
```

_O servidor escuta na porta 8888 por padrão e será indicado como "Servidor rodando em 0.0.0.0:8888"._

### Iniciando o Cliente

Para entrar no chat usando a interface gráfica:

```bash
python -m src.client.main
```

## 3. Usando a Interface Gráfica (GUI)

### 3.1. Registro de Novo Usuário

1. Na tela inicial, clique no botão **"Registrar"**
2. Preencha os campos:
   - **Usuário**: Escolha um nome de usuário único
   - **Senha**: Crie uma senha segura
3. Clique em **"Registrar"**
4. **IMPORTANTE**: Uma janela com QR Code aparecerá automaticamente
   - Escaneie este QR Code com um aplicativo autenticador (Google Authenticator, Authy, Microsoft Authenticator, etc.)
   - Ou anote o código secreto exibido abaixo do QR Code para configuração manual
   - **Guarde este QR Code/segredo em local seguro!** Você precisará do aplicativo autenticador para fazer login

### 3.2. Fazer Login

1. Na tela inicial, preencha os campos:
   - **Usuário**: Seu nome de usuário
   - **Senha**: Sua senha
   - **Código 2FA**: Código de 6 dígitos gerado pelo seu aplicativo autenticador
2. Clique em **"Login"**

_Se o login for bem-sucedido, você verá a janela principal do chat._

### 3.3. Janela Principal do Chat

A janela principal é dividida em três áreas:

#### Barra Lateral Esquerda

- **Lista de Chats**: Mostra todas as suas conversas (individuais e em grupo)
  - **Clique com botão direito** em um chat para ver o menu de contexto com opções:
    - **"Ver Participantes"**: Visualizar membros do chat e seus status
    - **"Sair do Chat"**: Sair da conversa
- **Usuários Online**: Lista de usuários conectados atualmente
  - 🟢 Indica usuário **online**
  - ⚫ Indica usuário **offline**
- **Botões de Ação**:
  - **"Novo Chat Individual"**: Criar chat individual com um usuário
  - **"Novo Chat em Grupo"**: Criar chat em grupo
  - **"Entrar em Chat em Grupo"**: Entrar em um chat existente pelo ID
  - **"🔑 Ver Histórico de Chaves"**: Visualizar todos os eventos criptográficos
- **Botão Sair (Logout)**: No topo da barra lateral, para fazer logout com segurança

#### Área Central

- **Área de Mensagens**: Visualização das mensagens do chat selecionado
- **Campo de Entrada**: Digite sua mensagem aqui
- **Botão "Enviar"**: Clique para enviar a mensagem (ou pressione Enter)

### 3.4. Criando um Novo Chat Individual

1. Clique no botão **"Novo Chat Individual"**
2. Digite o nome de usuário do destinatário
3. Clique em **"Criar"**
4. O novo chat aparecerá na lista de chats
5. Clique nela para começar a conversar

### 3.5. Criando um Novo Chat em Grupo

1. Clique no botão **"Novo Chat em Grupo"**
2. Digite o **nome do grupo**
3. Selecione os membros usando as **caixas de seleção (checkboxes)**:
   - Marque os usuários que deseja adicionar ao grupo
   - Você pode selecionar múltiplos usuários
   - **Você será automaticamente incluído** como membro (não precisa se selecionar)
4. Clique em **"Criar"**
5. O novo grupo aparecerá na lista de chats

### 3.6. Visualizando Membros de um Chat

1. **Clique com o botão direito** no chat desejado na lista de chats
2. Selecione **"Ver Participantes"** no menu
3. Uma janela será aberta mostrando:
   - Lista de todos os membros do chat
   - Status de cada membro:
     - 🟢 **Online**: Usuário está conectado no momento
     - ⚫ **Offline**: Usuário não está conectado

### 3.7. Saindo de um Chat

1. **Clique com o botão direito** no chat que deseja sair
2. Selecione **"Sair do Chat"** no menu de contexto
3. O chat será removido da sua lista de chats
4. Você não receberá mais mensagens dessa conversa

### 3.8. Enviando Mensagens

1. Selecione um chat/conversa na lista de chats
2. Digite sua mensagem no campo de entrada
3. Pressione **Enter** ou clique em **"Enviar"**
4. A mensagem será criptografada e enviada para todos os membros do chat

### 3.9. Visualizando Histórico

Ao selecionar um chat, o histórico de mensagens anteriores é carregado automaticamente e descriptografado localmente no seu cliente.

### 3.10. Visualizando Histórico de Chaves

1. Clique no botão **"🔑 Ver Histórico de Chaves"** na barra lateral
2. Uma janela será aberta mostrando:
   - Lista cronológica de eventos criptográficos
   - Tipo de evento (geração RSA, chave de sala recebida, rotação)
   - Timestamp exato
   - Detalhes contextuais (nome da sala, motivo, etc.)
3. Use o botão **"Limpar Histórico"** para apagar logs antigos (ação irreversível)

## 4. Funcionalidades de Segurança Explicadas

### Criptografia Serpent

Diferente do AES padrão, utilizamos o **Serpent**, um algoritmo conhecido por sua altíssima margem de segurança (foi finalista do concurso AES). Seus dados são transformados em código ilegível usando criptografia de 256 bits antes mesmo de saírem do seu computador.

### Isolamento de Chaves por Sala

Cada sala de chat (individual ou em grupo) possui sua própria **chave Serpent exclusiva**:

- Mensagens de chats diferentes não podem ser descriptografadas com a mesma chave
- Se uma chave for comprometida, apenas aquela sala é afetada
- O servidor nunca tem acesso às chaves descriptografadas

### Troca de Chaves via RSA

Quando você entra em uma sala, o servidor envia a "Chave da Sala" para você:

1. A chave é criptografada com sua **Chave Pública RSA** (gerada localmente no seu cliente)
2. Apenas você (com sua **Chave Privada RSA**) pode descriptografar a chave da sala
3. Suas chaves RSA são geradas a cada vez que você inicia o cliente
4. No login, sua chave pública é atualizada no servidor automaticamente

### Autenticação de Dois Fatores (2FA)

Mesmo que alguém descubra sua senha, não conseguirá entrar na sua conta sem o código temporário gerado pelo seu aplicativo autenticador:

- Códigos mudam a cada 30 segundos (TOTP - Time-based One-Time Password)
- Baseado no padrão RFC 6238
- Compatível com Google Authenticator, Authy, Microsoft Authenticator, etc.
- QR Code gerado automaticamente no registro para facilitar a configuração

### Integridade das Mensagens

Cada mensagem é assinada com **HMAC-SHA256**:

- Garante que a mensagem não foi alterada durante a transmissão
- Previne ataques de modificação mesmo se a criptografia for quebrada
- Verifica a autenticidade do remetente

### Rotação de Chaves e Forward Secrecy

O sistema implementa **rotação automática de chaves** para garantir forward secrecy:

**Quando ocorre:**

- Automaticamente quando um membro sai de um grupo

**Como funciona:**

1. Nova chave Serpent é gerada para a sala
2. **Todas as mensagens antigas são re-criptografadas** com a nova chave
3. Nova chave é distribuída para membros restantes
4. Membro que saiu **não pode mais descriptografar mensagens futuras**

**Benefícios:**

- Protege conversas futuras mesmo se chaves antigas forem comprometidas
- Mantém histórico completo acessível para membros atuais
- Garante que usuários removidos perdem acesso imediatamente

### Visualização de Histórico de Chaves

Você pode visualizar todos os eventos criptográficos no menu **"🔑 Ver Histórico de Chaves"**:

**Eventos rastreados:**

- Geração de chaves RSA
- Recebimento de chaves de sala
- Rotação de chaves (com motivo)

**Informações exibidas:**

- Timestamp exato do evento
- Tipo de evento
- Contexto (nome da sala, usuário, etc.)
- Hash da chave (para verificação)

### Persistência de Mensagens do Sistema

Todas as atividades do grupo são registradas e persistidas no banco de dados:

**Mensagens rastreadas:**

- "Usuário criou o grupo"
- "Usuário entrou no grupo"
- "Usuário saiu do chat"

**Características:**

- Criptografadas com a chave da sala (como mensagens normais)
- Exibidas com label **[Sistema]** no chat
- Visíveis no histórico após logout/login
- Re-criptografadas durante rotação de chaves

## 5. Solução de Problemas

### Problemas Comuns

- **"Erro ao descriptografar chave da sala"**:

  - Isso pode ocorrer se você está usando chaves RSA antigas. Feche o cliente, faça logout e login novamente.
  - O sistema agora atualiza automaticamente suas chaves RSA no servidor durante o login.

- **Janela do QR Code não aparece**:

  - Verifique se o registro foi bem-sucedido (mensagem de confirmação)
  - O código secreto TOTP também aparece na área de mensagens da interface

- **Chat não carrega mensagens**:

  - Verifique se o servidor está rodando
  - Certifique-se de que você está logado (título da janela mostra "Chat - [seu usuário]")

- **Erro "Código 2FA inválido"**:
  - O código muda a cada 30 segundos. Certifique-se de usar o código mais recente do seu aplicativo autenticador
  - Verifique se o relógio do seu computador está sincronizado

### Problemas de Conexão

- **"Não foi possível conectar ao servidor"**:

  - Verifique se o servidor está rodando (`python -m src.server.server`)
  - Confirme que a porta 8888 não está bloqueada por firewall
  - Por padrão, o servidor escuta em `127.0.0.1:8888` (localhost)

- **"Mensagens não aparecem"**:
  - Verifique a conexão de rede
  - Reinicie o cliente e faça login novamente

## 6. Dicas de Segurança

1. **Nunca compartilhe seu segredo TOTP**: O código secreto ou QR Code é equivalente à sua senha 2FA
2. **Use senhas fortes**: Combine letras, números e símbolos
3. **Mantenha backups do TOTP**: Se perder acesso ao aplicativo autenticador, você não conseguirá fazer login
4. **Feche o cliente ao sair**: Isso remove suas chaves RSA da memória
5. **Não confie cegamente**: Este é um projeto educacional - para produção, considere auditorias de segurança adicionais

## 7. Recursos Avançados

### Múltiplas Salas

Você pode participar de várias salas simultaneamente:

- Cada sala mantém sua própria chave de criptografia
- O histórico é carregado independentemente para cada sala
- Salas individuais aparecem como "usuario1-usuario2"
- Grupos aparecem com o nome definido na criação

### Persistência de Dados

- Todas as mensagens são salvas criptografadas no banco de dados SQLite (`chat.db`)
- O histórico completo é carregado ao entrar em uma sala
- Mensagens enviadas enquanto você estava offline estarão disponíveis quando você logar

## 8. Arquitetura do Sistema

### Cliente

- Gera par de chaves RSA (2048-bit) localmente
- Envia chave pública ao servidor durante login/registro
- Descriptografa chaves de sala recebidas do servidor
- Criptografa/descriptografa mensagens localmente usando Serpent
- Assina mensagens com HMAC-SHA256

### Servidor

- Gerencia conexões assíncronas (asyncio)
- Armazena chaves públicas dos usuários
- Distribui chaves de sala criptografadas com RSA
- Armazena mensagens criptografadas no banco de dados
- **Nunca tem acesso ao conteúdo das mensagens descriptografadas**

### Banco de Dados

- Tabela `users`: Credenciais, hashes bcrypt, chaves públicas RSA, segredos TOTP
- Tabela `rooms`: Salas de chat com chaves Serpent
- Tabela `room_members`: Relacionamento usuário-sala
- Tabela `messages`: Mensagens criptografadas, IVs, assinaturas HMAC
