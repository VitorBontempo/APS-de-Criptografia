from Crypto.Cipher import AES #Implementação de algoritmo para a criptografia
from Crypto.Util.Padding import pad, unpad #Para auxílio do algoritmo implementado, evitar erros
import os #Auxílio na complexificação da criptografia
import binascii  # Para converter para hexadecimal
import rich

#Função de criptografagem
def criptografar(mensagem, key):
    iv = os.urandom(16) #Gerar IV
    cripto = AES.new(key, AES.MODE_GCM, nonce=iv) #Modo da criptografia AES com o IV gerado
    mensagemPad = pad(mensagem.encode(), AES.block_size)  # Adiciona padding para evitar erros
    criptoMensagem, tag = cripto.encrypt_and_digest(mensagemPad) #Além de criptografar o código, gera uma 'tag' para verificar se foi alterado o código.
    return iv+criptoMensagem+tag

#Função de decriptografagem
def descriptografar(mensagem, key):
    iv = mensagem[:16] #Identificar o IV
    cripto = AES.new(key, AES.MODE_GCM, nonce=iv) #Modo da criptografia AES
    criptoMensagem = mensagem[16:-16] #Mensagem em si à ser decodificada
    tag = mensagem[-16:] #Identificar a tag
    try:
        descriptMensagem = cripto.decrypt_and_verify(criptoMensagem, tag)
        return unpad(descriptMensagem, AES.block_size).decode() #Remove o padding e retorna a mensagem original
    except ValueError:
        
        return "Erro de autentificação." #Aviso de falha na autentificação caso a tag seja alterada

mensagem1 = "=================[red]Sistema de Segurança Cibernética[/red]=================\n[blue]Selecione um modo ou digite 0 para sair.[/blue]\n[bright_black]Digite[/bright_black] CRIPTOGRAFAR[bright_black] para o modo de criptografar mensagens ou [/bright_black]DESCRIPTOGRAFAR[bright_black] para o modo descriptografar mensagens\nApós selecionar você só poderá trocar o modo caso reinicie o programa.[/bright_black]"

rich.print(mensagem1)
modeSelect = input("Insira: ")

while modeSelect != '0' and modeSelect != 'CRIPTOGRAFAR' and modeSelect != 'DESCRIPTOGRAFAR': #Caso o usuário erre a digitação
    print('Tente novamente.')
    modeSelect = input("Insira: ")
if modeSelect == 'CRIPTOGRAFAR': #Selecionado o modo de cifragem
    senha = os.urandom(16)
    mensagemOriginal = input("Mensagem para ser enviada: ") #Mensagem para ser criptografada
    mensagemCifrada = criptografar(mensagemOriginal, senha) #Criptografando a mensagem
    print(f"Mensagem criptografada: {binascii.hexlify(mensagemCifrada).decode('utf-8')}\nSenha: {binascii.hexlify(senha).decode('utf-8')}")

elif modeSelect == 'DESCRIPTOGRAFAR': #Selecionado o modo de decifragem
    mensagemCifrada = binascii.unhexlify(input("Mensagem cifrada: "))
    senha = binascii.unhexlify(input("Senha: "))
    mensagemDecifrada = descriptografar(mensagemCifrada, senha) #Removendo a criptografia
    print(f"Mensagem descriptografada: {mensagemDecifrada}")
elif modeSelect == '0':
    rich.print('Não se esqueça de sempre lavar as mãos!\n[red]Desligando[/red]')
