import string
import secrets
from flask import Flask, request, jsonify
from flask_cors import CORS

# Inicializa a aplicação Flask
app = Flask(__name__)
# Habilita o CORS para permitir requisições do frontend
CORS(app)

@app.route('/generate-password', methods=['GET'])
def generate_password_route():
    """
    Endpoint da API para gerar senhas seguras.
    Recebe parâmetros via query string para customizar a senha.
    """
    try:
        # Pega o comprimento da senha da query string, com valor padrão de 12
        length = int(request.args.get('length', 12))
        if not 4 <= length <= 128:
            return jsonify({"error": "O comprimento deve ser entre 4 e 128 caracteres."}), 400

        # Verifica quais conjuntos de caracteres incluir
        include_uppercase = request.args.get('uppercase', 'true').lower() == 'true'
        include_numbers = request.args.get('numbers', 'true').lower() == 'true'
        include_symbols = request.args.get('symbols', 'true').lower() == 'true'

        # Começa com letras minúsculas como base
        character_pool = string.ascii_lowercase
        password_chars = [secrets.choice(string.ascii_lowercase)]

        # Adiciona outros conjuntos de caracteres conforme solicitado
        if include_uppercase:
            character_pool += string.ascii_uppercase
            password_chars.append(secrets.choice(string.ascii_uppercase))
        if include_numbers:
            character_pool += string.digits
            password_chars.append(secrets.choice(string.digits))
        if include_symbols:
            # Conjunto de símbolos comuns para senhas
            symbols = '!@#$%^&*()-_=+'
            character_pool += symbols
            password_chars.append(secrets.choice(symbols))
        
        # Garante que a senha tenha pelo menos um caractere de cada tipo selecionado,
        # e preenche o restante com caracteres aleatórios do pool completo.
        remaining_length = length - len(password_chars)
        if remaining_length > 0:
            for _ in range(remaining_length):
                password_chars.append(secrets.choice(character_pool))

        # Embaralha a lista de caracteres para garantir a aleatoriedade da posição
        secrets.SystemRandom().shuffle(password_chars)

        # Junta os caracteres para formar a senha final
        password = "".join(password_chars)

        # Retorna a senha gerada em formato JSON
        return jsonify({"password": password})

    except ValueError:
        return jsonify({"error": "Parâmetro 'length' inválido. Deve ser um número."}), 400
    except Exception as e:
        # Captura de erro genérica para problemas inesperados
        return jsonify({"error": f"Ocorreu um erro interno: {str(e)}"}), 500

# Executa a aplicação se este script for o principal
if __name__ == '__main__':
    # Roda em modo de depuração para desenvolvimento
    app.run(host='0.0.0.0', port=5000, debug=True)
