import string
import secrets
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route('/generate-password', methods=['GET'])
def generate_password_route():
    """
    Endpoint da API para gerar senhas seguras.
    Recebe parâmetros via query string para customizar a senha.
    """
    try:
        length = int(request.args.get('length', 12))
        if not 4 <= length <= 128:
            return jsonify({"error": "O comprimento deve ser entre 4 e 128 caracteres."}), 400

        include_uppercase = request.args.get('uppercase', 'true').lower() == 'true'
        include_numbers = request.args.get('numbers', 'true').lower() == 'true'
        include_symbols = request.args.get('symbols', 'true').lower() == 'true'

        character_pool = string.ascii_lowercase
        password_chars = [secrets.choice(string.ascii_lowercase)]

        if include_uppercase:
            character_pool += string.ascii_uppercase
            password_chars.append(secrets.choice(string.ascii_uppercase))
        if include_numbers:
            character_pool += string.digits
            password_chars.append(secrets.choice(string.digits))
        if include_symbols:
            symbols = '!@#$%^&*()-_=+'
            character_pool += symbols
            password_chars.append(secrets.choice(symbols))
        
        remaining_length = length - len(password_chars)
        if remaining_length > 0:
            for _ in range(remaining_length):
                password_chars.append(secrets.choice(character_pool))

        secrets.SystemRandom().shuffle(password_chars)
        password = "".join(password_chars)

        return jsonify({"password": password})

    except ValueError:
        return jsonify({"error": "Parâmetro 'length' inválido. Deve ser um número."}), 400
    except Exception as e:
        return jsonify({"error": f"Ocorreu um erro interno: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
