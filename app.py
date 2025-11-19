# app.py
from flask import Flask, render_template_string, request
from crypto_app import encrypt, decrypt

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Text Encryption App</title>
</head>
<body>
    <h2>Encrypt / Decrypt Text</h2>

    <form method="POST">
        <label>Password:</label><br>
        <input type="password" name="password" required><br><br>

        <label>Plain Text (Encrypt):</label><br>
        <textarea name="plaintext" rows="3" cols="60"></textarea><br>
        <button name="action" value="encrypt">Encrypt</button>
        <br><br>

        <label>Encrypted Token (Decrypt):</label><br>
        <textarea name="token" rows="3" cols="60"></textarea><br>
        <button name="action" value="decrypt">Decrypt</button>
    </form>

    {% if result %}
    <hr>
    <h3>Result:</h3>
    <pre>{{ result }}</pre>
    {% endif %}
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        action = request.form.get("action")
        password = request.form.get("password")

        if action == "encrypt":
            plaintext = request.form.get("plaintext", "")
            result = encrypt(plaintext, password)

        elif action == "decrypt":
            token = request.form.get("token", "")
            try:
                result = decrypt(token.strip(), password)
            except Exception as e:
                result = "Decryption failed: " + str(e)

    return render_template_string(HTML, result=result)

if __name__ == "__main__":
    app.run(debug=True)
