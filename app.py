from flask import Flask, request, render_template_string, send_file
import os
from werkzeug.utils import secure_filename
from crypto import Encrypt, Decrypt

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

CIPHERS = ['aes', 'rsa2048', 'rsa4096', 'des']

HTML_FORM = """
<!doctype html>
<title>File Encryption / Decryption</title>
<h2>Загрузите файл для шифрования или расшифровки</h2>
<form method=post enctype=multipart/form-data>
  <label>Файл:</label><br>
  <input type=file name=file required><br><br>
  
  <label>Файл ключа (только для расшифровки):</label><br>
  <input type=file name=keyfile><br><br>
  
  <label for=cipher>Выберите шифр:</label>
  <select name=cipher required>
    {% for c in ciphers %}
      <option value="{{c}}">{{c.upper()}}</option>
    {% endfor %}
  </select><br><br>
  
  <button type="submit" name="action" value="encrypt">Зашифровать</button>
  <button type="submit" name="action" value="decrypt">Расшифровать</button>
</form>

{% if result %}
  <h3>Скачайте файлы:</h3>
  {% if result.enc %}
    <a href="{{ url_for('download_file', filename=result.enc) }}">Скачать шифрофайл</a><br>
  {% endif %}
  {% if result.key %}
    <a href="{{ url_for('download_file', filename=result.key) }}">Скачать {{ result.key }}</a><br>
  {% endif %}
  {% if result.dec %}
    <a href="{{ url_for('download_file', filename=result.dec) }}">Скачать расшифрованный файл</a><br>
  {% endif %}
{% endif %}
"""

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    result = None
    if request.method == 'POST':
        action = request.form.get('action')
        cipher = request.form['cipher'].lower()

        # Сохраняем основной файл
        uploaded_file = request.files['file']
        filename = secure_filename(uploaded_file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        uploaded_file.save(file_path)

        if action == 'encrypt':
            enc_file, key_file = Encrypt(file_path, cipher)
            result = {
                'enc': os.path.basename(enc_file),
                'key': os.path.basename(key_file),
                'dec': None
            }

        elif action == 'decrypt':
            keyfile = request.files.get('keyfile')
            if not keyfile or keyfile.filename == '':
                return "Файл ключа обязателен для расшифровки.", 400

            key_filename = secure_filename(keyfile.filename)
            key_path = os.path.join(app.config['UPLOAD_FOLDER'], key_filename)
            keyfile.save(key_path)

            dec_file = Decrypt(file_path, cipher, key_path)
            result = {
                'enc': None,
                'key': None,
                'dec': os.path.basename(dec_file)
            }
        else:
            return "Неизвестное действие", 400

    return render_template_string(HTML_FORM, ciphers=CIPHERS, result=result)

@app.route('/uploads/<filename>')
def download_file(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename), as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

