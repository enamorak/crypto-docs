from flask import Flask, request, render_template_string, send_file, redirect, url_for
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
<title>File Encryption</title>
<h2>Загрузите файл для шифрования</h2>
<form method=post enctype=multipart/form-data>
  <input type=file name=file required><br><br>
  <label for=cipher>Выберите шифр:</label>
  <select name=cipher required>
    {% for c in ciphers %}
      <option value="{{c}}">{{c.upper()}}</option>
    {% endfor %}
  </select><br><br>
  <input type=submit value="Зашифровать">
</form>
{% if result %}
  <h3>Скачайте файлы:</h3>
  <a href="{{ url_for('download_file', filename=result['enc']) }}">Скачать шифрофайл</a><br>
  <a href="{{ url_for('download_file', filename=result['key']) }}">Скачать key.txt</a>
{% endif %}
"""

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    result = None
    if request.method == 'POST':
        uploaded_file = request.files['file']
        cipher = request.form['cipher'].lower()
        filename = secure_filename(uploaded_file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        uploaded_file.save(file_path)

        enc_file, key_file = Encrypt(file_path, cipher)
        result = {
            'enc': os.path.basename(enc_file),
            'key': os.path.basename(key_file)
        }
    return render_template_string(HTML_FORM, ciphers=CIPHERS, result=result)

@app.route('/uploads/<filename>')
def download_file(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename), as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)