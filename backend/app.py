from flask import Flask, request, render_template
import os
from scanner import scan_java_code

app = Flask(__name__, template_folder='../frontend/templates')
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/', methods=['GET', 'POST'])
def index():
    findings = []
    if request.method == 'POST':
        file = request.files.get('file')
        if file and file.filename.endswith('.java'):
            filepath = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(filepath)
            with open(filepath, 'r', encoding='utf-8') as f:
                code = f.read()
            findings = scan_java_code(code)  # This returns list of dicts now
    return render_template('index.html', findings=findings)

if __name__ == '__main__':
    app.run(debug=True)
