"""
Tek sayfalık Türkçe CSR Decoder (Flask + AJAX)
- Sayfa yenilenmeden CSR çözümlenir.
- Türkçe açıklamalar içerir.
- Hem PEM metni hem dosya yüklemeyi destekler.

Kurulum:
    pip install flask cryptography

Çalıştırma:
    python app.py

Sonra tarayıcıdan http://127.0.0.1:8000 adresine git.

Güvenlik uyarısı:
Bu uygulama sadece geliştirme içindir. Gerçek sistemlerde HTTPS, kimlik doğrulama ve rate-limit ekleyin.
"""
from flask import Flask, request, jsonify, render_template_string
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec

app = Flask(__name__)

HTML_PAGE = """
<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <title>CSR Çözücü</title>
  <style>
    body { font-family: Arial; margin: 40px; }
    textarea { width: 100%; height: 200px; }
    .result { margin-top: 20px; padding: 10px; border: 1px solid #ccc; border-radius: 8px; background: #f9f9f9; }
    h2 { color: #0077cc; }
    button { background: #0077cc; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }
    button:hover { background: #005fa3; }
  </style>
</head>
<body>
  <h1>CSR Çözücü</h1>
  <p>Buradan <b>Certificate Signing Request (CSR)</b> dosyanızı çözümleyebilirsiniz.</p>
  <form id="csrForm">
    <label>PEM formatında CSR metni:</label><br>
    <textarea name="csr_text" placeholder="-----BEGIN CERTIFICATE REQUEST-----\n..."></textarea><br><br>
    <label>veya .csr dosyası yükleyin:</label><br>
    <input type="file" name="csr_file" accept=".csr,.pem"><br><br>
    <button type="submit">Çözümle</button>
  </form>
  <div id="result" class="result" style="display:none"></div>

  <script>
    const form = document.getElementById('csrForm');
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const formData = new FormData(form);
      const res = await fetch('/api/decode', { method: 'POST', body: formData });
      const data = await res.json();
      const resultDiv = document.getElementById('result');
      if (data.error) {
        resultDiv.innerHTML = `<b>Hata:</b> ${data.error}`;
      } else {
        let html = `<h2>Çözümleme Sonucu</h2>`;
        html += `<h3>Konu Bilgileri (Subject)</h3><ul>`;
        data.subject.forEach(a => {
          html += `<li><b>${a.name}</b>: ${a.value}</li>`;
        });
        html += `</ul>`;
        html += `<h3>Halka Açık Anahtar</h3><ul>`;
        for (const [k, v] of Object.entries(data.public_key)) {
          html += `<li><b>${k}</b>: ${v}</li>`;
        }
        html += `</ul>`;
        if (data.extensions && data.extensions.length) {
          html += `<h3>Uzantılar (Extensions)</h3><ul>`;
          data.extensions.forEach(ext => {
            html += `<li><b>${ext.name || ext.oid}</b>: ${JSON.stringify(ext.value)}</li>`;
          });
          html += `</ul>`;
        }
        html += `<p><b>İmza Algoritması:</b> ${data.signature_algorithm_oid}</p>`;
        resultDiv.innerHTML = html;
      }
      resultDiv.style.display = 'block';
    });
  </script>
</body>
</html>
"""

def load_csr(data: bytes):
    try:
        return x509.load_pem_x509_csr(data)
    except Exception:
        return x509.load_der_x509_csr(data)

def name_to_dict(name: x509.Name):
    return [{'oid': attr.oid.dotted_string, 'name': attr.oid._name, 'value': attr.value} for attr in name]

def pubkey_info(key):
    if isinstance(key, rsa.RSAPublicKey):
        return {'tip': 'RSA', 'bit_uzunluğu': key.key_size}
    elif isinstance(key, ec.EllipticCurvePublicKey):
        return {'tip': 'EC', 'eğri': key.curve.name}
    return {'tip': str(type(key))}

def ext_to_dict(ext):
    try:
        if isinstance(ext.value, x509.SubjectAlternativeName):
            sans = [str(gn) for gn in ext.value]
            return {'oid': ext.oid.dotted_string, 'name': 'subjectAltName', 'value': sans}
        return {'oid': ext.oid.dotted_string, 'name': ext.oid._name, 'value': str(ext.value)}
    except Exception as e:
        return {'oid': ext.oid.dotted_string, 'error': str(e)}

@app.route('/')
def index():
    return render_template_string(HTML_PAGE)

@app.route('/api/decode', methods=['POST'])
def decode_api():
    csr_bytes = None
    if 'csr_file' in request.files and request.files['csr_file'].filename:
        csr_bytes = request.files['csr_file'].read()
    elif 'csr_text' in request.form and request.form['csr_text'].strip():
        csr_bytes = request.form['csr_text'].encode('utf-8')
    else:
        return jsonify({'error': 'CSR verisi bulunamadı. Lütfen metin yapıştırın veya dosya yükleyin.'}), 400

    try:
        csr = load_csr(csr_bytes)
    except Exception as e:
        return jsonify({'error': f'CSR okunamadı: {e}'}), 400

    result = {
        'subject': name_to_dict(csr.subject),
        'public_key': pubkey_info(csr.public_key()),
        'signature_algorithm_oid': csr.signature_algorithm_oid.dotted_string if hasattr(csr, 'signature_algorithm_oid') else str(csr.signature_algorithm),
        'extensions': []
    }

    try:
        for ext in csr.extensions:
            result['extensions'].append(ext_to_dict(ext))
    except Exception:
        pass

    return jsonify(result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
