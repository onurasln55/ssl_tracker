# app.py
# Tek dosyalık Flask uygulaması: CSR oluşturma, CSR decode, Sertifika discovery
# Kullanım:
#   pip install flask cryptography
#   python app.py
#
# Geliştirme amaçlıdır. Prod ortamda HTTPS, kimlik doğrulama ve rate-limit ekleyin.

from flask import Flask, request, jsonify, render_template_string
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
import ssl
import socket
import datetime
import base64
import io
import zipfile
import traceback

app = Flask(__name__)

########################
# HTML (tek sayfa + nav)
########################
HTML = """
<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <title>Mini SSL Yönetim - CSR Oluştur / Çöz / Keşfet</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    body { font-family: Inter, Arial, sans-serif; margin: 20px; max-width: 1000px; }
    header { display:flex; gap:12px; align-items:center; margin-bottom:20px; }
    nav a { margin-right:12px; text-decoration:none; color:#004a99; font-weight:600; }
    section { border:1px solid #e1e1e1; padding:16px; border-radius:8px; margin-bottom:18px; background:#fafafa; }
    label { font-weight:600; display:block; margin-top:8px; }
    input[type=text], textarea, select { width:100%; padding:8px; margin-top:6px; box-sizing:border-box; }
    textarea { height:120px; font-family: monospace; }
    button { margin-top:12px; padding:10px 14px; background:#0077cc; color:white; border:none; border-radius:6px; cursor:pointer; }
    .row { display:flex; gap:12px; }
    .col { flex:1; }
    .result { margin-top:14px; padding:12px; background:white; border-radius:6px; border:1px solid #ddd; }
    pre { background:#111; color:#dcdcdc; padding:12px; border-radius:6px; overflow:auto; }
    .small { font-size:0.9rem; color:#555; }
    .danger { color:#b00020; font-weight:700; }
  </style>
</head>
<body>
  <header>
    <h1>Mini SSL Yönetim</h1>
    <nav>
      <a href="#create">CSR Oluştur</a>
      <a href="#decode">CSR Çözücü</a>
      <a href="#discover">Sertifika Keşfi</a>
    </nav>
  </header>

  <!-- CSR Oluştur -->
  <section id="create">
    <h2>CSR Oluşturucu</h2>
    <div class="small">Formu doldurun, RSA anahtar üretilecek ve CSR oluşturulacaktır. Oluşturulan CSR ve özel anahtarı indirilebilir / kopyalanabilir.</div>

    <div style="margin-top:12px;">
      <label>Ülke (C) — 2 harf</label>
      <input type="text" id="c" placeholder="TR" value="TR">

      <div class="row">
        <div class="col">
          <label>Şehir / İl (L)</label>
          <input type="text" id="l" placeholder="Istanbul" value="Istanbul">
        </div>
        <div class="col">
          <label>Kurum (O)</label>
          <input type="text" id="o" placeholder="Sekerbank T.A.S." value="Sekerbank T.A.S.">
        </div>
      </div>

      <label>Organizasyon Birimi (OU)</label>
      <input type="text" id="ou" placeholder="BT">

      <label>Ortak Ad (CN) — örn: example.com</label>
      <input type="text" id="cn" placeholder="example.com">

      <label>E-posta (emailAddress)</label>
      <input type="text" id="email" placeholder="admin@example.com">

      <label>Alternatif İsimler (SAN) — virgülle ayrılmış (opsiyonel)</label>
      <input type="text" id="san" placeholder="www.example.com,api.example.com">

      <label>Anahtar Tipi</label>
      <select id="key_type">
        <option value="rsa">RSA</option>
        <option value="ec">EC (secp256r1)</option>
      </select>

      <label>Anahtar Uzunluğu (RSA için)</label>
      <select id="key_size">
        <option selected>2048</option>
        <option >4096</option>
      </select>

      <button id="createBtn">CSR Oluştur</button>

      <div id="createResult" class="result" style="display:none;"></div>
    </div>
  </section>

  <!-- CSR Decode -->
  <section id="decode">
    <h2>CSR Çözücü</h2>
    <div class="small">PEM formatında CSR yapıştırın veya dosya yükleyin; içerik anında çözümlenir.</div>

    <label>PEM CSR metni</label>
    <textarea id="csr_text" placeholder="-----BEGIN CERTIFICATE REQUEST-----..."></textarea>

    <label>veya dosya yükle</label>
    <input type="file" id="csr_file" accept=".csr,.pem">

    <button id="decodeBtn">Çözümle</button>

    <div id="decodeResult" class="result" style="display:none;"></div>
  </section>

  <!-- Cert Discovery -->
  <section id="discover">
    <h2>Sertifika Keşfi (Discovery)</h2>
    <div class="small">Bir domain girin, uzaktaki sunucunun TLS sertifikasını çekip analiz eder.</div>

    <label>Domain (örn: example.com veya example.com:8443)</label>
    <input type="text" id="discover_host" placeholder="example.com">

    <button id="discoverBtn">Keşfet</button>
    <div id="discoverResult" class="result" style="display:none;"></div>
  </section>

<script>
  // CSR Oluştur
  document.getElementById('createBtn').addEventListener('click', async () => {
    const payload = {
      c: document.getElementById('c').value,
      l: document.getElementById('l').value,
      o: document.getElementById('o').value,
      ou: document.getElementById('ou').value,
      cn: document.getElementById('cn').value,
      email: document.getElementById('email').value,
      san: document.getElementById('san').value,
      key_type: document.getElementById('key_type').value,
      key_size: document.getElementById('key_size').value
    };
    const res = await fetch('/api/create-csr', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(payload)
    });
    const j = await res.json();
    const d = document.getElementById('createResult');
    if (j.error) {
      d.style.display='block';
      d.innerHTML = '<div class="danger">Hata: '+ j.error +'</div>';
      return;
    }
    // göster
    let html = '<h3>Oluşturulan CSR</h3>';
    html += '<div class="small">CSR içeriği (PEM)</div>';
    html += `<pre id="csr_pem">${j.csr_pem}</pre>`;
    html += '<div class="small" style="margin-top:8px;">Özel Anahtar (PEM) — saklayın!</div>';
    html += `<pre id="key_pem">${j.key_pem}</pre>`;
    html += '<div style="margin-top:10px;">';
    html += '<button id="downloadCsr">CSR indir (.csr)</button> ';
    html += '<button id="downloadKey">Private Key indir (.key)</button> ';
    html += '<button id="downloadZip">CSR+Key .zip indir</button>';
    html += '</div>';
    d.style.display='block';
    d.innerHTML = html;

    document.getElementById('downloadCsr').onclick = () => {
      downloadText('request.csr', j.csr_pem);
    };
    document.getElementById('downloadKey').onclick = () => {
      downloadText('private.key', j.key_pem);
    };
    document.getElementById('downloadZip').onclick = () => {
      // oluşturuyoruz client-side zip
      const zip = new JSZip();
      zip.file('request.csr', j.csr_pem);
      zip.file('private.key', j.key_pem);
      zip.generateAsync({type:'blob'}).then(function(content) {
        saveAs(content, 'csr_and_key.zip');
      });
    };
  });

  // CSR Decode
  document.getElementById('decodeBtn').addEventListener('click', async () => {
    const text = document.getElementById('csr_text').value;
    const fileInput = document.getElementById('csr_file');
    const form = new FormData();
    if (fileInput.files.length) {
      form.append('csr_file', fileInput.files[0]);
    } else {
      form.append('csr_text', text);
    }
    const res = await fetch('/api/decode', {method:'POST', body: form});
    const j = await res.json();
    const d = document.getElementById('decodeResult');
    if (j.error) {
      d.style.display='block';
      d.innerHTML = '<div class="danger">Hata: '+ j.error +'</div>';
      return;
    }
    let html = '<h3>Çözümleme Sonucu</h3>';
    html += '<ul>';
    j.subject.forEach(s => { html += `<li><b>${s.name}</b>: ${s.value}</li>`; });
    html += '</ul>';
    html += '<h4>Public Key</h4><ul>';
    for (const k in j.public_key) html += `<li><b>${k}</b>: ${j.public_key[k]}</li>`;
    html += '</ul>';
    if (j.extensions && j.extensions.length) {
      html += '<h4>Uzantılar</h4><ul>';
      j.extensions.forEach(e => {
        html += `<li><b>${e.name || e.oid}</b>: ${JSON.stringify(e.value)}</li>`;
      });
      html += '</ul>';
    }
    d.style.display='block';
    d.innerHTML = html;
  });

  // Discover
  document.getElementById('discoverBtn').addEventListener('click', async () => {
    const host = document.getElementById('discover_host').value.trim();
    const res = await fetch('/api/discover', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ host })
    });
    const j = await res.json();
    const d = document.getElementById('discoverResult');
    if (j.error) {
      d.style.display='block';
      d.innerHTML = '<div class="danger">Hata: '+ j.error +'</div>';
      return;
    }
    let html = '<h3>Sertifika Bilgileri</h3>';
    html += `<p><b>Sunucu:</b> ${j.host}</p>`;
    html += `<p><b>CN:</b> ${j.subject_cn}</p>`;
    html += `<p><b>Issuer:</b> ${j.issuer}</p>`;
    html += `<p><b>Not After:</b> ${j.not_after} (kalan: ${j.days_left} gün)</p>`;
    html += `<p><b>SHA256 Fingerprint:</b> ${j.sha256}</p>`;
    if (j.sans && j.sans.length) {
      html += '<h4>SAN</h4><ul>';
      j.sans.forEach(s => html += `<li>${s}</li>`);
      html += '</ul>';
    }
    d.style.display='block';
    d.innerHTML = html;
  });

  // utilities: download text
  function downloadText(filename, text) {
    const blob = new Blob([text], {type:'text/plain;charset=utf-8'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename; document.body.appendChild(a);
    a.click(); a.remove(); URL.revokeObjectURL(url);
  }

  // Load JSZip & FileSaver dynamically for ZIP feature
  (function loadHelpers(){
    const js = document.createElement('script');
    js.src = 'https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.0/jszip.min.js';
    document.head.appendChild(js);
    const fs = document.createElement('script');
    fs.src = 'https://cdnjs.cloudflare.com/ajax/libs/FileSaver.js/2.0.5/FileSaver.min.js';
    document.head.appendChild(fs);
    js.onload = () => { window.JSZip = window.JSZip || window.JSZip; };
  })();
</script>
</body>
</html>
"""

########################
# Yardımcı fonksiyonlar
########################
def make_name(c, l, o, ou, cn, email):
    attrs = []
    if c: attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, c))
    if l: attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, l))
    if o: attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, o))
    if ou: attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
    if cn: attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
    if email: attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
    return x509.Name(attrs)

def pem_bytes_to_str(b: bytes):
    try:
        return b.decode('utf-8')
    except:
        return b.decode('latin-1')

########################
# Routes
########################
@app.route('/')
def index():
    return render_template_string(HTML)

@app.route('/api/create-csr', methods=['POST'])
def api_create_csr():
    try:
        data = request.get_json() or {}
        c = (data.get('c') or '').strip()
        l = (data.get('l') or '').strip()
        o = (data.get('o') or '').strip()
        ou = (data.get('ou') or '').strip()
        cn = (data.get('cn') or '').strip()
        email = (data.get('email') or '').strip()
        san_raw = (data.get('san') or '').strip()
        san_list = [s.strip() for s in san_raw.split(',') if s.strip()]
        key_type = data.get('key_type', 'rsa')
        key_size = int(data.get('key_size') or 4096)

        # Key generation
        if key_type == 'rsa':
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        elif key_type == 'ec':
            private_key = ec.generate_private_key(ec.SECP256R1())
        else:
            return jsonify({'error':'Bilinmeyen anahtar tipi'}), 400

        # CSR builder
        name = make_name(c, l, o, ou, cn, email)
        csr_builder = x509.CertificateSigningRequestBuilder().subject_name(name)

        # SAN ekle
        if san_list:
            san_objs = []
            for name_s in san_list:
                # IP kontrolü basit: rakam nokta içerirse DNS yerine IP olarak eklemeye çalışıyoruz
                if name_s.replace('.','').isdigit():
                    # hızlı IP algılama değil; güvenli yol: x509.IPAddress
                    try:
                        import ipaddress
                        san_objs.append(x509.IPAddress(ipaddress.ip_address(name_s)))
                    except Exception:
                        san_objs.append(x509.DNSName(name_s))
                else:
                    san_objs.append(x509.DNSName(name_s))
            csr_builder = csr_builder.add_extension(x509.SubjectAlternativeName(san_objs), critical=False)

        # sign
        csr = csr_builder.sign(private_key, hashes.SHA256())

        # PEM encode
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        return jsonify({
            'csr_pem': pem_bytes_to_str(csr_pem),
            'key_pem': pem_bytes_to_str(key_pem)
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': f'CSR oluşturulurken hata: {e}'}), 500

@app.route('/api/decode', methods=['POST'])
def api_decode():
    try:
        csr_bytes = None
        if 'csr_file' in request.files and request.files['csr_file'].filename:
            csr_bytes = request.files['csr_file'].read()
        elif 'csr_text' in request.form and request.form['csr_text'].strip():
            csr_bytes = request.form['csr_text'].encode('utf-8')
        else:
            # maybe raw body (AJAX JSON not used here)
            return jsonify({'error':'CSR verisi bulunamadı. Lütfen metin girin veya dosya yükleyin.'}), 400

        # attempt load pem then der
        try:
            csr = x509.load_pem_x509_csr(csr_bytes)
        except Exception:
            csr = x509.load_der_x509_csr(csr_bytes)

        subject = []
        for attr in csr.subject:
            # attr.oid._name bazen yok; güvenli şekilde al
            name = getattr(attr.oid, '_name', attr.oid.dotted_string)
            subject.append({'oid': attr.oid.dotted_string, 'name': name, 'value': attr.value})

        # public key
        pub = csr.public_key()
        pubinfo = {}
        try:
            if hasattr(pub, 'key_size'):
                pubinfo['key_size'] = pub.key_size
            if hasattr(pub, 'curve'):
                pubinfo['curve'] = pub.curve.name
            pubinfo['type'] = pub.__class__.__name__
        except Exception:
            pubinfo['type'] = str(type(pub))

        extensions = []
        try:
            for ext in csr.extensions:
                ename = getattr(ext.oid, '_name', ext.oid.dotted_string)
                if ext.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                    san_entries = []
                    for name in ext.value:
                        if isinstance(name, x509.DNSName):
                            san_entries.append({"type": "DNS", "value": name.value})
                        elif isinstance(name, x509.IPAddress):
                            san_entries.append({"type": "IP", "value": str(name.value)})
                        elif isinstance(name, x509.RFC822Name):
                            san_entries.append({"type": "EMAIL", "value": name.value})
                        elif isinstance(name, x509.UniformResourceIdentifier):
                            san_entries.append({"type": "URI", "value": name.value})
                        elif isinstance(name, x509.OtherName):
                            # otherName içeriği binary gelebilir, bozulmasın diye base64’e saralım:
                            import base64
                            san_entries.append({
                                "type": "OTHERNAME",
                                "oid": name.type_id.dotted_string,
                                "value_b64": base64.b64encode(name.value).decode()
                            })
                        else:
                            san_entries.append({"type": "UNKNOWN", "repr": repr(name)})

                    extensions.append({
                        "oid": ext.oid.dotted_string,
                        "name": ename,
                        "value": san_entries
                    })
        except Exception:
            pass

        return jsonify({'subject': subject, 'public_key': pubinfo, 'extensions': extensions})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': f'CSR çözümlenirken hata: {e}'}), 500

@app.route('/api/discover', methods=['POST'])
def api_discover():
    try:
        data = request.get_json() or {}
        host_raw = (data.get('host') or '').strip()
        if not host_raw:
            return jsonify({'error': 'Host girin (ör: example.com veya example.com:8443)'}), 400

        # parse host:port
        if ':' in host_raw and host_raw.count(':') == 1:
            host, port_s = host_raw.split(':',1)
            try:
                port = int(port_s)
            except:
                port = 443
        else:
            host = host_raw
            port = 443

        # connect and get cert (binary form)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=6) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                if not der:
                    # fallback
                    pem = ssl.get_server_certificate((host, port))
                    cert = x509.load_pem_x509_certificate(pem.encode('utf-8'))
                else:
                    cert = x509.load_der_x509_certificate(der)

        # parse certificate
        subject_cn = None
        for rdn in cert.subject.rdns:
            for attr in rdn:
                if attr.oid == NameOID.COMMON_NAME:
                    subject_cn = attr.value

        issuer = ", ".join([f"{getattr(a.oid,'_name',a.oid.dotted_string)}={a.value}" for a in cert.issuer])

        not_after = cert.not_valid_after
        days_left = (not_after - datetime.datetime.utcnow()).days

        # SANs
        sans = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            sans = [str(n) for n in san_ext.value]
        except Exception:
            sans = []

        # fingerprint
        sha256 = cert.fingerprint(hashes.SHA256()).hex().upper()
        # format nice: AA:BB:CC...
        sha256_f = ':'.join(a+b for a,b in zip(sha256[::2], sha256[1::2]))

        return jsonify({
            'host': f"{host}:{port}",
            'subject_cn': subject_cn,
            'issuer': issuer,
            'not_after': not_after.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'days_left': days_left,
            'sans': sans,
            'sha256': sha256_f
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': f'Keşif hatası: {e}'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)
