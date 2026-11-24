"""
PinguRegistry — Flask app vulnerable to Server-Side Template Injection (SSTI).

The vulnerability: render_template_string() receives user input directly,
allowing Jinja2 template expressions to be evaluated server-side.

This is an intentionally vulnerable application for authorized security testing.
"""
from flask import Flask, request, render_template_string

app = Flask(__name__)

INDEX = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Pingu Flask Web</title>
  <style>
    body { font-family: monospace; background: #0a0a0a; color: #c8e6c9; margin: 0; }
    .container { max-width: 500px; margin: 80px auto; padding: 2rem;
                 border: 1px solid #2e7d32; border-radius: 6px; }
    h1 { color: #4caf50; letter-spacing: 0.1em; }
    input[type=text] { width: 100%%; padding: 0.5rem; background: #111;
                       color: #c8e6c9; border: 1px solid #2e7d32;
                       border-radius: 3px; font-family: monospace; }
    button { margin-top: 0.75rem; padding: 0.5rem 1.5rem;
             background: #2e7d32; color: #fff; border: none;
             border-radius: 3px; cursor: pointer; font-family: monospace; }
    .result { margin-top: 1.5rem; padding: 1rem;
              background: #111; border-left: 3px solid #4caf50; }
  </style>
</head>
<body>
  <div class="container">
    <h1>🐧 PinguRegistry</h1>
    <p>Enter your name to register:</p>
    <form method="POST">
      <input type="text" name="name" placeholder="Your name..." autofocus>
      <button type="submit">Register</button>
    </form>
    {% if result %}
    <div class="result">{{ result }}</div>
    {% endif %}
  </div>
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        name = request.form.get('name', '')
        # VULNERABLE: user input rendered directly as Jinja2 template
        rendered = render_template_string(f'Hello, {name}! Welcome to PinguRegistry.')
        result = rendered
    return render_template_string(INDEX, result=result)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
