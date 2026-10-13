from flask import Flask, render_template, request, redirect, url_for, session
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

app = Flask(__name__)
app.secret_key = "secret123"   # required for session

UPLOAD_FOLDER = "uploads/original"
SIGN_FOLDER = "uploads/signed"
KEY_FOLDER = "keys"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SIGN_FOLDER, exist_ok=True)

# ================== LOAD KEYS ==================
with open("keys/private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

with open("keys/public_key.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

# ================== LOGIN ==================
@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # LOGIN CREDENTIALS
        if username == "admin" and password == "1234":
            session["user"] = username
            return redirect("/home")
        else:
            return render_template(
                "login.html",
                error="❌ Incorrect Username or Password"
            )

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/login")


# ================== HOME ==================
@app.route("/home")
def home():
    if "user" not in session:
        return redirect("/login")
    return render_template("index.html")


# ================== SIGN ==================
@app.route("/sign", methods=["POST"])
def sign_file():
    if "user" not in session:
        return redirect("/login")

    file = request.files["file"]
    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)

    with open(filepath, "rb") as f:
        data = f.read()

    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    sig_filename = file.filename + ".sig"
    sig_path = os.path.join(SIGN_FOLDER, sig_filename)

    with open(sig_path, "wb") as f:
        f.write(signature)

    return render_template(
        "signed.html",
        filename=file.filename,
        sigfile=sig_filename
    )


# ================== VERIFY ==================
@app.route("/verify", methods=["GET", "POST"])
def verify():
    if "user" not in session:
        return redirect("/login")

    if request.method == "POST":
        file = request.files["file"]
        sig = request.files["signature"]

        data = file.read()
        signature = sig.read()

        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            result = "✅ FILE VERIFIED – SIGNATURE IS VALID"
        except:
            result = "❌ FILE NOT VERIFIED – SIGNATURE INVALID"

        return render_template("result.html", result=result)

    return render_template("verify.html")


if __name__ == "__main__":
    app.run(debug=True)
