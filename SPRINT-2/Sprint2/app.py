from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
import os
import random
from dotenv import load_dotenv

# Initialisation de l'application Flask
app = Flask(__name__)
app.secret_key = os.urandom(24)
load_dotenv()

# Configuration pour la base de données MySQL
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:vitrygtr@mysql/project'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configuration pour Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')  # Chargé depuis .env
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')  # Chargé depuis .env
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')  # Utiliser le même e-mail

# Initialisation des extensions
db = SQLAlchemy(app)
mail = Mail(app)

# Modèle de la table utilisateur
class UserAccount(db.Model):
    __tablename__ = 'useraccounts'

    id = db.Column(db.Integer, primary_key=True)
    nom = db.Column(db.String(40), nullable=False)
    prenom = db.Column(db.String(40), nullable=False)
    email = db.Column(db.String(40), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    email_verified = db.Column(db.Boolean, default=False)
    verification_code = db.Column(db.String(100), nullable=True)

# Fonction pour valider les mots de passe
def validate_password(password):
    if len(password) < 8:
        return "Le mot de passe doit contenir au moins 8 caractères."
    if not any(char.isupper() for char in password):
        return "Le mot de passe doit contenir au moins une lettre majuscule."
    if not any(char.isdigit() for char in password):
        return "Le mot de passe doit contenir au moins un chiffre."
    if not any(char in "!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~" for char in password):
        return "Le mot de passe doit contenir au moins un caractère spécial."
    return None

# Route pour la connexion
@app.route("/", methods=["GET", "POST"])
def connexion():
    if "user_id" in session:
        return redirect(url_for("connecte"))

    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = UserAccount.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            if not user.email_verified:
                session["verification_email"] = email  # Stocker l'e-mail pour vérification
                flash("Veuillez vérifier votre adresse e-mail avant de vous connecter.", "error")
                return redirect(url_for("verification"))
            session["user_id"] = user.id
            session["user_name"] = user.nom
            return redirect(url_for("connecte"))
        else:
            flash("Identifiants incorrects.", "error")
    return render_template("connexion.html")

# Route pour créer un compte
@app.route("/ouverturedecompte", methods=["GET", "POST"])
def ouverturedecompte():
    if request.method == "POST":
        nom = request.form["nom"]
        prenom = request.form["prenom"]
        email = request.form["email"]
        password = request.form["password"]

        error = validate_password(password)
        if error:
            flash(error, "error")
            return redirect(url_for("ouverturedecompte"))

        hashed_password = generate_password_hash(password)

        if UserAccount.query.filter_by(email=email).first():
            flash("Un compte avec cet email existe déjà.", "error")
            return redirect(url_for("ouverturedecompte"))

        verification_code = str(random.randint(100000, 999999))
        new_user = UserAccount(nom=nom, prenom=prenom, email=email, password=hashed_password, verification_code=verification_code)
        db.session.add(new_user)
        db.session.commit()

        # Envoi du code par e-mail
        msg = Message("Vérifiez votre adresse e-mail", recipients=[email])
        msg.body = f"Votre code de vérification est : {verification_code}"
        mail.send(msg)

        session["verification_email"] = email  # Stocker l'e-mail dans la session
        flash("Un e-mail de vérification vous a été envoyé.", "success")
        return redirect(url_for("verification"))

    return render_template("ouverturedecompte.html")

# Route pour vérifier le code
@app.route("/verification", methods=["GET", "POST"])
def verification():
    email = session.get("verification_email")  # Récupérer l'e-mail de la session

    if not email:
        flash("Une erreur est survenue. Veuillez recommencer.", "error")
        return redirect(url_for("connexion"))

    if request.method == "POST":
        code = request.form["code"]
        user = UserAccount.query.filter_by(email=email).first()
        if user and user.verification_code == code:
            user.email_verified = True
            user.verification_code = None
            db.session.commit()
            session.pop("verification_email", None)  # Supprimer l'e-mail de la session
            flash("Votre e-mail a été vérifié avec succès.", "success")
            return redirect(url_for("connexion"))
        else:
            flash("Code de vérification incorrect.", "error")
    return render_template("verification.html", email=email)

# Route pour la page une fois connecté
@app.route("/connecte")
def connecte():
    if "user_id" not in session:
        return redirect(url_for("connexion"))
    return render_template("connecte.html", nom=session["user_name"])

# Route pour la déconnexion
@app.route("/deconnexion", methods=["GET", "POST"])
def deconnexion():
    if request.method == "POST":
        session.clear()
        flash("Déconnexion réussie.", "success")
        return redirect(url_for("deconnexion"))
    return render_template("deconnexion.html")

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
