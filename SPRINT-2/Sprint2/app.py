import logging
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
import os
import random
from ldap3 import Server, Connection, ALL, SIMPLE
from dotenv import load_dotenv
from logging.handlers import SocketHandler

# Initialisation de l'application Flask
app = Flask(__name__)
app.secret_key = os.urandom(24)
load_dotenv()

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

logstash_handler = SocketHandler('192.168.20.20', 5044)
logger.addHandler(logstash_handler)  # Logs envoyés à Logstash

# Configuration pour la base de données MySQL
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:vitrygtr@mysql/project'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configuration pour Flask-LDAP3-Login
app.config['LDAP_HOST'] = 'ldap://openldap:389'
app.config['LDAP_PORT'] = 389
app.config['LDAP_BASE_DN'] = 'dc=rtlocal,dc=com'
app.config['LDAP_USER_DN'] = 'ou=users'
app.config['LDAP_BIND_USER_DN'] = 'cn=admin,dc=rtlocal,dc=com'
app.config['LDAP_BIND_USER_PASSWORD'] = 'admin_pass'
app.config['LDAP_USER_RDN_ATTR'] = 'uid'
app.config['LDAP_USER_LOGIN_ATTR'] = 'uid'
app.config['LDAP_ALWAYS_SEARCH_BIND'] = True

# Configuration pour Flask-Mail - plusieurs serveurs SMTP
MAIL_SERVERS = {
    "gmail": {
        "server": "smtp.gmail.com",
        "port": 587,
        "use_tls": True,
    },
    "outlook": {
        "server": "smtp.office365.com",
        "port": 587,
        "use_tls": True,
    },
    "yahoo": {
        "server": "smtp.mail.yahoo.com",
        "port": 587,
        "use_tls": True,
    },
    "zoho": {
        "server": "smtp.zoho.com",
        "port": 587,
        "use_tls": True,
    }
}

# Récupération du serveur SMTP depuis les variables d'environnement
selected_provider = os.getenv("MAIL_PROVIDER", "gmail")  # Par défaut, Gmail
smtp_config = MAIL_SERVERS.get(selected_provider)

if not smtp_config:
    raise ValueError(f"Fournisseur SMTP non pris en charge : {selected_provider}")

# Configuration dynamique
app.config['MAIL_SERVER'] = smtp_config["server"]
app.config['MAIL_PORT'] = smtp_config["port"]
app.config['MAIL_USE_TLS'] = smtp_config["use_tls"]
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")  # Chargé depuis .env
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")  # Chargé depuis .env
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_USERNAME")

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
        logger.info("Utilisateur déjà connecté.")
        return redirect(url_for("connecte"))

    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = UserAccount.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            if not user.email_verified:
                session["verification_email"] = email
                flash("Veuillez vérifier votre adresse e-mail avant de vous connecter.", "error")
                logger.warning("Tentative de connexion avec un e-mail non vérifié : %s", email)
                return redirect(url_for("verification"))
            session["user_id"] = user.id
            session["user_name"] = user.nom
            logger.info("Connexion réussie pour l'utilisateur : %s", email)
            return redirect(url_for("connecte"))
        else:
            flash("Identifiants incorrects.", "error")
            logger.error("Tentative de connexion échouée pour l'e-mail : %s", email)
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
            logger.warning("Erreur de validation du mot de passe pour : %s", email)
            return redirect(url_for("ouverturedecompte"))

        hashed_password = generate_password_hash(password)
        if UserAccount.query.filter_by(email=email).first():
            flash("Un compte avec cet email existe déjà.", "error")
            logger.warning("Tentative de création de compte avec un e-mail existant : %s", email)
            return redirect(url_for("ouverturedecompte"))

        verification_code = str(random.randint(100000, 999999))
        new_user = UserAccount(nom=nom, prenom=prenom, email=email, password=hashed_password, verification_code=verification_code)
        db.session.add(new_user)
        db.session.commit()

        msg = Message("Vérifiez votre adresse e-mail", recipients=[email])
        msg.body = f"Votre code de vérification est : {verification_code}"
        mail.send(msg)

        session["verification_email"] = email
        flash("Un e-mail de vérification vous a été envoyé.", "success")
        logger.info("Compte créé avec succès pour : %s", email)
        return redirect(url_for("verification"))

    return render_template("ouverturedecompte.html")

# Route pour vérifier le code
@app.route("/verification", methods=["GET", "POST"])
def verification():
    email = session.get("verification_email")
    if not email:
        flash("Une erreur est survenue. Veuillez recommencer.", "error")
        logger.error("Vérification échouée : aucune adresse e-mail en session.")
        return redirect(url_for("connexion"))

    if request.method == "POST":
        code = request.form["code"]
        user = UserAccount.query.filter_by(email=email).first()
        if user and user.verification_code == code:
            user.email_verified = True
            user.verification_code = None
            db.session.commit()
            session.pop("verification_email", None)
            flash("Votre e-mail a été vérifié avec succès.", "success")
            logger.info("Vérification réussie pour l'utilisateur : %s", email)
            return redirect(url_for("connexion"))
        else:
            flash("Code de vérification incorrect.", "error")
            logger.warning("Code de vérification incorrect pour l'e-mail : %s", email)
    return render_template("verification.html", email=email)

@app.route("/connecte")
def connecte():
    if "user_id" not in session:
        return redirect(url_for("connexion"))
    return render_template("connecte.html", nom=session["user_name"])

@app.route("/connexion_interne", methods=["GET", "POST"])
def connexion_interne():
    if "user_ldap" in session:
        logger.info("Utilisateur interne déjà connecté.")
        return redirect(url_for("accueil_interne"))

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Configuration du serveur LDAP
        ldap_server = app.config['LDAP_HOST']
        ldap_port = app.config['LDAP_PORT']
        ldap_base_dn = app.config['LDAP_BASE_DN']
        ldap_user_rdn_attr = app.config['LDAP_USER_RDN_ATTR']  # 'uid' au lieu de 'cn'
        user_dn = f"uid={username},{app.config['LDAP_USER_DN']},{ldap_base_dn}"  # Utilisation de 'uid'

        try:
            # Création de la connexion LDAP
            server = Server(ldap_server, port=ldap_port, get_info=ALL)
            conn = Connection(server, user=user_dn, password=password, auto_bind=True)
            
            if conn.bound:  # Vérifie si la connexion a réussi
                session["user_ldap"] = username
                logger.info("Connexion LDAP réussie pour l'utilisateur : %s", username)
                flash("Connexion réussie.", "success")
                return redirect(url_for("accueil_interne"))
            else:
                flash("Identifiants LDAP incorrects.", "error")
                logger.warning("Échec de la connexion LDAP pour l'utilisateur : %s", username)
        except Exception as e:
            logger.error("Erreur lors de la connexion LDAP : %s", str(e))
            flash("Erreur de connexion au serveur LDAP.", "error")

    return render_template("connexion_interne.html")

# Route pour l'accueil interne
@app.route("/accueil_interne")
def accueil_interne():
    if "user_ldap" not in session:
        logger.warning("Accès non autorisé à la page interne sans connexion.")
        return redirect(url_for("connexion_interne"))
    logger.info("Utilisateur LDAP connecté : %s", session.get("user_ldap"))
    return render_template("accueil_interne.html", user=session["user_ldap"])

# Route pour la déconnexion
@app.route("/deconnexion", methods=["GET", "POST"])
def deconnexion():
    if request.method == "POST":
        logger.info("Déconnexion de l'utilisateur : %s", session.get("user_name") or session.get("user_ldap"))
        session.clear()
        flash("Déconnexion réussie.", "success")
        return redirect(url_for("deconnexion"))
    return render_template("deconnexion.html")

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
