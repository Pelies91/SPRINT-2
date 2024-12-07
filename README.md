Sprint1 -------- avec framework Flask

1. sudo apt update
2. sudo apt install apt-transport-https ca-certificates curl software-properties-common -y
3. curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
4. echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
5. sudo apt update
6. sudo apt install docker-ce docker-ce-cli containerd.io docker.io docker-compose -y
7. sudo systemctl start docker
8. sudo systemctl enable docker
9. sudo usermod -aG docker $USER


Flask avec Docker :
1. git clone https://github.com/FathiMohamed00/SPRINT-1.git
2. sudo apt install python3
3. sudo apt install pyhton3-pip
4. docker pull mysql:8.0
5. docker pull phpmyadmin/phpmyadmin
6. docker pull python:3.9-slim
7. docker compose up -d
8. SI BESOIN ALLER DANS "Sprint1" et: "python3 -m venv venv"
                                      "source venv/bin/activate"
                                      "pip install -r requirements.txt"
  Sinon directement mettre "pip install -r requirements.txt"
9. Aller dans le dossier "SPRINT-1" et mettre "docker-compose up -d"
   On pourra vérifier l'état des dockers avec "docker ps"
10. Aller à l'adresse "127.0.0.1:8080" et importer le fichier "project.sql" dans la base de donnée "project"
11. Aller à l'adresse "127.0.0.1:5000" et arrivé sur la page de connexion

A partir d'ici, nous n'avons pas encore de compte donc nous allons en créer un en cliquant sur le bouton "s'inscrire". Ensuite nous allons remplir le formulaire d'inscription en mettant un mail "@gmail.com" car nous n'avons pas encore ajouté les autres serveurs SMTP, le mot de passe doit respecté les demandes affiché en dessous du formulaire. Si le formulaire est correctement envoyé à la base de données, nous allons être redirigé sur la page de vérification demandant un code à 6 chiffres. Si le code est incorrecte un message d'erreur s'affichera. Si le code est correcte alors nous allons être redirigé sur la page de connexion et une fois connecté nous atterissons sur la page 'connecte' qui montre que la connexion a reussi. Nous pourrons ensuite nous déconnecté à l'aide du bouton désigné. 

