apt-get update
apt-get install -y net-tools iputils-ping
python3 -m venv venv
source venv/bin/activate
export LC_ALL=C.UTF-8
export LANG=C.UTF-8
export FLASK_APP=app
flask run -h $(/bin/hostname -i) -p 5000