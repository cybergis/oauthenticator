# docker build -t hub .
# docker run --rm -it -v /var/run/docker.sock:/var/run/docker.sock --net jupyterhub --name jupyterhub -p8000:8000 hub
FROM jupyterhub/jupyterhub:0.9.4
COPY requirements.txt /tmp/requirements.txt
RUN python3 -m pip install --no-cache -r /tmp/requirements.txt
COPY jupyterhub_config.py /srv/jupyterhub/jupyterhub_config.py
COPY login.html /srv/jupyterhub/login.html
