# Readme

### Command to build the docker image:

```docker
docker build -t openfhe-docker .
```
Make sure you run this command from the same folder where the Dockerfile is located (in the "docker" folder of the openfhe-python repository).

### Command to check if the image is built:

```docker
docker images
```

You should see a "openfhe-docker" in the list

### Command to create the container from the image:

```docker
docker run -d -p 8888:8888 openfhe-docker
```

### Command to check if the container is running:

```docker
docker ps
```

You should see openfhe-docker running

### This openfhe-docker has jupyterlab installed in it which has access to openfhe installation and is accessible via localhost. To run the jupyterlab use:

```docker
[http://localhost:8888](http://localhost:8888/)
```

All the code can be executed through this jupyterlab now

## Alternate way to execute the code in this docker:

### Go inside the docker, use:

```docker
docker exec -it <container-name> /bin/bash
```

replace the <container-name> with the name that you see when you use the command "docker run -d -p 8888:8888 openfhe-docker"

This takes you to a terminal interface inside the container which has all the dependencies installed.

You can now clone a github repo that depends on OpenFHE and run the code.
