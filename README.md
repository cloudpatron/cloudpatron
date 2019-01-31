# Cloud Patron - Open source Patreon alternative

Cloud Patron is an open source membership platform that enables fans to support creators with monthly subscriptions. Creators can customize support levels, set goals, and post updates for their patrons. Supports monthly credit card billing using Stripe.

![Screenshot](https://raw.githubusercontent.com/cloudpatron/cloudpatron/master/screenshot1.png)

[Demo](https://frequency.cloudpatron.portal.cloud/)


## Features

* **Post Updates**
  * Add private updates for your patrons. Posts can also be unlocked for public access.
* **Project Goals**
  * Set short and long-term milestones for your project.
* **Support Levels**
  * Customize support levels for your patrons.
* **Credit Card Billing**
  * Add your Stripe API keys to enable monthly credit card processing.
* **Export Email List**
  * Download your patron email list for use with cloud email services.
* **Social Media Links**
  * Add your Facebook, Twitter, YouTube, and Instagram.
* **Custom Landing Page**
  * Add your name, description, logo, and header image to customize your landing page.
* **Bitcoin Payments (TODO)**
  * Allow Patrons to pay their membership with Bitcoin.

## Run Cloud Patron on Portal Cloud

Portal Cloud is a hosting service that enables anyone to run open source cloud applications.

[Sign up for Portal Cloud](https://portal.cloud/) and get $15 free credit.

## Run Cloud Patron on a VPS

Running Cloud Patron on a VPS is designed to be as simple as possible.

  * Public Docker image
  * Single static Go binary with assets bundled
  * Automatic TLS using Let's Encrypt
  * Redirects http to https
  * No database required

### 1. Get a server

**Recommended Specs**

* Type: VPS or dedicated
* Distribution: Ubuntu 16.04 (Xenial)
* Memory: 512MB or greater

### 2. Add a DNS record

Create a DNS record for your domain that points to your server's IP address.

**Example:** `cloudpatron.example.com  A  172.x.x.x`

### 3. Enable Let's Encrypt

Cloud Patron runs a TLS ("SSL") https server on port 443/tcp. It also runs a standard web server on port 80/tcp to redirect clients to the secure server. Port 80/tcp is required for Let's Encrypt verification.

**Requirements**

* Your server must have a publicly resolvable DNS record.
* Your server must be reachable over the internet on ports 80/tcp and 443/tcp.

### Usage

**Example usage:**

```bash
# Download the cloudpatron binary.
$ sudo wget -O /usr/bin/cloudpatron https://github.com/cloudpatron/cloudpatron/raw/master/cloudpatron-linux-amd64

# Make it executable.
$ sudo chmod +x /usr/bin/cloudpatron

# Allow it to bind to privileged ports 80 and 443.
$ sudo setcap cap_net_bind_service=+ep /usr/bin/cloudpatron

$ cloudpatron --http-host cloudpatron.example.com
```

### Arguments

```bash
  -backlink string
    	backlink (optional)
  -datadir string
    	data dir (default "/data")
  -debug
    	debug mode
  -help
    	display help and exit
  -http-host string
    	HTTP host
  -version
    	display version and exit


```
### Run as a Docker container

The official image is `cloudpatron/cloudpatron`.

Follow the official Docker install instructions: [Get Docker CE for Ubuntu](https://docs.docker.com/engine/installation/linux/docker-ce/ubuntu/)

Make sure to change the `--env CLOUDPATRON_HTTP_HOST` to your publicly accessible domain name.

```bash

# Your data directory must be bind-mounted as `/data` inside the container using the `--volume` flag.
# Create a data directoy 
$ mkdir /data

docker create \
    --name cloudpatron \
    --restart always \
    --volume /data:/data \
    --network host \
    --env CLOUDPATRON_HTTP_HOST=cloudpatron.example.com \
    cloudpatron/cloudpatron:latest

$ sudo docker start cloudpatron

$ sudo docker logs cloudpatron

<log output>

```

#### Updating the container image

Pull the latest image, remove the container, and re-create the container as explained above.

```bash
# Pull the latest image
$ sudo docker pull cloudpatron/cloudpatron

# Stop the container
$ sudo docker stop cloudpatron

# Remove the container (data is stored on the mounted volume)
$ sudo docker rm cloudpatron

# Re-create and start the container
$ sudo docker create ... (see above)
```

## Help / Reporting Bugs

Email support@portal.cloud

