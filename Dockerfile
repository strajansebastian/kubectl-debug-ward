# used for development

FROM ubuntu:22.04

RUN mkdir -p /app /config
WORKDIR /app

RUN apt update && \
    apt install -y ca-certificates golang curl vim && \
    rm -rf /var/lib/apt/lists/*

RUN apt update && \
    apt install -y gpg && \
	curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.29/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg && \
	echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.29/deb/ /' | tee /etc/apt/sources.list.d/kubernetes.list && \
	apt update && \
    apt install -y kubectl && \
    rm -rf /var/lib/apt/lists/*

RUN apt update && \
    apt install -y git && \
    rm -rf /var/lib/apt/lists/*

RUN (   set -x; cd "$(mktemp -d)" &&   OS="$(uname | tr '[:upper:]' '[:lower:]')" &&   ARCH="$(uname -m | sed -e 's/x86_64/amd64/' -e 's/\(arm\)\(64\)\?.*/\1\2/' -e 's/aarch64$/arm64/')" &&   KREW="krew-${OS}_${ARCH}" &&   curl -fsSLO "https://github.com/kubernetes-sigs/krew/releases/latest/download/${KREW}.tar.gz" &&   tar zxvf "${KREW}.tar.gz" &&   ./"${KREW}" install krew; )

ENV KREW_ROOT=/root/.krew \
    PATH="/root/.krew/bin:${PATH}"

RUN mkdir /local-go && \
    cd /local-go && \
    curl -L 'https://go.dev/dl/go1.21.5.linux-amd64.tar.gz' -o go.tar.gz && \
    tar -C /local-go/ -xvzf go.tar.gz && \
    cd /local-go/go/src && \
    ./make.bash && \
    mv /local-go/go/bin/go /usr/local/bin && \
    rm /local-go/go.tar.gz

ENV GOROOT=/local-go/go

RUN apt update && \
    apt install -y vim mlocate && \
    rm -rf /var/lib/apt/lists/*

COPY go.mod go.sum README.md /app/
RUN go mod download

COPY release /app/release
COPY cmd /app/cmd
COPY pkg /app/pkg

