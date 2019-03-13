FROM centos

ENV PATH=$PATH:/usr/local/go/bin

RUN yum install -y git gcc openssl

RUN curl -k -o go.tar.gz -L https://dl.google.com/go/go1.10.8.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go.tar.gz

RUN go get github.com/docker/docker/client

RUN go get gopkg.in/yaml.v2

ADD . ./

RUN go build main.go

CMD ["./main"]
