docker build . -t mydeployer

# with local repo
docker build -f Dockerfile.local_repo --network havipv2-test-net --add-host github.com:172.28.0.2 --add-host dl.google.com:172.28.0.2 . -t mydeployer
