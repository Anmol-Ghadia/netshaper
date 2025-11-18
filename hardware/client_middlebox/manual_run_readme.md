sudo ./build.sh
docker build -t amirsabzi/netshaper:peer1-no-shaping ./peer1/
./run.sh 0 tmp.mpd 1 600 300 'no-shaping'
