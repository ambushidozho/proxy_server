cd ./certs
chmod +x ./gen_ca.sh
./gen_ca.sh
cd ..
docker build -t wmai .
docker run -p 8080:8080 -p 8000:8000 -p 9432:5432 wmai
