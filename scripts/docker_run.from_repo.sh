image="gordonaspin/icloudpd:latest"
container="icloudpd"

docker run --detach --name $container -v ~/Pictures/Photos:/data -v ~/.pyicloud:/cookies $image sleep infinite
docker exec -it $container icloudpd -d /data --cookie-directory /cookies --all-albums --folder-structure album -u gordon.aspin@gmail.com --no-progress-bar --newest --log-level info
docker stop $container
docker rm $container