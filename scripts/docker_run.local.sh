image="gordonaspin/icloudpd:2.0.0-local"
container="icloudpdlocal"
docker run --detach --name $container -v ~/Pictures/Photos:/data -v ~/.pyicloud:/cookies $image sleep infinite
docker exec -it $container icloudpd -d /data --cookie-directory /cookies --all-albums --folder-structure album -u gordon.aspin@gmail.com --no-progress-bar --newest --log-level debug
docker stop $container
docker rm $container