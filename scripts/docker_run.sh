docker run -d --name icloudpd -v ~/Pictures/Photos:/data -v ~/.pyicloud:/cookies gordonaspin/icloudpd:latest sleep infinite
docker exec -it icloudpd icloudpd -d /data --cookie-directory /cookies --all-albums --folder-structure album -u gordon.aspin@gmail.com --no-progress-bar --newest --log-level info
